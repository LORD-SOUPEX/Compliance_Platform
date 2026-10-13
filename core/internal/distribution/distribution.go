package distribution

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var (
	ErrInvalidSignature       = errors.New("signature du manifeste invalide ou corrompue")
	ErrSignatureLengthMismatch = errors.New("longueur de signature cryptographique invalide")
	ErrArchiveHashMismatch    = errors.New("somme SHA-256 de l'archive téléchargée non conforme")
	ErrBinaryHashMismatch     = errors.New("somme SHA-256 du binaire extrait non conforme")
	ErrPlatformUnsupported    = errors.New("plateforme non présente dans le manifeste")
	ErrToolNotFound           = errors.New("binaire introuvable dans l'archive")
	ErrToolNotInManifest      = errors.New("outil absent du manifeste pour cette plateforme")
	ErrToolUnavailableOffline = errors.New("outil indisponible hors-ligne (archive absente du cache local)")
	ErrIntegrityViolation     = errors.New("intégrité binaire compromise : somme SHA-256 divergente")
)

// DefaultPhase0PublicKey is a dedicated Ed25519 public key for platform distribution.
// (Hex-encoded 32 bytes)
const DefaultPhase0PublicKeyHex = "c59fd4e179c55a3dd2110785d9ae7a9b4adafc1e54ca3dcde54e2f3c3458645f"

// ToolEntry describes a tool artifact within the runtime manifest.
type ToolEntry struct {
	Name            string   `json:"name"`
	Version         string   `json:"version"`
	ArchiveURL      string   `json:"archive_url"`
	ArchiveSHA256   string   `json:"archive_sha256"`
	BinaryInArchive string   `json:"binary_in_archive"`
	BinarySHA256    string   `json:"binary_sha256"`
	VersionArgs     []string `json:"version_args,omitempty"`
}

// PlatformManifest maps tools for a specific OS-arch tuple.
type PlatformManifest struct {
	Status string               `json:"status"` // qualified, experimental, targeted
	Tools  map[string]ToolEntry `json:"tools"`
}

// RuntimeManifest represents the signed multi-platform distribution manifest.
type RuntimeManifest struct {
	SchemaVersion   int                         `json:"schema_version"`
	ManifestVersion string                      `json:"manifest_version"`
	Platforms       map[string]PlatformManifest `json:"platforms"`
}

// SignManifest creates an Ed25519 signature over manifest bytes and returns it in hex.
func SignManifest(manifestBytes []byte, privKey ed25519.PrivateKey) string {
	sig := ed25519.Sign(privKey, manifestBytes)
	return hex.EncodeToString(sig)
}

// VerifyManifest verifies that sigHex matches manifestBytes using pubKey.
func VerifyManifest(manifestBytes []byte, sigHex string, pubKey ed25519.PublicKey) error {
	sigHex = strings.TrimSpace(sigHex)
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return ErrInvalidSignature
	}
	if len(sig) != ed25519.SignatureSize {
		return ErrSignatureLengthMismatch
	}
	if !ed25519.Verify(pubKey, manifestBytes, sig) {
		return ErrInvalidSignature
	}
	return nil
}

// DetectPlatform returns the standard platform ID (e.g. windows-x64, linux-x64, macos-arm64).
func DetectPlatform() string {
	osName := runtime.GOOS
	if osName == "darwin" {
		osName = "macos"
	}
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x64"
	}
	return fmt.Sprintf("%s-%s", osName, arch)
}

// SyncOptions contains configuration for runtime sync.
type SyncOptions struct {
	ManifestPath    string // URL or local path
	SigPath         string // URL or local path
	CacheDir        string // Destination folder
	Platform        string // Defaults to DetectPlatform()
	PublicKey       ed25519.PublicKey
	CABundlePath    string // Optional enterprise CA bundle for TLS
	ArchiveCacheDir string // Optional directory for caching/retrieving archives offline
	ToolName        string // Optional: if specified, synchronizes ONLY this tool
	OfflineOnly     bool   // If true, strictly forbids network requests
}

// SyncResult details synced tools.
type SyncResult struct {
	Platform    string
	SyncedTools map[string]string // tool name -> local executable path
}

// SyncRuntime fetches, verifies, and installs tool binaries from static distribution.
func SyncRuntime(opts SyncOptions) (*SyncResult, error) {
	if opts.Platform == "" {
		opts.Platform = DetectPlatform()
	}

	if len(opts.PublicKey) == 0 {
		pubBytes, err := hex.DecodeString(DefaultPhase0PublicKeyHex)
		if err != nil {
			return nil, fmt.Errorf("décodage de la clé publique par défaut: %w", err)
		}
		opts.PublicKey = ed25519.PublicKey(pubBytes)
	}

	client := buildHTTPClient(opts.CABundlePath)

	manifestBytes, err := fetchBytes(opts.ManifestPath, client)
	if err != nil {
		return nil, fmt.Errorf("lecture du manifeste impossible: %w", err)
	}

	sigBytes, err := fetchBytes(opts.SigPath, client)
	if err != nil {
		return nil, fmt.Errorf("lecture de la signature impossible: %w", err)
	}

	if err := VerifyManifest(manifestBytes, string(sigBytes), opts.PublicKey); err != nil {
		return nil, fmt.Errorf("vérification cryptographique échouée: %w", err)
	}

	var manifest RuntimeManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("décodage JSON du manifeste: %w", err)
	}

	plat, ok := manifest.Platforms[opts.Platform]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrPlatformUnsupported, opts.Platform)
	}

	binDir := filepath.Join(opts.CacheDir, "bin", opts.Platform)
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return nil, err
	}

	result := &SyncResult{
		Platform:    opts.Platform,
		SyncedTools: make(map[string]string),
	}

	for name, tool := range plat.Tools {
		if opts.ToolName != "" && name != opts.ToolName {
			continue // Skip tools outside the requested filter
		}

		destPath := filepath.Join(binDir, tool.Name)
		if runtime.GOOS == "windows" && !strings.HasSuffix(destPath, ".exe") {
			destPath += ".exe"
		}

		var archiveBytes []byte
		var err error

		// Vérifier si l'archive est déjà disponible dans le cache local (mode hors-ligne)
		if opts.ArchiveCacheDir != "" {
			archiveFileName := filepath.Base(tool.ArchiveURL)
			candidates := []string{
				filepath.Join(opts.ArchiveCacheDir, archiveFileName),
				filepath.Join(opts.ArchiveCacheDir, "wheels", archiveFileName),
			}
			for _, c := range candidates {
				if b, readErr := os.ReadFile(c); readErr == nil {
					if strings.EqualFold(sha256Hex(b), tool.ArchiveSHA256) {
						archiveBytes = b
						break
					}
				}
			}
		}

		if archiveBytes == nil {
			if opts.OfflineOnly {
				return nil, fmt.Errorf("%w pour %s: mode hors-ligne actif et archive introuvable localement", ErrToolNotFound, name)
			}
			archiveBytes, err = fetchBytes(tool.ArchiveURL, client)
			if err != nil {
				return nil, fmt.Errorf("téléchargement de l'outil %s: %w", name, err)
			}
			// Sauvegarder dans le cache local pour les prochaines exécutions
			if opts.ArchiveCacheDir != "" {
				_ = os.MkdirAll(opts.ArchiveCacheDir, 0755)
				archiveFileName := filepath.Base(tool.ArchiveURL)
				_ = os.WriteFile(filepath.Join(opts.ArchiveCacheDir, archiveFileName), archiveBytes, 0644)
			}
		}

		actualArchiveHash := sha256Hex(archiveBytes)
		if !strings.EqualFold(actualArchiveHash, tool.ArchiveSHA256) {
			return nil, fmt.Errorf("%w pour %s: attendu %s, obtenu %s",
				ErrArchiveHashMismatch, name, tool.ArchiveSHA256, actualArchiveHash)
		}

		binBytes, err := extractBinary(archiveBytes, tool.BinaryInArchive, tool.ArchiveURL)
		if err != nil {
			return nil, fmt.Errorf("extraction du binaire pour %s: %w", name, err)
		}

		actualBinaryHash := sha256Hex(binBytes)
		if !strings.EqualFold(actualBinaryHash, tool.BinarySHA256) {
			return nil, fmt.Errorf("%w pour %s: attendu %s, obtenu %s",
				ErrBinaryHashMismatch, name, tool.BinarySHA256, actualBinaryHash)
		}

		// Écriture atomique avec fichier temporaire et renommage
		tempPath := fmt.Sprintf("%s.tmp.%d", destPath, time.Now().UnixNano())
		if err := os.WriteFile(tempPath, binBytes, 0755); err != nil {
			return nil, fmt.Errorf("écriture temporaire de l'exécutable %s: %w", tempPath, err)
		}
		if err := os.Rename(tempPath, destPath); err != nil {
			_ = os.Remove(tempPath)
			return nil, fmt.Errorf("renommage atomique vers %s: %w", destPath, err)
		}

		result.SyncedTools[name] = destPath
	}

	return result, nil
}

// ResolverOptions configures the toolchain resolver.
type ResolverOptions struct {
	ManifestPath    string
	SigPath         string
	CacheDir        string // Base cache dir, e.g. ~/.compliance/tools
	LocalBinDir     string // Fallback local bin dir, e.g. .tools/bin
	ArchiveCacheDir string // Directory for cached archives, e.g. .tools/cache
	Platform        string // Defaults to DetectPlatform()
	PublicKey       ed25519.PublicKey
	CABundlePath    string
	OfflineOnly     bool
}

// ResolvedTool provides details on a successfully resolved executable.
type ResolvedTool struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	ExecutablePath string `json:"executable_path"`
	SHA256         string `json:"sha256"`
	Source         string `json:"source"` // "local_bin", "cache", "extracted", "synced"
}

// Resolver resolves tool binaries deterministically.
type Resolver struct {
	opts     ResolverOptions
	manifest RuntimeManifest
}

// NewResolver initializes a Tool Resolver, validating the signed distribution manifest.
func NewResolver(opts ResolverOptions) (*Resolver, error) {
	if opts.Platform == "" {
		opts.Platform = DetectPlatform()
	}

	if len(opts.PublicKey) == 0 {
		pubBytes, err := hex.DecodeString(DefaultPhase0PublicKeyHex)
		if err != nil {
			return nil, fmt.Errorf("clé publique par défaut invalide: %w", err)
		}
		opts.PublicKey = ed25519.PublicKey(pubBytes)
	}

	manifestBytes, err := os.ReadFile(opts.ManifestPath)
	if err != nil {
		return nil, fmt.Errorf("lecture du manifeste impossible (%s): %w", opts.ManifestPath, err)
	}

	sigBytes, err := os.ReadFile(opts.SigPath)
	if err != nil {
		return nil, fmt.Errorf("lecture de la signature impossible (%s): %w", opts.SigPath, err)
	}

	if err := VerifyManifest(manifestBytes, string(sigBytes), opts.PublicKey); err != nil {
		return nil, fmt.Errorf("vérification cryptographique du manifeste échouée: %w", err)
	}

	var m RuntimeManifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		return nil, fmt.Errorf("désérialisation JSON du manifeste: %w", err)
	}

	return &Resolver{
		opts:     opts,
		manifest: m,
	}, nil
}

// ResolveTool locates or fetches the tool executable and verifies its SHA-256.
func (r *Resolver) ResolveTool(ctx context.Context, toolName string) (*ResolvedTool, error) {
	plat, ok := r.manifest.Platforms[r.opts.Platform]
	if !ok {
		return nil, fmt.Errorf("%w: plateforme %s non déclarée", ErrPlatformUnsupported, r.opts.Platform)
	}

	toolEntry, ok := plat.Tools[toolName]
	if !ok {
		return nil, fmt.Errorf("%w: %s sur %s", ErrToolNotInManifest, toolName, r.opts.Platform)
	}

	exeName := toolName
	if runtime.GOOS == "windows" && !strings.HasSuffix(exeName, ".exe") {
		exeName += ".exe"
	}

	// 1. Check local bin directory (.tools/bin)
	if r.opts.LocalBinDir != "" {
		candidate := filepath.Join(r.opts.LocalBinDir, exeName)
		if verifyFileSHA256(candidate, toolEntry.BinarySHA256) {
			absPath, _ := filepath.Abs(candidate)
			return &ResolvedTool{
				Name:           toolName,
				Version:        toolEntry.Version,
				ExecutablePath: absPath,
				SHA256:         toolEntry.BinarySHA256,
				Source:         "local_bin",
			}, nil
		}
	}

	// 2. Check cache directory (CacheDir/bin/<platform>/<exeName>)
	cacheTarget := filepath.Join(r.opts.CacheDir, "bin", r.opts.Platform, exeName)
	if verifyFileSHA256(cacheTarget, toolEntry.BinarySHA256) {
		absPath, _ := filepath.Abs(cacheTarget)
		return &ResolvedTool{
			Name:           toolName,
			Version:        toolEntry.Version,
			ExecutablePath: absPath,
			SHA256:         toolEntry.BinarySHA256,
			Source:         "cache",
		}, nil
	}

	// 3. Binary missing: trigger on-demand sync for THIS tool only
	syncRes, err := SyncRuntime(SyncOptions{
		ManifestPath:    r.opts.ManifestPath,
		SigPath:         r.opts.SigPath,
		CacheDir:        r.opts.CacheDir,
		ArchiveCacheDir: r.opts.ArchiveCacheDir,
		Platform:        r.opts.Platform,
		PublicKey:       r.opts.PublicKey,
		CABundlePath:    r.opts.CABundlePath,
		ToolName:        toolName,
		OfflineOnly:     r.opts.OfflineOnly,
	})
	if err != nil {
		if r.opts.OfflineOnly {
			return nil, fmt.Errorf("%w pour %s: %v", ErrToolUnavailableOffline, toolName, err)
		}
		return nil, fmt.Errorf("échec de la synchronisation à la demande pour %s: %w", toolName, err)
	}

	syncedPath, ok := syncRes.SyncedTools[toolName]
	if !ok {
		return nil, fmt.Errorf("l'outil %s n'a pas été produit par SyncRuntime", toolName)
	}

	if !verifyFileSHA256(syncedPath, toolEntry.BinarySHA256) {
		return nil, fmt.Errorf("%w: binaire extrait pour %s invalide", ErrIntegrityViolation, toolName)
	}

	absPath, _ := filepath.Abs(syncedPath)
	return &ResolvedTool{
		Name:           toolName,
		Version:        toolEntry.Version,
		ExecutablePath: absPath,
		SHA256:         toolEntry.BinarySHA256,
		Source:         "synced",
	}, nil
}

func verifyFileSHA256(path, expectedHash string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	h := sha256.Sum256(data)
	actualHex := hex.EncodeToString(h[:])
	return strings.EqualFold(actualHex, expectedHash)
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func fetchBytes(uriOrPath string, client *http.Client) ([]byte, error) {
	if strings.HasPrefix(uriOrPath, "http://") || strings.HasPrefix(uriOrPath, "https://") {
		resp, err := client.Get(uriOrPath)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("code HTTP %d", resp.StatusCode)
		}
		return io.ReadAll(resp.Body)
	}

	if strings.HasPrefix(uriOrPath, "file://") {
		u, err := url.Parse(uriOrPath)
		if err != nil {
			return nil, err
		}
		uriOrPath = u.Path
		if runtime.GOOS == "windows" {
			uriOrPath = strings.TrimPrefix(uriOrPath, "/")
		}
	}

	return os.ReadFile(uriOrPath)
}

func buildHTTPClient(caBundlePath string) *http.Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
	}

	if caBundlePath != "" {
		if caData, err := os.ReadFile(caBundlePath); err == nil {
			rootCAs, _ := x509.SystemCertPool()
			if rootCAs == nil {
				rootCAs = x509.NewCertPool()
			}
			rootCAs.AppendCertsFromPEM(caData)
			transport.TLSClientConfig = &tls.Config{
				RootCAs: rootCAs,
			}
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
	}
}

func extractBinary(archiveBytes []byte, binaryName, sourceURL string) ([]byte, error) {
	lowerSource := strings.ToLower(sourceURL)
	if strings.HasSuffix(lowerSource, ".zip") || strings.HasSuffix(lowerSource, ".whl") {
		zr, err := zip.NewReader(bytes.NewReader(archiveBytes), int64(len(archiveBytes)))
		if err != nil {
			return nil, err
		}
		for _, f := range zr.File {
			base := filepath.Base(f.Name)
			targetBase := filepath.Base(binaryName)
			if strings.EqualFold(base, targetBase) || strings.EqualFold(base, targetBase+".exe") || strings.EqualFold(f.Name, binaryName) {
				rc, err := f.Open()
				if err != nil {
					return nil, err
				}
				defer rc.Close()
				return io.ReadAll(rc)
			}
		}
		return nil, ErrToolNotFound
	}

	if strings.HasSuffix(lowerSource, ".tar.gz") || strings.HasSuffix(lowerSource, ".tgz") {
		gzr, err := gzip.NewReader(bytes.NewReader(archiveBytes))
		if err != nil {
			return nil, err
		}
		defer gzr.Close()
		tr := tar.NewReader(gzr)
		for {
			hdr, err := tr.Next()
			if err != nil {
				break
			}
			base := filepath.Base(hdr.Name)
			if strings.EqualFold(base, binaryName) || strings.EqualFold(base, binaryName+".exe") {
				return io.ReadAll(tr)
			}
		}
		return nil, ErrToolNotFound
	}

	// Raw binary if not an archive
	return archiveBytes, nil
}
