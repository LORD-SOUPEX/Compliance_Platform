package distribution

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
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
	ErrArchiveHashMismatch = errors.New("somme SHA-256 de l'archive téléchargée non conforme")
	ErrBinaryHashMismatch  = errors.New("somme SHA-256 du binaire extrait non conforme")
	ErrPlatformUnsupported = errors.New("plateforme non présente dans le manifeste")
	ErrToolNotFound        = errors.New("binaire introuvable dans l'archive")
)

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
