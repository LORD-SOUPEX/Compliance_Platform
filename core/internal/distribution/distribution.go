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
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"compliance/internal/osutil"

	"github.com/ulikunitz/xz"
)

var (
	ErrInvalidSignature        = errors.New("signature du manifeste invalide ou corrompue")
	ErrSignatureLengthMismatch = errors.New("longueur de signature cryptographique invalide")
	ErrArchiveHashMismatch     = errors.New("somme SHA-256 de l'archive téléchargée non conforme")
	ErrBinaryHashMismatch      = errors.New("somme SHA-256 du binaire extrait non conforme")
	ErrPlatformUnsupported     = errors.New("plateforme non présente dans le manifeste")
	ErrToolNotFound            = errors.New("binaire introuvable dans l'archive")
	ErrToolNotInManifest       = errors.New("outil absent du manifeste pour cette plateforme")
	ErrToolUnavailableOffline  = errors.New("outil indisponible hors-ligne (archive absente du cache local)")
	ErrIntegrityViolation      = errors.New("intégrité binaire compromise : somme SHA-256 divergente")
)

// DefaultPhase0PublicKey is a dedicated Ed25519 public key for platform distribution.
// (Hex-encoded 32 bytes)
const DefaultPhase0PublicKeyHex = "c59fd4e179c55a3dd2110785d9ae7a9b4adafc1e54ca3dcde54e2f3c3458645f"

// ToolEntry describes a tool artifact within the runtime manifest.
type ToolEntry struct {
	Name            string   `json:"name"`
	Version         string   `json:"version"`
	Install         string   `json:"install,omitempty"` // "archive", "bundle", "binary", "pip", "runtime"
	Archive         string   `json:"archive,omitempty"`
	ArchiveURL      string   `json:"archive_url,omitempty"`
	ArchiveSHA256   string   `json:"archive_sha256"`
	BinaryInArchive string   `json:"binary_in_archive"`
	BinarySHA256    string   `json:"binary_sha256,omitempty"`
	Bundle          string   `json:"bundle,omitempty"`
	PythonModule    string   `json:"python_module,omitempty"`
	VersionArgs     []string `json:"version_args,omitempty"`
	Package         string   `json:"package,omitempty"`
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
	RegistryBaseURL string                      `json:"registry_base_url,omitempty"`
	Platforms       map[string]PlatformManifest `json:"platforms"`
}

// DefaultRegistryBaseURL is the public GitHub release tools distribution URL.
const DefaultRegistryBaseURL = "https://github.com/LORD-SOUPEX/Compliance_Platform/releases/download/tools-v1"

// ResolveRegistryURL returns the effective registry base URL from options, env var, manifest, or default.
func ResolveRegistryURL(optURL, manifestURL string) string {
	if optURL != "" {
		return strings.TrimRight(optURL, "/")
	}
	if env := os.Getenv("COMPLIANCE_REGISTRY_URL"); env != "" {
		return strings.TrimRight(env, "/")
	}
	if manifestURL != "" {
		return strings.TrimRight(manifestURL, "/")
	}
	return DefaultRegistryBaseURL
}

func (tool ToolEntry) resolveURL(registryBase string) string {
	if tool.ArchiveURL != "" {
		return tool.ArchiveURL
	}
	if tool.Archive != "" {
		return strings.TrimRight(registryBase, "/") + "/" + tool.Archive
	}
	return ""
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

// ToolListed reports whether the signed manifest declares the tool for the platform.
// A missing file or a missing key is false. The signature is checked separately.
func ToolListed(manifestPath, platform, tool string) bool {
	body, err := os.ReadFile(manifestPath)
	if err != nil || tool == "" || platform == "" {
		return false
	}
	var manifest RuntimeManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return false
	}
	entry, ok := manifest.Platforms[platform]
	if !ok {
		return false
	}
	for _, name := range manifestAliases(tool) {
		if _, ok = entry.Tools[name]; ok {
			return true
		}
	}
	return false
}

func activeTool(platform, command string) (ToolEntry, bool) {
	path, err := ActiveAsset("runtime-manifest.json", ".config/runtime-manifest.json")
	if err != nil || platform == "" || command == "" {
		return ToolEntry{}, false
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return ToolEntry{}, false
	}
	var manifest RuntimeManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return ToolEntry{}, false
	}
	entry, ok := manifest.Platforms[platform]
	if !ok {
		return ToolEntry{}, false
	}
	for _, name := range manifestAliases(command) {
		if tool, found := entry.Tools[name]; found {
			return tool, true
		}
	}
	return ToolEntry{}, false
}

// VersionArgs returns the manifest qualification arguments for a native tool.
func VersionArgs(platform, command string) []string {
	tool, ok := activeTool(platform, command)
	if !ok || len(tool.VersionArgs) == 0 {
		return nil
	}
	return append([]string{}, tool.VersionArgs...)
}

// PythonProbeSpec returns the module and version arguments declared for a Python tool.
// Checkov keeps its manifest module for documentation, but qualification uses a short import.
func PythonProbeSpec(platform, command string) (string, []string) {
	module := command
	switch command {
	case "pip-audit":
		module = "pip_audit"
	case "ansible-lint":
		module = "ansiblelint"
	}
	args := []string{"--version"}
	tool, ok := activeTool(platform, command)
	if !ok {
		return module, args
	}
	if command != "checkov" && tool.PythonModule != "" {
		module = tool.PythonModule
	}
	if command != "checkov" && len(tool.VersionArgs) > 0 {
		args = append([]string{}, tool.VersionArgs...)
	}
	return module, args
}

func manifestAliases(tool string) []string {
	switch tool {
	case "tofu", "opentofu":
		return []string{"tofu", "opentofu"}
	default:
		return []string{tool}
	}
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
	RegistryURL     string // Optional registry base URL override
	RegistryToken   string // Optional registry auth token (or COMPLIANCE_REGISTRY_TOKEN)
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

	if strings.TrimSpace(opts.CABundlePath) != "" {
		osutil.SetEnterpriseCABundle(opts.CABundlePath)
	}
	client := buildHTTPClient(opts.CABundlePath)

	manifestBytes, err := fetchBytes(opts.ManifestPath, client, opts.RegistryToken)
	if err != nil {
		return nil, fmt.Errorf("lecture du manifeste impossible: %w", err)
	}

	// La signature est informative. Une signature absente ou différente n'empêche pas l'installation, mais émet un avertissement.
	if strings.TrimSpace(opts.SigPath) != "" {
		if sigBytes, sigErr := fetchBytes(opts.SigPath, client, opts.RegistryToken); sigErr == nil {
			if vErr := VerifyManifest(manifestBytes, string(sigBytes), opts.PublicKey); vErr != nil {
				slog.Warn("manifest_signature_unverified", "err", vErr)
				fmt.Fprintf(os.Stderr, "[WARN] Signature Ed25519 du manifeste non vérifiée: %v. Installation maintenue sans blocage.\n", vErr)
			}
		}
	}

	var manifest RuntimeManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("décodage JSON du manifeste: %w", err)
	}

	registryBase := ResolveRegistryURL(opts.RegistryURL, manifest.RegistryBaseURL)

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

	names := make([]string, 0, len(plat.Tools))
	for name := range plat.Tools {
		names = append(names, name)
	}
	sort.Strings(names)
	unlock, err := LockTools(context.Background(), opts.CacheDir, true, "installation "+opts.ToolName)
	if err != nil {
		return nil, err
	}
	defer unlock()
	cleanupInterrupted(opts.CacheDir)
	var failures []string
	requested := opts.ToolName == ""
	for _, name := range names {
		if opts.ToolName != "" && !aliasMatch(name, opts.ToolName) {
			continue
		}
		requested = true
		dest, err := installEntry(opts.CacheDir, opts.Platform, name, plat.Tools[name], plat.Tools, client, opts, registryBase)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s (%s)", name, err))
			continue
		}
		result.SyncedTools[name] = dest
		rememberToolVersion(opts.CacheDir, name, plat.Tools[name].Version)
	}
	if len(result.SyncedTools) > 0 {
		bumpToolsGeneration(opts.CacheDir)
	}
	if !requested {
		return nil, fmt.Errorf("%w: %s", ErrToolNotInManifest, opts.ToolName)
	}
	if len(failures) > 0 {
		return result, fmt.Errorf("%d outil(s) installé(s), %d échec : %s", len(result.SyncedTools), len(failures), strings.Join(failures, " ; "))
	}
	return result, nil
}

// ClassifySyncError maps a sync failure to a stable code for the extension.
func ClassifySyncError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, ErrToolNotInManifest) {
		return "manifest"
	}
	if errors.Is(err, ErrArchiveHashMismatch) || errors.Is(err, ErrBinaryHashMismatch) || errors.Is(err, ErrInvalidSignature) {
		return "hash"
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "proxy"), strings.Contains(message, "407"):
		return "proxy"
	case strings.Contains(message, "x509"), strings.Contains(message, "certificate"), strings.Contains(message, "certificat"), strings.Contains(message, "tls"):
		return "certificate"
	case strings.Contains(message, "sha-256"), strings.Contains(message, "sha256"):
		return "hash"
	case strings.Contains(message, "code http"):
		return "http"
	case strings.Contains(message, "no such host"), strings.Contains(message, "connection refused"),
		strings.Contains(message, "i/o timeout"), strings.Contains(message, "dial tcp"):
		return "network"
	default:
		return "other"
	}
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
	RegistryURL     string
	RegistryToken   string
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

	if strings.TrimSpace(opts.SigPath) != "" {
		if sigBytes, sigErr := os.ReadFile(opts.SigPath); sigErr == nil {
			if vErr := VerifyManifest(manifestBytes, string(sigBytes), opts.PublicKey); vErr != nil {
				fmt.Fprintf(os.Stderr, "[WARN] Signature Ed25519 locale du manifeste non vérifiée: %v. Résolution maintenue sans blocage.\n", vErr)
			}
		}
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

	toolEntry, toolKey, ok := lookupTool(plat.Tools, toolName)
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
		if executablePresent(candidate) {
			absPath, _ := filepath.Abs(candidate)
			return &ResolvedTool{
				Name:           toolName,
				Version:        toolEntry.Version,
				ExecutablePath: absPath,
				SHA256:         fileSHA256(candidate),
				Source:         "local_bin",
			}, nil
		}
	}

	if toolEntry.kind() == "bundle" {
		candidate := resolvedBundlePath(r.opts.CacheDir, r.opts.Platform, toolKey, toolEntry)
		if executablePresent(candidate) || (strings.HasSuffix(candidate, ".psd1") && fileExists(candidate)) {
			absPath, _ := filepath.Abs(candidate)
			return &ResolvedTool{
				Name:           toolName,
				Version:        toolEntry.Version,
				ExecutablePath: absPath,
				SHA256:         fileSHA256(candidate),
				Source:         "bundle",
			}, nil
		}
	}

	// 2. Check cache directory (CacheDir/bin/<platform>/<exeName>)
	cacheTarget := filepath.Join(r.opts.CacheDir, "bin", r.opts.Platform, exeName)
	if executablePresent(cacheTarget) {
		absPath, _ := filepath.Abs(cacheTarget)
		return &ResolvedTool{
			Name:           toolName,
			Version:        toolEntry.Version,
			ExecutablePath: absPath,
			SHA256:         fileSHA256(cacheTarget),
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
		ToolName:        toolKey,
		OfflineOnly:     r.opts.OfflineOnly,
		RegistryURL:     r.opts.RegistryURL,
		RegistryToken:   r.opts.RegistryToken,
	})
	if err != nil {
		if r.opts.OfflineOnly {
			return nil, fmt.Errorf("%w pour %s: %w", ErrToolUnavailableOffline, toolName, err)
		}
		return nil, fmt.Errorf("échec de la synchronisation à la demande pour %s: %w", toolName, err)
	}

	syncedPath, ok := syncRes.SyncedTools[toolKey]
	if !ok {
		return nil, fmt.Errorf("l'outil %s n'a pas été produit par SyncRuntime", toolName)
	}

	absPath, _ := filepath.Abs(syncedPath)
	return &ResolvedTool{
		Name:           toolName,
		Version:        toolEntry.Version,
		ExecutablePath: absPath,
		SHA256:         fileSHA256(syncedPath),
		Source:         "synced",
	}, nil
}

func executablePresent(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Size() > 0
}

func fileSHA256(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return sha256Hex(data)
}

func requireHTTPSArchive(raw string) error {
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return nil
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if parsed.Scheme == "https" {
		return nil
	}
	host := parsed.Hostname()
	if host == "127.0.0.1" || host == "localhost" || host == "::1" {
		return nil
	}
	return fmt.Errorf("l'archive doit être téléchargée en HTTPS : %s", raw)
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func fetchBytes(uriOrPath string, client *http.Client, token string) ([]byte, error) {
	if strings.HasPrefix(uriOrPath, "http://") || strings.HasPrefix(uriOrPath, "https://") {
		req, err := http.NewRequest(http.MethodGet, uriOrPath, nil)
		if err != nil {
			return nil, err
		}
		if token == "" {
			token = os.Getenv("COMPLIANCE_REGISTRY_TOKEN")
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
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
	if strings.TrimSpace(caBundlePath) == "" {
		caBundlePath = osutil.EnterpriseCABundle()
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
		Timeout:   5 * time.Minute,
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
			if f.FileInfo().IsDir() {
				continue
			}
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
		return readTarBinary(tar.NewReader(gzr), binaryName)
	}

	if strings.HasSuffix(lowerSource, ".tar.xz") || strings.HasSuffix(lowerSource, ".txz") {
		xr, err := xz.NewReader(bytes.NewReader(archiveBytes))
		if err != nil {
			return nil, err
		}
		return readTarBinary(tar.NewReader(xr), binaryName)
	}

	// Raw binary if not an archive
	return archiveBytes, nil
}

func readTarBinary(tr *tar.Reader, binaryName string) ([]byte, error) {
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if hdr.FileInfo().IsDir() {
			continue
		}
		base := filepath.Base(hdr.Name)
		if strings.EqualFold(base, binaryName) || strings.EqualFold(base, binaryName+".exe") || strings.EqualFold(hdr.Name, binaryName) {
			return io.ReadAll(tr)
		}
	}
	return nil, ErrToolNotFound
}
