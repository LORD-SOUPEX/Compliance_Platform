package toolchain

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"compliance/internal/distribution"
)

var (
	ErrToolNotInManifest      = errors.New("outil absent du manifeste pour cette plateforme")
	ErrToolUnavailableOffline = errors.New("outil indisponible hors-ligne (archive absente du cache local)")
	ErrIntegrityViolation     = errors.New("intégrité binaire compromise : somme SHA-256 divergente")
)

// ResolverOptions configures the toolchain resolver.
type ResolverOptions struct {
	ManifestPath    string
	SigPath         string
	CacheDir        string // Base cache dir, e.g. ~/.compliance/tools
	LocalBinDir     string // Fallback local bin dir, e.g. .tools/bin
	ArchiveCacheDir string // Directory for cached archives, e.g. .tools/cache
	Platform        string // Defaults to distribution.DetectPlatform()
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
	manifest distribution.RuntimeManifest
}

// NewResolver initializes a Tool Resolver, validating the signed distribution manifest.
func NewResolver(opts ResolverOptions) (*Resolver, error) {
	if opts.Platform == "" {
		opts.Platform = distribution.DetectPlatform()
	}

	if len(opts.PublicKey) == 0 {
		pubBytes, err := hex.DecodeString(distribution.DefaultPhase0PublicKeyHex)
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

	if err := distribution.VerifyManifest(manifestBytes, string(sigBytes), opts.PublicKey); err != nil {
		return nil, fmt.Errorf("vérification cryptographique du manifeste échouée: %w", err)
	}

	var m distribution.RuntimeManifest
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
		return nil, fmt.Errorf("%w: plateforme %s non déclarée", distribution.ErrPlatformUnsupported, r.opts.Platform)
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
	syncRes, err := distribution.SyncRuntime(distribution.SyncOptions{
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
