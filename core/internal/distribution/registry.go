package distribution

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"compliance/internal/embedded"
)

const registryRefreshTimeout = 3 * time.Second

// RegistrySelection is the manifest and catalog the process should use.
type RegistrySelection struct {
	ManifestPath string
	CatalogPath  string
	SigPath      string
	Source       string // remote, cache, local
	RegistryURL  string
}

// RefreshOptions configures a short registry lookup.
type RefreshOptions struct {
	RegistryURL   string
	RegistryToken string
	Timeout       time.Duration
	CacheDir      string
	LocalRoot     string
	Offline       bool
	Client        *http.Client
}

type registryFreshness struct {
	CatalogRevision int
	ManifestVersion string
	Tools           map[string]string
}

var (
	activeMu sync.RWMutex
	active   RegistrySelection
)

// RememberRegistry keeps the selection for later lookups in this process.
func RememberRegistry(selection RegistrySelection) {
	activeMu.Lock()
	active = selection
	activeMu.Unlock()
}

// ActiveAsset returns the refreshed registry file when one was selected,
// otherwise the first existing candidate or the embedded copy.
func ActiveAsset(name string, candidates ...string) (string, error) {
	activeMu.RLock()
	selection := active
	activeMu.RUnlock()
	preferred := ""
	switch name {
	case "runtime-manifest.json":
		preferred = selection.ManifestPath
	case "control-catalog.json":
		preferred = selection.CatalogPath
	case "runtime-manifest.json.sig":
		preferred = selection.SigPath
	}
	if preferred != "" {
		if info, err := os.Stat(preferred); err == nil && !info.IsDir() {
			return preferred, nil
		}
	}
	return embedded.ResolveAsset(name, candidates...)
}

// RegistryCacheDir is ~/.compliance/registry-cache.
func RegistryCacheDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(os.TempDir(), ".compliance", "registry-cache")
	}
	return filepath.Join(home, ".compliance", "registry-cache")
}

// RefreshRegistry checks the GitHub registry with a short timeout.
// A newer remote manifest or catalog is stored in the cache.
// Offline, or when the remote is not newer, the cache wins over the embedded files, then the local files.
func RefreshRegistry(ctx context.Context, opts RefreshOptions) RegistrySelection {
	if opts.Timeout <= 0 {
		opts.Timeout = registryRefreshTimeout
	}
	if opts.CacheDir == "" {
		opts.CacheDir = RegistryCacheDir()
	}
	if opts.Offline || os.Getenv("COMPLIANCE_OFFLINE") == "1" {
		opts.Offline = true
	}
	localManifest := firstExisting(
		filepath.Join(opts.LocalRoot, ".config", "runtime-manifest.json"),
	)
	localCatalog := firstExisting(
		filepath.Join(opts.LocalRoot, ".config", "control-catalog.json"),
	)
	localSig := firstExisting(
		filepath.Join(opts.LocalRoot, ".config", "runtime-manifest.json.sig"),
	)
	if localManifest == "" {
		if resolved, err := embedded.ResolveAsset("runtime-manifest.json"); err == nil {
			localManifest = resolved
		}
	}
	if localCatalog == "" {
		if resolved, err := embedded.ResolveAsset("control-catalog.json"); err == nil {
			localCatalog = resolved
		}
	}
	if localSig == "" {
		if resolved, err := embedded.ResolveAsset("runtime-manifest.json.sig"); err == nil {
			localSig = resolved
		}
	}

	cacheManifest := filepath.Join(opts.CacheDir, "runtime-manifest.json")
	cacheCatalog := filepath.Join(opts.CacheDir, "control-catalog.json")
	cacheSig := filepath.Join(opts.CacheDir, "runtime-manifest.json.sig")

	baselineManifest, baselineCatalog, baselineSig, baselineSource := localManifest, localCatalog, localSig, "local"
	if fileExists(cacheManifest) && fileExists(cacheCatalog) && newerThan(cacheManifest, cacheCatalog, localManifest, localCatalog) {
		baselineManifest, baselineCatalog, baselineSource = cacheManifest, cacheCatalog, "cache"
		if fileExists(cacheSig) {
			baselineSig = cacheSig
		}
	}

	selection := RegistrySelection{
		ManifestPath: baselineManifest,
		CatalogPath:  baselineCatalog,
		SigPath:      baselineSig,
		Source:       baselineSource,
	}
	registryURL := opts.RegistryURL
	if registryURL == "" {
		registryURL = os.Getenv("COMPLIANCE_REGISTRY_URL")
	}
	if registryURL == "" {
		registryURL = registryURLFrom(baselineManifest)
	}
	registryURL = strings.TrimRight(ResolveRegistryURL(registryURL, ""), "/")
	selection.RegistryURL = registryURL

	if opts.Offline || registryURL == "" {
		RememberRegistry(selection)
		return selection
	}

	fetchCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: opts.Timeout}
	}
	remoteManifest, manifestErr := fetchLimited(fetchCtx, client, registryURL+"/runtime-manifest.json", opts.RegistryToken)
	remoteCatalog, catalogErr := fetchLimited(fetchCtx, client, registryURL+"/control-catalog.json", opts.RegistryToken)
	if manifestErr != nil || catalogErr != nil || !validManifest(remoteManifest) || !validCatalog(remoteCatalog) {
		slog.Warn("registry_unreachable", "url", registryURL, "manifest_err", manifestErr, "catalog_err", catalogErr)
		RememberRegistry(selection)
		return selection
	}
	if !newerThanBytes(remoteManifest, remoteCatalog, mustRead(baselineManifest), mustRead(baselineCatalog)) {
		RememberRegistry(selection)
		return selection
	}
	if err := writeRegistryFile(cacheManifest, remoteManifest); err != nil {
		RememberRegistry(selection)
		return selection
	}
	if err := writeRegistryFile(cacheCatalog, remoteCatalog); err != nil {
		RememberRegistry(selection)
		return selection
	}
	if remoteSig, sigErr := fetchLimited(fetchCtx, client, registryURL+"/runtime-manifest.json.sig", opts.RegistryToken); sigErr == nil && len(strings.TrimSpace(string(remoteSig))) >= 64 {
		_ = writeRegistryFile(cacheSig, remoteSig)
		selection.SigPath = cacheSig
	}
	selection.ManifestPath = cacheManifest
	selection.CatalogPath = cacheCatalog
	selection.Source = "remote"
	RememberRegistry(selection)
	slog.Info("registry_refreshed", "url", registryURL, "manifest", cacheManifest, "catalog", cacheCatalog)
	return selection
}

// UpgradeOptions updates tools already present in the local cache.
type UpgradeOptions struct {
	ManifestPath string
	BaselinePath string
	SigPath      string
	CacheDir     string
	RegistryURL  string
	Token        string
	// OnUpgrade reports an upgrade starting (true) and ending (false), for /health.
	OnUpgrade func(tool string, active bool)
}

// UpgradeInstalledTools replaces an installed tool when the active manifest
// announces a higher version. A tool without a recorded version is stamped
// from the baseline manifest and is not downloaded.
func UpgradeInstalledTools(opts UpgradeOptions) []string {
	if opts.CacheDir == "" || opts.ManifestPath == "" {
		return nil
	}
	active, err := readManifest(opts.ManifestPath)
	if err != nil {
		return nil
	}
	baselinePath := opts.BaselinePath
	if baselinePath == "" {
		baselinePath = opts.ManifestPath
	}
	baseline, err := readManifest(baselinePath)
	if err != nil {
		baseline = active
	}
	platform := DetectPlatform()
	activeTools, origin, _ := toolsForHost(active, platform)
	baseTools, _, _ := toolsForHost(baseline, platform)
	stamp := readInstalledVersions(opts.CacheDir)
	changed := false
	var upgraded []string
	names := make([]string, 0, len(activeTools))
	for name := range activeTools {
		names = append(names, name)
	}
	for _, name := range names {
		entry := activeTools[name]
		if !toolPresent(opts.CacheDir, origin[name], name, entry) {
			continue
		}
		known := stamp[name]
		if known == "" {
			if base, ok := baseTools[name]; ok && base.Version != "" {
				known = base.Version
			} else {
				known = entry.Version
			}
			stamp[name] = known
			changed = true
		}
		if !versionNewer(entry.Version, known) {
			continue
		}
		slog.Info("tool_upgrade_started", "tool", name, "from", known, "version", entry.Version)
		if opts.OnUpgrade != nil {
			opts.OnUpgrade(name, true)
		}
		_, syncErr := SyncRuntime(SyncOptions{
			ManifestPath:  opts.ManifestPath,
			SigPath:       opts.SigPath,
			CacheDir:      opts.CacheDir,
			Platform:      platform,
			ToolName:      name,
			RegistryURL:   opts.RegistryURL,
			RegistryToken: opts.Token,
		})
		if opts.OnUpgrade != nil {
			opts.OnUpgrade(name, false)
		}
		if syncErr != nil {
			slog.Warn("tool_upgrade_failed", "tool", name, "version", entry.Version, "err", syncErr)
			continue
		}
		stamp[name] = entry.Version
		changed = true
		upgraded = append(upgraded, name)
		slog.Info("tool_upgraded", "tool", name, "from", known, "version", entry.Version)
	}
	if changed {
		_ = writeInstalledVersions(opts.CacheDir, stamp)
	}
	return upgraded
}

func toolPresent(cacheDir, platform, name string, entry ToolEntry) bool {
	if entry.kind() == "bundle" || entry.kind() == "runtime" {
		dest := resolvedBundlePath(cacheDir, platform, name, entry)
		return dest != "" && fileExists(dest)
	}
	return fileExists(filepath.Join(cacheDir, "bin", platform, executableFileName(name, entry)))
}

func rememberToolVersion(cacheDir, name, version string) {
	if cacheDir == "" || name == "" || version == "" {
		return
	}
	stamp := readInstalledVersions(cacheDir)
	stamp[name] = version
	_ = writeInstalledVersions(cacheDir, stamp)
}

func installedVersionsPath(cacheDir string) string {
	return filepath.Join(cacheDir, "installed-versions.json")
}

func readInstalledVersions(cacheDir string) map[string]string {
	body, err := os.ReadFile(installedVersionsPath(cacheDir))
	out := map[string]string{}
	if err != nil {
		return out
	}
	_ = json.Unmarshal(body, &out)
	if out == nil {
		out = map[string]string{}
	}
	return out
}

func writeInstalledVersions(cacheDir string, versions map[string]string) error {
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return err
	}
	body, err := json.MarshalIndent(versions, "", "  ")
	if err != nil {
		return err
	}
	return writeRegistryFile(installedVersionsPath(cacheDir), append(body, '\n'))
}

func newerThan(remoteManifest, remoteCatalog, localManifest, localCatalog string) bool {
	return newerThanBytes(mustRead(remoteManifest), mustRead(remoteCatalog), mustRead(localManifest), mustRead(localCatalog))
}

func newerThanBytes(remoteManifest, remoteCatalog, localManifest, localCatalog []byte) bool {
	remote := freshnessOf(remoteManifest, remoteCatalog)
	local := freshnessOf(localManifest, localCatalog)
	if remote.CatalogRevision > local.CatalogRevision {
		return true
	}
	if versionNewer(remote.ManifestVersion, local.ManifestVersion) {
		return true
	}
	for key, version := range remote.Tools {
		current, ok := local.Tools[key]
		if !ok || versionNewer(version, current) {
			return true
		}
	}
	return false
}

func freshnessOf(manifestBody, catalogBody []byte) registryFreshness {
	fresh := registryFreshness{Tools: map[string]string{}}
	var manifest RuntimeManifest
	if json.Unmarshal(manifestBody, &manifest) == nil {
		fresh.ManifestVersion = manifest.ManifestVersion
		for platform, entry := range manifest.Platforms {
			for name, tool := range entry.Tools {
				fresh.Tools[platform+"\x00"+name] = tool.Version
			}
		}
	}
	var catalog struct {
		Revision int `json:"catalog_revision"`
	}
	if json.Unmarshal(catalogBody, &catalog) == nil {
		fresh.CatalogRevision = catalog.Revision
	}
	return fresh
}

func versionNewer(remote, local string) bool {
	if strings.TrimSpace(remote) == "" {
		return false
	}
	remoteParts := versionParts(remote)
	localParts := versionParts(local)
	count := len(remoteParts)
	if len(localParts) > count {
		count = len(localParts)
	}
	for i := 0; i < count; i++ {
		rv, lv := 0, 0
		if i < len(remoteParts) {
			rv = remoteParts[i]
		}
		if i < len(localParts) {
			lv = localParts[i]
		}
		if rv != lv {
			return rv > lv
		}
	}
	return false
}

func versionParts(value string) []int {
	value = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(value), "v"))
	var parts []int
	current := -1
	flush := func() {
		if current >= 0 {
			parts = append(parts, current)
			current = -1
		}
	}
	for _, r := range value {
		if r >= '0' && r <= '9' {
			if current < 0 {
				current = 0
			}
			current = current*10 + int(r-'0')
			continue
		}
		flush()
	}
	flush()
	return parts
}

func validManifest(body []byte) bool {
	var manifest RuntimeManifest
	if json.Unmarshal(body, &manifest) != nil || manifest.SchemaVersion < 1 || len(manifest.Platforms) == 0 {
		return false
	}
	return true
}

func validCatalog(body []byte) bool {
	var catalog struct {
		SchemaVersion int             `json:"schema_version"`
		Controls      json.RawMessage `json:"controls"`
	}
	if json.Unmarshal(body, &catalog) != nil || catalog.SchemaVersion != 1 || len(catalog.Controls) < 3 {
		return false
	}
	return catalog.Controls[0] == '['
}

func registryURLFrom(manifestPath string) string {
	body, err := os.ReadFile(manifestPath)
	if err != nil {
		return ""
	}
	var manifest RuntimeManifest
	if json.Unmarshal(body, &manifest) != nil {
		return ""
	}
	return manifest.RegistryBaseURL
}

func readManifest(path string) (RuntimeManifest, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return RuntimeManifest{}, err
	}
	var manifest RuntimeManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return RuntimeManifest{}, err
	}
	return manifest, nil
}

func fetchLimited(ctx context.Context, client *http.Client, rawURL, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
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
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

func writeRegistryFile(path string, body []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temp := path + ".tmp"
	if err := os.WriteFile(temp, body, 0o600); err != nil {
		return err
	}
	return os.Rename(temp, path)
}

func firstExisting(paths ...string) string {
	for _, path := range paths {
		if path != "" && fileExists(path) {
			return path
		}
	}
	return ""
}

func mustRead(path string) []byte {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return body
}
