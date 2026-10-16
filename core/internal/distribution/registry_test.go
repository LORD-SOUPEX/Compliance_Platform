package distribution

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestVersionNewer(t *testing.T) {
	if !versionNewer("0.17.0", "0.16.10") || !versionNewer("1.10.0", "1.9.4") || versionNewer("0.16.10", "0.16.10") || versionNewer("0.16.9", "0.16.10") {
		t.Fatal("version compare")
	}
}

func TestRefreshRegistryUsesNewerRemoteAndFallsBackOffline(t *testing.T) {
	t.Cleanup(func() { RememberRegistry(RegistrySelection{}) })
	dir := t.TempDir()
	config := filepath.Join(dir, ".config")
	writeTestRegistry(t, filepath.Join(config, "runtime-manifest.json"), filepath.Join(config, "control-catalog.json"), "0.16.10", 1)
	remoteManifest, remoteCatalog := registryBodies("0.17.0", 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/runtime-manifest.json":
			_, _ = w.Write(remoteManifest)
		case "/control-catalog.json":
			_, _ = w.Write(remoteCatalog)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	cache := filepath.Join(dir, "cache")
	selected := RefreshRegistry(context.Background(), RefreshOptions{
		RegistryURL: server.URL,
		CacheDir:    cache,
		LocalRoot:   dir,
		Timeout:     2 * time.Second,
		Client:      server.Client(),
	})
	if selected.Source != "remote" || !strings.Contains(string(mustRead(selected.ManifestPath)), "0.17.0") {
		t.Fatalf("remote selection = %#v", selected)
	}
	offline := RefreshRegistry(context.Background(), RefreshOptions{
		RegistryURL: "http://127.0.0.1:1",
		CacheDir:    cache,
		LocalRoot:   dir,
		Offline:     true,
	})
	if offline.Source != "cache" || !strings.Contains(string(mustRead(offline.CatalogPath)), `"catalog_revision":2`) {
		t.Fatalf("offline selection = %#v body=%s", offline, mustRead(offline.CatalogPath))
	}
}

func TestRefreshRegistryKeepsNewerLocalCopy(t *testing.T) {
	t.Cleanup(func() { RememberRegistry(RegistrySelection{}) })
	dir := t.TempDir()
	config := filepath.Join(dir, ".config")
	writeTestRegistry(t, filepath.Join(config, "runtime-manifest.json"), filepath.Join(config, "control-catalog.json"), "0.17.0", 3)
	bodyM, bodyC := registryBodies("0.16.10", 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "control-catalog.json") {
			_, _ = w.Write(bodyC)
			return
		}
		_, _ = w.Write(bodyM)
	}))
	defer server.Close()
	selected := RefreshRegistry(context.Background(), RefreshOptions{
		RegistryURL: server.URL,
		CacheDir:    filepath.Join(dir, "cache"),
		LocalRoot:   dir,
		Client:      server.Client(),
	})
	if selected.Source != "local" || !strings.Contains(string(mustRead(selected.ManifestPath)), "0.17.0") {
		t.Fatalf("local should win: %#v", selected)
	}
}

func TestUpgradeSkipsAbsentTools(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "runtime-manifest.json")
	writeTestRegistry(t, manifest, filepath.Join(dir, "control-catalog.json"), "0.17.0", 1)
	cache := filepath.Join(dir, "tools")
	if upgraded := UpgradeInstalledTools(UpgradeOptions{ManifestPath: manifest, BaselinePath: manifest, CacheDir: cache}); len(upgraded) != 0 {
		t.Fatalf("absent tools upgraded: %v", upgraded)
	}
	if _, err := os.Stat(filepath.Join(cache, "installed-versions.json")); !os.IsNotExist(err) {
		t.Fatal("stamp should not be created when nothing is installed")
	}
}

func writeTestRegistry(t *testing.T, manifestPath, catalogPath, version string, revision int) {
	t.Helper()
	manifest, catalog := registryBodies(version, revision)
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(catalogPath, catalog, 0o644); err != nil {
		t.Fatal(err)
	}
}

func registryBodies(version string, revision int) ([]byte, []byte) {
	manifest := []byte(`{"schema_version":3,"manifest_version":"2.1.0","registry_base_url":"https://example.test","platforms":{"windows-x64":{"status":"qualified","tools":{"ruff":{"name":"ruff","version":"` + version + `"}}}}}`)
	catalog := []byte(`{"schema_version":1,"catalog_revision":` + strconv.Itoa(revision) + `,"controls":[{},{},{}]}`)
	return manifest, catalog
}
