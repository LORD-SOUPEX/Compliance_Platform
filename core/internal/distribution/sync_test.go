package distribution

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSyncInstallsVerifiedToolAndRejectsNetworkFailure(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("tool-bytes")
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	entry, err := zw.Create("hello.exe")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	archiveBytes := archive.Bytes()
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "hello.zip")
	if err := os.WriteFile(archivePath, archiveBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := RuntimeManifest{
		SchemaVersion:   2,
		ManifestVersion: "test",
		Platforms: map[string]PlatformManifest{
			"windows-x64": {
				Status: "qualified",
				Tools: map[string]ToolEntry{
					"hello": {
						Name:            "hello",
						Version:         "1.2.3",
						ArchiveURL:      archivePath,
						ArchiveSHA256:   sha(archiveBytes),
						BinaryInArchive: "hello.exe",
						BinarySHA256:    sha(payload),
					},
					"other": {
						Name:            "other",
						Version:         "9.9.9",
						ArchiveURL:      archivePath,
						ArchiveSHA256:   sha(archiveBytes),
						BinaryInArchive: "hello.exe",
						BinarySHA256:    sha(payload),
					},
				},
			},
		},
	}
	manifestPath, sigPath := writeSignedManifest(t, dir, manifest, priv)
	cache := filepath.Join(dir, "cache")
	result, err := SyncRuntime(SyncOptions{
		ManifestPath: manifestPath,
		SigPath:      sigPath,
		CacheDir:     cache,
		Platform:     "windows-x64",
		PublicKey:    pub,
		ToolName:     "hello",
	})
	if err != nil {
		t.Fatal(err)
	}
	installed, ok := result.SyncedTools["hello"]
	if !ok {
		t.Fatal("hello was not installed")
	}
	if _, exists := result.SyncedTools["other"]; exists {
		t.Fatal("sync installed a tool that was not requested")
	}
	body, err := os.ReadFile(installed)
	if err != nil || string(body) != string(payload) {
		t.Fatalf("installed bytes = %q, err = %v", body, err)
	}
	if _, err := os.Stat(filepath.Join(cache, "bin", "windows-x64", "other.exe")); err == nil {
		t.Fatal("unrequested tool was written")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "offline", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	manifest.Platforms["windows-x64"].Tools["hello"] = ToolEntry{
		Name: "hello", Version: "1.2.3", ArchiveURL: server.URL, ArchiveSHA256: sha(archiveBytes), BinaryInArchive: "hello.exe", BinarySHA256: sha(payload),
	}
	failedDir := filepath.Join(dir, "failed")
	failedManifest, failedSig := writeSignedManifest(t, failedDir, manifest, priv)
	failedCache := filepath.Join(dir, "failed-cache")
	_, err = SyncRuntime(SyncOptions{
		ManifestPath: failedManifest,
		SigPath:      failedSig,
		CacheDir:     failedCache,
		Platform:     "windows-x64",
		PublicKey:    pub,
		ToolName:     "hello",
	})
	if err == nil {
		t.Fatal("network failure was ignored")
	}
	if ClassifySyncError(err) != "http" || !strings.Contains(err.Error(), "hello") || !strings.Contains(err.Error(), "503") {
		t.Fatalf("class = %s, err = %v", ClassifySyncError(err), err)
	}
	if matches, _ := filepath.Glob(filepath.Join(failedCache, "bin", "windows-x64", "*")); len(matches) != 0 {
		t.Fatalf("partial install left files: %v", matches)
	}

	_, err = SyncRuntime(SyncOptions{
		ManifestPath: manifestPath,
		SigPath:      sigPath,
		CacheDir:     filepath.Join(dir, "missing"),
		Platform:     "windows-x64",
		PublicKey:    pub,
		ToolName:     "pre-commit",
	})
	if err == nil || ClassifySyncError(err) != "manifest" || !strings.Contains(err.Error(), "pre-commit") {
		t.Fatalf("missing manifest tool err = %v", err)
	}
}

func writeSignedManifest(t *testing.T, dir string, manifest RuntimeManifest, key ed25519.PrivateKey) (string, string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, "runtime-manifest.json")
	sigPath := filepath.Join(dir, "runtime-manifest.json.sig")
	if err := os.WriteFile(manifestPath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sigPath, []byte(SignManifest(body, key)), 0o644); err != nil {
		t.Fatal(err)
	}
	return manifestPath, sigPath
}

func TestSyncInstallsWhenSignatureAndHashesDoNotMatch(t *testing.T) {
	payload := []byte("rumdl-bytes")
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	entry, err := zw.Create("rumdl.exe")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "rumdl.zip")
	if err := os.WriteFile(archivePath, archive.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := RuntimeManifest{
		SchemaVersion: 2, ManifestVersion: "test",
		Platforms: map[string]PlatformManifest{
			"windows-x64": {Status: "qualified", Tools: map[string]ToolEntry{
				"rumdl": {Name: "rumdl", Version: "0.2.79", ArchiveURL: archivePath, ArchiveSHA256: "deadbeef", BinaryInArchive: "rumdl.exe", BinarySHA256: "cafebabe"},
			}},
		},
	}
	body, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, "runtime-manifest.json")
	sigPath := filepath.Join(dir, "runtime-manifest.json.sig")
	if err := os.WriteFile(manifestPath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sigPath, []byte("00"), 0o644); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(dir, "tools")
	_, err = SyncRuntime(SyncOptions{ManifestPath: manifestPath, SigPath: sigPath, CacheDir: cache, Platform: "windows-x64", ToolName: "rumdl"})
	if err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("hash mismatch must refuse the binary, err = %v", err)
	}
	if ClassifySyncError(err) != "hash" {
		t.Fatalf("hash class = %s (%v)", ClassifySyncError(err), err)
	}
	if _, statErr := os.Stat(filepath.Join(cache, "bin", "windows-x64", "rumdl.exe")); !os.IsNotExist(statErr) {
		t.Fatalf("binary installed despite hash mismatch: %v", statErr)
	}

	manifest.Platforms["windows-x64"].Tools["rumdl"] = ToolEntry{Name: "rumdl", Version: "0.2.79", ArchiveURL: "http://example.com/rumdl.zip", BinaryInArchive: "rumdl.exe"}
	clearBody, _ := json.Marshal(manifest)
	clearManifest := filepath.Join(dir, "clear.json")
	if err := os.WriteFile(clearManifest, clearBody, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = SyncRuntime(SyncOptions{ManifestPath: clearManifest, CacheDir: filepath.Join(dir, "http"), Platform: "windows-x64", ToolName: "rumdl"})
	if err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("cleartext archive err = %v", err)
	}
}

func TestSyncKeepsSuccessfulTools(t *testing.T) {
	payload := []byte("kept-bytes")
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	entry, err := zw.Create("kept.exe")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "kept.zip")
	if err := os.WriteFile(archivePath, archive.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "missing", http.StatusNotFound)
	}))
	defer server.Close()
	manifest := RuntimeManifest{
		SchemaVersion: 2, ManifestVersion: "test",
		Platforms: map[string]PlatformManifest{
			"windows-x64": {Status: "qualified", Tools: map[string]ToolEntry{
				"kept":   {Name: "kept", Version: "1", ArchiveURL: archivePath, BinaryInArchive: "kept.exe"},
				"broken": {Name: "broken", Version: "1", ArchiveURL: server.URL + "/broken.zip", BinaryInArchive: "broken.exe"},
			}},
		},
	}
	body, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, "runtime-manifest.json")
	if err := os.WriteFile(manifestPath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := SyncRuntime(SyncOptions{ManifestPath: manifestPath, CacheDir: filepath.Join(dir, "cache"), Platform: "windows-x64"})
	if err == nil || !strings.Contains(err.Error(), "1 outil(s) installé(s), 1 échec") || !strings.Contains(err.Error(), "broken") || !strings.Contains(err.Error(), "404") {
		t.Fatalf("err = %v", err)
	}
	if ClassifySyncError(err) == "network" {
		t.Fatal("HTTP 404 was classified as network")
	}
	installed := result.SyncedTools["kept"]
	got, readErr := os.ReadFile(installed)
	if readErr != nil || string(got) != string(payload) {
		t.Fatalf("kept tool was discarded: %q %v", got, readErr)
	}
}

func TestClassifySyncErrorSeparatesHTTPFromDNS(t *testing.T) {
	if ClassifySyncError(fmtError("dial tcp 10.0.0.1:443: i/o timeout")) != "network" {
		t.Fatal("tcp timeout")
	}
	if ClassifySyncError(fmtError("lookup files.pythonhosted.org: no such host")) != "network" {
		t.Fatal("dns")
	}
	httpErr := fmtError("téléchargement de l'outil bandit: code HTTP 404")
	if ClassifySyncError(httpErr) == "network" || ClassifySyncError(httpErr) != "http" {
		t.Fatalf("class = %s", ClassifySyncError(httpErr))
	}
}

func fmtError(message string) error { return &plainError{message} }

type plainError struct{ message string }

func (e *plainError) Error() string { return e.message }

func sha(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
