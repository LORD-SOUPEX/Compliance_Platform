package toolchain

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"compliance/internal/distribution"
)

func TestToolResolverLocalBin(t *testing.T) {
	manifestPath := filepath.Join("..", "..", "..", ".config", "runtime-manifest.json")
	sigPath := filepath.Join("..", "..", "..", ".config", "runtime-manifest.json.sig")
	localBinDir := filepath.Join("..", "..", "..", ".tools", "bin")

	targetExe := filepath.Join(localBinDir, "gitleaks.exe")
	if _, err := os.Stat(targetExe); err != nil {
		t.Skip("Binaire gitleaks.exe absent dans .tools/bin: test local bin sauté en environnement minimal")
	}

	resolver, err := NewResolver(ResolverOptions{
		ManifestPath: manifestPath,
		SigPath:      sigPath,
		CacheDir:     t.TempDir(),
		LocalBinDir:  localBinDir,
		Platform:     "windows-x64",
	})
	if err != nil {
		t.Fatalf("NewResolver failed: %v", err)
	}

	ctx := context.Background()

	res, err := resolver.ResolveTool(ctx, "gitleaks")
	if err != nil {
		t.Fatalf("ResolveTool('gitleaks') failed: %v", err)
	}

	if res.Name != "gitleaks" {
		t.Errorf("Expected name 'gitleaks', got %s", res.Name)
	}
	if res.Version != "8.30.1" {
		t.Errorf("Expected version '8.30.1', got %s", res.Version)
	}
	if res.Source != "local_bin" {
		t.Errorf("Expected source 'local_bin', got %s", res.Source)
	}

	if runtime.GOOS == "windows" {
		cmd := exec.Command(res.ExecutablePath, "version")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Execution of resolved gitleaks failed: %v", err)
		}
		if !strings.Contains(string(out), "8.30.1") {
			t.Errorf("Unexpected output: %s", string(out))
		}
		t.Logf("SUCCESS: gitleaks resolved and verified: %s", strings.TrimSpace(string(out)))
	}
}

func TestToolResolverOnDemandExtraction(t *testing.T) {
	manifestPath := filepath.Join("..", "..", "..", ".config", "runtime-manifest.json")
	sigPath := filepath.Join("..", "..", "..", ".config", "runtime-manifest.json.sig")
	archiveCacheDir := filepath.Join("..", "..", "..", ".tools", "cache")

	tflintArc := filepath.Join(archiveCacheDir, "tflint_windows_amd64.zip")
	if _, err := os.Stat(tflintArc); err != nil {
		t.Skip("Archive tflint absente dans .tools/cache: test extraction sauté en environnement minimal")
	}

	tempCache := t.TempDir()

	resolver, err := NewResolver(ResolverOptions{
		ManifestPath:    manifestPath,
		SigPath:         sigPath,
		CacheDir:        tempCache,
		ArchiveCacheDir: archiveCacheDir,
		Platform:        "windows-x64",
	})
	if err != nil {
		t.Fatalf("NewResolver failed: %v", err)
	}

	ctx := context.Background()

	res, err := resolver.ResolveTool(ctx, "tflint")
	if err != nil {
		t.Fatalf("ResolveTool('tflint') on-demand failed: %v", err)
	}

	if res.Source != "synced" {
		t.Errorf("Expected source 'synced', got %s", res.Source)
	}

	if runtime.GOOS == "windows" {
		cmd := exec.Command(res.ExecutablePath, "--version")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Execution of extracted tflint failed: %v", err)
		}
		if !strings.Contains(string(out), "0.64.0") {
			t.Errorf("Unexpected output from tflint: %s", string(out))
		}
		t.Logf("SUCCESS: tflint extracted on demand and executed: %s", strings.TrimSpace(string(out)))
	}

	// Second resolution should be instant from "cache"
	res2, err := resolver.ResolveTool(ctx, "tflint")
	if err != nil {
		t.Fatalf("Second ResolveTool('tflint') failed: %v", err)
	}
	if res2.Source != "cache" {
		t.Errorf("Expected second resolution to be 'cache', got %s", res2.Source)
	}
}

func TestToolResolverTamperedBinaryRejection(t *testing.T) {
	manifestPath := filepath.Join("..", "..", "..", ".config", "runtime-manifest.json")
	sigPath := filepath.Join("..", "..", "..", ".config", "runtime-manifest.json.sig")
	archiveCacheDir := filepath.Join("..", "..", "..", ".tools", "cache")

	gitleaksArc := filepath.Join(archiveCacheDir, "gitleaks_8.30.1_windows_x64.zip")
	if _, err := os.Stat(gitleaksArc); err != nil {
		t.Skip("Archive gitleaks absente dans .tools/cache: test falsification sauté en environnement minimal")
	}

	fakeBinDir := t.TempDir()
	corruptExe := filepath.Join(fakeBinDir, "gitleaks.exe")
	os.WriteFile(corruptExe, []byte("NOT A VALID GITLEAKS BINARY"), 0755)

	tempCache := t.TempDir()

	resolver, err := NewResolver(ResolverOptions{
		ManifestPath:    manifestPath,
		SigPath:         sigPath,
		CacheDir:        tempCache,
		LocalBinDir:     fakeBinDir,
		ArchiveCacheDir: archiveCacheDir,
		Platform:        "windows-x64",
	})
	if err != nil {
		t.Fatalf("NewResolver failed: %v", err)
	}

	ctx := context.Background()

	res, err := resolver.ResolveTool(ctx, "gitleaks")
	if err != nil {
		t.Fatalf("ResolveTool failed: %v", err)
	}

	if res.Source == "local_bin" {
		t.Errorf("Tampered binary should NOT have been accepted as local_bin!")
	}
	if res.Source != "synced" {
		t.Errorf("Expected fallback recovery to 'synced', got %s", res.Source)
	}
	t.Logf("SUCCESS: Corrupted local binary rejected and recovered via authentic extraction")
}

func TestToolResolverUnknownTool(t *testing.T) {
	manifestPath := filepath.Join("..", "..", "..", ".config", "runtime-manifest.json")
	sigPath := filepath.Join("..", "..", "..", ".config", "runtime-manifest.json.sig")

	resolver, err := NewResolver(ResolverOptions{
		ManifestPath: manifestPath,
		SigPath:      sigPath,
		CacheDir:     t.TempDir(),
		Platform:     "windows-x64",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = resolver.ResolveTool(context.Background(), "non_existent_tool")
	if err == nil {
		t.Errorf("Expected error for non_existent_tool")
	}
}

// TestToolResolverAutonomousMock proves the Tool Resolver works 100% autonomously in CI
// without any files in .tools/bin or .tools/cache.
func TestToolResolverAutonomousMock(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Create a mock executable in a zip archive
	mockBinContent := []byte("#!/bin/sh\necho mock 1.0\n")
	mockBinHash := sha256Hex(mockBinContent)

	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	f, err := zw.Create("mytool")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(mockBinContent); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	zipBytes := zipBuf.Bytes()
	zipHash := sha256Hex(zipBytes)

	// 2. Start mock HTTP server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		w.Write(zipBytes)
	}))
	defer ts.Close()

	// 3. Ephemeral keypair
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	plat := distribution.DetectPlatform()
	manifest := distribution.RuntimeManifest{
		SchemaVersion:   2,
		ManifestVersion: "2.0.0",
		Platforms: map[string]distribution.PlatformManifest{
			plat: {
				Status: "qualified",
				Tools: map[string]distribution.ToolEntry{
					"mytool": {
						Name:            "mytool",
						Version:         "1.0.0",
						ArchiveURL:      ts.URL + "/mytool.zip",
						ArchiveSHA256:   zipHash,
						BinaryInArchive: "mytool",
						BinarySHA256:    mockBinHash,
						VersionArgs:     []string{"version"},
					},
				},
			},
		},
	}

	manifestBytes, _ := json.MarshalIndent(manifest, "", "  ")
	sigHex := distribution.SignManifest(manifestBytes, privKey)

	manifestPath := filepath.Join(tempDir, "manifest.json")
	sigPath := filepath.Join(tempDir, "manifest.sig")
	cacheDir := filepath.Join(tempDir, "cache")

	os.WriteFile(manifestPath, manifestBytes, 0644)
	os.WriteFile(sigPath, []byte(sigHex), 0644)

	// 4. Test on-demand resolution via mock server
	resolver, err := NewResolver(ResolverOptions{
		ManifestPath: manifestPath,
		SigPath:      sigPath,
		CacheDir:     cacheDir,
		Platform:     plat,
		PublicKey:    pubKey,
	})
	if err != nil {
		t.Fatalf("NewResolver autonomous failed: %v", err)
	}

	res, err := resolver.ResolveTool(context.Background(), "mytool")
	if err != nil {
		t.Fatalf("ResolveTool autonomous failed: %v", err)
	}

	if res.Name != "mytool" || res.Version != "1.0.0" {
		t.Errorf("Unexpected resolved tool: %+v", res)
	}
	if res.Source != "synced" {
		t.Errorf("Expected source 'synced', got %s", res.Source)
	}

	t.Logf("SUCCESS: Tool Resolver autonomous test passed in %s with source %s", plat, res.Source)
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
