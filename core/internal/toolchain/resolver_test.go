package toolchain

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestToolResolverLocalBin(t *testing.T) {
	manifestPath := filepath.Join("..", "..", "..", ".config", "runtime-manifest.json")
	sigPath := filepath.Join("..", "..", "..", ".config", "runtime-manifest.json.sig")
	localBinDir := filepath.Join("..", "..", "..", ".tools", "bin")

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

	// Test resolving gitleaks from existing local bin
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

	// Verify executing resolved tool
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

func TestToolResolverOnDemandExtraction(t *testing.T) {
	manifestPath := filepath.Join("..", "..", "..", ".config", "runtime-manifest.json")
	sigPath := filepath.Join("..", "..", "..", ".config", "runtime-manifest.json.sig")
	archiveCacheDir := filepath.Join("..", "..", "..", ".tools", "cache")

	tempCache := t.TempDir()

	// Empty LocalBinDir so it MUST sync/extract on demand from archive cache
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

	// Test resolving tflint on demand
	res, err := resolver.ResolveTool(ctx, "tflint")
	if err != nil {
		t.Fatalf("ResolveTool('tflint') on-demand failed: %v", err)
	}

	if res.Source != "synced" {
		t.Errorf("Expected source 'synced', got %s", res.Source)
	}

	cmd := exec.Command(res.ExecutablePath, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Execution of extracted tflint failed: %v", err)
	}
	if !strings.Contains(string(out), "0.64.0") {
		t.Errorf("Unexpected output from tflint: %s", string(out))
	}
	t.Logf("SUCCESS: tflint extracted on demand and executed: %s", strings.TrimSpace(string(out)))

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

	fakeBinDir := t.TempDir()
	// Place a corrupted fake gitleaks.exe in LocalBinDir
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

	// Resolution should reject corrupted local binary and recover by extracting from authentic archive!
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
