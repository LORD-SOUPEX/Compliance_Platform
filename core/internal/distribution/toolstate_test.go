package distribution

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func zipArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, body := range files {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestInstallTreeReplacesTheBundleWholeAndKeepsNeighbours(t *testing.T) {
	cache := t.TempDir()
	for name, body := range map[string]string{
		"python/old-module.py":                "stale",
		"bin/windows-x64/ruff":                "native",
		"powershell-modules/Other/Other.psd1": "other module",
	} {
		path := filepath.Join(cache, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	body := zipArchive(t, map[string]string{"python/python.exe": "new", "python/lib/new.py": "fresh"})
	if err := installTree(body, "https://example.invalid/python.zip", cache, "python/python.exe"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cache, "python", "old-module.py")); !os.IsNotExist(err) {
		t.Fatal("files of the previous bundle survived the swap")
	}
	for _, name := range []string{"python/python.exe", "python/lib/new.py", "bin/windows-x64/ruff", "powershell-modules/Other/Other.psd1"} {
		if _, err := os.Stat(filepath.Join(cache, filepath.FromSlash(name))); err != nil {
			t.Fatalf("%s missing: %v", name, err)
		}
	}

	module := zipArchive(t, map[string]string{"powershell-modules/PSScriptAnalyzer/PSScriptAnalyzer.psd1": "pssa"})
	if err := installTree(module, "https://example.invalid/pssa.zip", cache, "powershell-modules/PSScriptAnalyzer/PSScriptAnalyzer.psd1"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cache, "powershell-modules", "Other", "Other.psd1")); err != nil {
		t.Fatal("installing one PowerShell module removed another one")
	}
	entries, _ := os.ReadDir(cache)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".staging-") || strings.HasPrefix(entry.Name(), ".trash-") {
			t.Fatalf("leftover %s", entry.Name())
		}
	}
}

func TestBundleRoot(t *testing.T) {
	for binary, want := range map[string]string{
		"python/python.exe":                          "python",
		"python/bin/python3":                         "python",
		"node/node_modules/.bin/eslint.cmd":          "node",
		"powershell-modules/PSScriptAnalyzer/x.psd1": "powershell-modules/PSScriptAnalyzer",
		"ruff.exe":    "",
		"../escape/x": "",
	} {
		if got := bundleRoot(binary); got != want {
			t.Fatalf("bundleRoot(%q) = %q, want %q", binary, got, want)
		}
	}
}

func TestGenerationChangesAfterInstall(t *testing.T) {
	cache := t.TempDir()
	if ToolsGeneration(cache) != "" {
		t.Fatal("fresh cache has a generation")
	}
	bumpToolsGeneration(cache)
	first := ToolsGeneration(cache)
	bumpToolsGeneration(cache)
	if first == "" || ToolsGeneration(cache) == first {
		t.Fatalf("generation did not move: %q", first)
	}
}

func TestWindowsArm64BorrowsX64Tools(t *testing.T) {
	manifest := RuntimeManifest{Platforms: map[string]PlatformManifest{
		"windows-arm64": {Tools: map[string]ToolEntry{"rumdl": {Version: "arm"}}},
		"windows-x64":   {Tools: map[string]ToolEntry{"rumdl": {Version: "x64"}, "ruff": {Version: "x64"}}},
		"linux-x64":     {Tools: map[string]ToolEntry{"ruff": {Version: "linux"}}},
	}}
	tools, origin, ok := toolsForHost(manifest, "windows-arm64")
	if !ok || tools["rumdl"].Version != "arm" || origin["rumdl"] != "windows-arm64" || origin["ruff"] != "windows-x64" {
		t.Fatalf("arm64 tools = %v origin = %v", tools, origin)
	}
	if linux, _, _ := toolsForHost(manifest, "linux-arm64"); len(linux) != 0 {
		t.Fatalf("only Windows on ARM borrows x64 tools: %v", linux)
	}
}
