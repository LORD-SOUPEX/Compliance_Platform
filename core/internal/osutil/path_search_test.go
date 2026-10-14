package osutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestToolSearchDirsDarwinIncludesHomebrewAndUserBins(t *testing.T) {
	home := t.TempDir()
	pyBin := filepath.Join(home, "Library", "Python", "3.12", "bin")
	if err := os.MkdirAll(pyBin, 0o755); err != nil {
		t.Fatal(err)
	}

	dirs := ToolSearchDirs("darwin", home)
	for _, want := range []string{
		"/opt/homebrew/bin",
		"/opt/homebrew/sbin",
		"/usr/local/bin",
		"/usr/local/sbin",
		filepath.Join(home, ".local", "bin"),
		filepath.Join(home, ".pyenv", "shims"),
		pyBin,
	} {
		if !containsPath(dirs, want) {
			t.Fatalf("ToolSearchDirs(darwin) missing %s in %v", want, dirs)
		}
	}

	if got := ToolSearchDirs("windows", home); len(got) != 0 {
		t.Fatalf("ToolSearchDirs(windows) = %v, want empty", got)
	}
	if got := ToolSearchDirs("linux", home); len(got) != 0 {
		t.Fatalf("ToolSearchDirs(linux) = %v, want empty", got)
	}
}

func TestPowerShellModuleDirs(t *testing.T) {
	home := filepath.Join(string(filepath.Separator), "Users", "dev")
	dirs := PowerShellModuleDirs("darwin", home)
	if !containsPath(dirs, filepath.Join(home, ".local", "share", "powershell", "Modules")) {
		t.Fatalf("missing user module dir: %v", dirs)
	}
	if !containsPath(dirs, "/opt/homebrew/share/powershell/Modules") {
		t.Fatalf("missing Homebrew module dir: %v", dirs)
	}
	if got := PowerShellModuleDirs("windows", home); len(got) != 0 {
		t.Fatalf("windows module dirs = %v, want empty", got)
	}
}

func containsPath(dirs []string, want string) bool {
	for _, dir := range dirs {
		if dir == want {
			return true
		}
	}
	return false
}
