package osutil

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// ToolSearchDirs lists extra directories consulted before PATH.
// goos is explicit so the Darwin list can be tested on any host.
// Windows and Linux return an empty list: their tools stay on PATH,
// .tools/bin, and the distribution cache.
func ToolSearchDirs(goos, home string) []string {
	if goos != "darwin" {
		return nil
	}
	dirs := []string{
		"/opt/homebrew/bin",
		"/opt/homebrew/sbin",
		"/usr/local/bin",
		"/usr/local/sbin",
	}
	if home != "" {
		dirs = append(dirs,
			filepath.Join(home, ".local", "bin"),
			filepath.Join(home, ".pyenv", "shims"),
		)
		pyRoot := filepath.Join(home, "Library", "Python")
		entries, err := os.ReadDir(pyRoot)
		if err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					dirs = append(dirs, filepath.Join(pyRoot, entry.Name(), "bin"))
				}
			}
		}
	}
	return dirs
}

// PowerShellModuleDirs lists PSScriptAnalyzer roots outside Windows.
func PowerShellModuleDirs(goos, home string) []string {
	if goos == "windows" || home == "" && goos != "darwin" && goos != "linux" {
		return nil
	}
	var dirs []string
	if home != "" {
		dirs = append(dirs, filepath.Join(home, ".local", "share", "powershell", "Modules"))
	}
	dirs = append(dirs, "/usr/local/share/powershell/Modules")
	if goos == "darwin" {
		dirs = append(dirs, "/opt/homebrew/share/powershell/Modules")
	}
	return dirs
}

// ScriptCommand launches a Windows console script with the Python interpreter
// that sits beside it. A .cmd launcher from pip searches PATH and can bind the
// Microsoft Store stub instead of the venv that actually contains the package.
func ScriptCommand(exePath string, args []string) (string, []string) {
	ext := strings.ToLower(filepath.Ext(exePath))
	if runtime.GOOS == "windows" && (ext == ".cmd" || ext == ".bat") {
		python := filepath.Join(filepath.Dir(exePath), "python.exe")
		if info, err := os.Stat(python); err == nil && !info.IsDir() {
			return python, append([]string{"-x", exePath}, args...)
		}
	}
	return exePath, args
}

// DefaultToolCacheDir is the distribution cache written by compliance runtime sync.
func DefaultToolCacheDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".compliance", "tools")
	}
	return filepath.Join(home, ".compliance", "tools")
}

// LookupExecutable searches Darwin tool directories, then PATH.
func LookupExecutable(name string) string {
	home, _ := os.UserHomeDir()
	for _, dir := range ToolSearchDirs(runtime.GOOS, home) {
		candidate := filepath.Join(dir, name)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	if found, err := exec.LookPath(name); err == nil {
		return found
	}
	return ""
}

// AugmentedEnviron returns the process environment with Darwin tool
// directories prepended to PATH. On Windows and Linux the environment
// is unchanged.
func AugmentedEnviron() []string {
	env := os.Environ()
	home, _ := os.UserHomeDir()
	extra := existingDirectories(ToolSearchDirs(runtime.GOOS, home))
	if len(extra) == 0 {
		return env
	}

	updated := false
	for i, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || !strings.EqualFold(key, "PATH") {
			continue
		}
		parts := append(extra, filepath.SplitList(value)...)
		env[i] = key + "=" + strings.Join(dedupePaths(parts), string(os.PathListSeparator))
		updated = true
		break
	}
	if !updated {
		env = append(env, "PATH="+strings.Join(extra, string(os.PathListSeparator)))
	}
	return env
}

func existingDirectories(dirs []string) []string {
	var out []string
	seen := make(map[string]struct{}, len(dirs))
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		if _, ok := seen[dir]; ok {
			continue
		}
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		seen[dir] = struct{}{}
		out = append(out, dir)
	}
	return out
}

func dedupePaths(parts []string) []string {
	var out []string
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		key := part
		if runtime.GOOS == "windows" {
			key = strings.ToLower(part)
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, part)
	}
	return out
}
