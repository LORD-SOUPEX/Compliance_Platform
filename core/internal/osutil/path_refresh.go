package osutil

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

var pathMu sync.Mutex

// RefreshPath appends to the daemon PATH the folders it does not know yet:
// on Windows the PATH currently stored in the registry (an installer or setx
// changed it after VS Code started), on every OS the PATH sent by the client
// (VS Code resolves the login-shell PATH on macOS and Linux). Existing entries
// keep their priority. Only existing folders are added. It returns the additions.
func RefreshPath(clientPath string) []string {
	pathMu.Lock()
	defer pathMu.Unlock()
	current := filepath.SplitList(os.Getenv("PATH"))
	seen := make(map[string]bool, len(current))
	for _, entry := range current {
		seen[pathKey(entry)] = true
	}
	candidates := append(systemPathEntries(), filepath.SplitList(clientPath)...)
	var added []string
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(strings.Trim(candidate, `"`))
		if candidate == "" || seen[pathKey(candidate)] {
			continue
		}
		if info, err := os.Stat(candidate); err != nil || !info.IsDir() {
			continue
		}
		seen[pathKey(candidate)] = true
		added = append(added, candidate)
	}
	if len(added) > 0 {
		_ = os.Setenv("PATH", strings.Join(append(current, added...), string(os.PathListSeparator)))
	}
	return added
}

func pathKey(entry string) string {
	cleaned := filepath.Clean(strings.TrimSpace(entry))
	if runtime.GOOS == "windows" {
		return strings.ToLower(strings.TrimRight(cleaned, `\`))
	}
	return cleaned
}
