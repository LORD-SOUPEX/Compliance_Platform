package osutil

import (
	"fmt"
	"os"
	"path/filepath"
)

// CanonicalPath returns a cleaned absolute path with symlinks resolved.
// When the leaf does not exist yet, the longest existing ancestor is resolved
// and the missing suffix is reapplied. On macOS this maps /var/folders/... to
// /private/var/folders/... even before the final directory is created.
func CanonicalPath(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("chemin vide")
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)

	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return filepath.Clean(resolved), nil
	} else if !os.IsNotExist(err) {
		return "", err
	}

	current := abs
	var missing []string
	for {
		_, statErr := os.Lstat(current)
		if statErr == nil {
			resolved, evErr := filepath.EvalSymlinks(current)
			if evErr != nil {
				if !os.IsNotExist(evErr) {
					return "", evErr
				}
				resolved = current
			}
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return filepath.Clean(resolved), nil
		}
		if !os.IsNotExist(statErr) {
			return "", statErr
		}
		parent := filepath.Dir(current)
		if parent == current {
			return abs, nil
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}
