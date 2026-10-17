//go:build !windows

package osutil

func exportSystemRoots() (string, error) {
	return "", nil
}
