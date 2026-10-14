package embedded

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

//go:embed assets/*
var assets embed.FS

// Read returns an embedded configuration file by base name.
func Read(name string) ([]byte, error) {
	return assets.ReadFile("assets/" + name)
}

// Materialize writes every embedded asset into dir.
func Materialize(dir string) error {
	entries, err := fs.ReadDir(assets, "assets")
	if err != nil {
		return fmt.Errorf("lecture des fichiers embarqués: %w", err)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		body, err := assets.ReadFile("assets/" + entry.Name())
		if err != nil {
			return err
		}
		dest := filepath.Join(dir, entry.Name())
		if err := os.WriteFile(dest, body, 0600); err != nil {
			return err
		}
		if err := os.Chmod(dest, 0600); err != nil {
			return err
		}
	}
	return nil
}

// ResolveAsset returns the first existing candidate. HTTP(S) and file URLs are
// returned unchanged. When every disk candidate is missing, the embedded copy
// is materialized under the user cache so a binary can run outside the Git checkout.
func ResolveAsset(name string, candidates ...string) (string, error) {
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if strings.HasPrefix(candidate, "http://") || strings.HasPrefix(candidate, "https://") || strings.HasPrefix(candidate, "file://") {
			return candidate, nil
		}
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() {
			return candidate, nil
		}
	}

	home, err := os.UserCacheDir()
	if err != nil || home == "" {
		home = os.TempDir()
	}
	dir := filepath.Join(home, "compliance", "embedded-config")
	if err := Materialize(dir); err != nil {
		return "", err
	}
	dest := filepath.Join(dir, name)
	if _, err := os.Stat(dest); err != nil {
		return "", fmt.Errorf("fichier embarqué absent: %s", name)
	}
	return dest, nil
}
