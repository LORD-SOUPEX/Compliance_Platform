package distribution

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"compliance/internal/osutil"
)

// ToolsLockWait bounds the wait for the tools folder: an installation waits for
// running audits, an audit waits for an installation in progress.
var ToolsLockWait = 15 * time.Minute

const (
	toolsLockName       = ".install.lock"
	toolsGenerationName = ".generation"
)

// LockTools takes the cross-process lock of the tools folder. Audits and plans
// take it shared; installations and upgrades take it exclusive. The same lock
// serialises the daemon, `compliance runtime sync` and several VS Code windows.
func LockTools(ctx context.Context, cacheDir string, exclusive bool, purpose string) (func(), error) {
	if cacheDir == "" {
		cacheDir = osutil.DefaultToolCacheDir()
	}
	ctx, cancel := context.WithTimeout(ctx, ToolsLockWait)
	defer cancel()
	started := time.Now()
	unlock, err := osutil.LockFile(ctx, filepath.Join(cacheDir, toolsLockName), exclusive, func() {
		slog.Info("tools_lock_wait", "purpose", purpose, "exclusive", exclusive, "dir", cacheDir)
	})
	if err != nil {
		return nil, fmt.Errorf("dossier des outils occupé (%s) : %w", purpose, err)
	}
	if waited := time.Since(started); waited > time.Second {
		slog.Info("tools_lock_acquired", "purpose", purpose, "exclusive", exclusive, "waited_ms", waited.Milliseconds())
	}
	return unlock, nil
}

// ToolsGeneration changes after every installation. Probe caches compare it to
// forget results that predate a new tool, across processes.
func ToolsGeneration(cacheDir string) string {
	if cacheDir == "" {
		cacheDir = osutil.DefaultToolCacheDir()
	}
	body, err := os.ReadFile(filepath.Join(cacheDir, toolsGenerationName))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
}

func bumpToolsGeneration(cacheDir string) {
	path := filepath.Join(cacheDir, toolsGenerationName)
	_ = os.WriteFile(path, []byte(strconv.FormatInt(time.Now().UnixNano(), 10)), 0o644)
}

// cleanupInterrupted removes staging and trash folders left by an installation
// that crashed, or by a Windows rename that could not delete an old tree.
func cleanupInterrupted(cacheDir string) {
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".staging-") || strings.HasPrefix(name, ".trash-") {
			_ = os.RemoveAll(materialize(filepath.Join(cacheDir, name)))
		}
	}
}

// bundleRoot is the folder a bundle owns, read from its binary path:
// "python/python.exe" owns "python"; shared containers such as
// "powershell-modules/PSScriptAnalyzer/..." own their second level only.
func bundleRoot(binaryInArchive string) string {
	parts := strings.Split(filepath.ToSlash(binaryInArchive), "/")
	if len(parts) < 2 || parts[0] == "" || parts[0] == "." || parts[0] == ".." {
		return ""
	}
	if parts[0] == "powershell-modules" || parts[0] == "bin" {
		if len(parts) < 3 {
			return ""
		}
		return parts[0] + "/" + parts[1]
	}
	return parts[0]
}

// installTree extracts an archive beside the tools, then swaps the bundle folder
// in with two renames. A probe or a control never sees a half-extracted bundle,
// and a failed swap puts the previous tree back.
func installTree(body []byte, sourceURL, cacheDir, binaryInArchive string) error {
	if err := mkdirAll(cacheDir, 0o755); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(cacheDir, ".staging-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(materialize(staging))
	if err := extractTree(body, sourceURL, staging); err != nil {
		return err
	}
	if root := bundleRoot(binaryInArchive); root != "" {
		fresh := filepath.Join(staging, filepath.FromSlash(root))
		if _, err := os.Stat(fresh); err == nil {
			if err := swapDir(fresh, filepath.Join(cacheDir, filepath.FromSlash(root)), cacheDir); err != nil {
				return err
			}
		}
	}
	return mergeTree(staging, cacheDir)
}

func swapDir(fresh, target, cacheDir string) error {
	if err := mkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	old := ""
	if _, err := os.Lstat(target); err == nil {
		old = filepath.Join(cacheDir, fmt.Sprintf(".trash-%d-%s", time.Now().UnixNano(), filepath.Base(target)))
		if err := os.Rename(materialize(target), materialize(old)); err != nil {
			return fmt.Errorf("remplacement de %s impossible, un fichier est peut-être en cours d'utilisation : %w", target, err)
		}
	}
	if err := os.Rename(materialize(fresh), materialize(target)); err != nil {
		if old != "" {
			_ = os.Rename(materialize(old), materialize(target))
		}
		return fmt.Errorf("installation de %s impossible : %w", target, err)
	}
	if old != "" {
		if err := os.RemoveAll(materialize(old)); err != nil {
			slog.Warn("tool_trash_kept", "path", old, "err", err)
		}
	}
	return nil
}

// mergeTree moves the remaining staged files into place, replacing files and
// merging folders. os.Rename replaces an existing file on every OS.
func mergeTree(src, dst string) error {
	entries, err := os.ReadDir(materialize(src))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		from := filepath.Join(src, entry.Name())
		to := filepath.Join(dst, entry.Name())
		if entry.IsDir() {
			if info, err := os.Lstat(to); err == nil && !info.IsDir() {
				_ = os.Remove(materialize(to))
			}
			if err := mkdirAll(to, 0o755); err != nil {
				return err
			}
			if err := mergeTree(from, to); err != nil {
				return err
			}
			continue
		}
		if err := os.Rename(materialize(from), materialize(to)); err != nil {
			return fmt.Errorf("installation de %s : %w", to, err)
		}
	}
	return nil
}
