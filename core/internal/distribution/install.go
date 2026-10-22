package distribution

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"compliance/internal/osutil"

	"github.com/ulikunitz/xz"
)

func (tool ToolEntry) kind() string {
	inst := strings.ToLower(strings.TrimSpace(tool.Install))
	switch inst {
	case "bundle":
		return "bundle"
	case "archive", "binary":
		return "binary"
	case "pip", "runtime":
		return inst
	}
	if tool.Bundle != "" {
		return "bundle"
	}
	if strings.Contains(strings.ToLower(tool.ArchiveURL), "py3-none-any") {
		return "pip"
	}
	return "binary"
}

func aliasMatch(key, requested string) bool {
	for _, name := range manifestAliases(requested) {
		if name == key {
			return true
		}
	}
	return false
}

func lookupTool(tools map[string]ToolEntry, name string) (ToolEntry, string, bool) {
	for _, alias := range manifestAliases(name) {
		if entry, ok := tools[alias]; ok {
			return entry, alias, true
		}
	}
	return ToolEntry{}, name, false
}

func installEntry(cacheDir, platform, key string, tool ToolEntry, tools map[string]ToolEntry, client *http.Client, opts SyncOptions, registryBase string) (string, error) {
	switch tool.kind() {
	case "pip":
		return "", errors.New("manifeste de schéma 2 obsolète : les installations pip à la volée ont été retirées au profit des bundles relocalisables (schéma 3). Veuillez utiliser le manifeste version 2.0.15+")
	case "bundle", "runtime":
		return installBundle(cacheDir, platform, key, tool, client, opts, registryBase)
	default:
		return installBinary(cacheDir, platform, key, tool, client, opts, registryBase)
	}
}

func installBundle(cacheDir, platform, key string, tool ToolEntry, client *http.Client, opts SyncOptions, registryBase string) (string, error) {
	if needsQualification(key, tool) {
		if existing := resolvedBundlePath(cacheDir, platform, key, tool); existing != "" {
			if err := qualifyExtracted(key, tool, existing); err == nil {
				return existing, nil
			}
		}
	}
	archiveURL := tool.resolveURL(registryBase)
	body, err := loadArchive(key, archiveURL, client, opts)
	if err != nil {
		return "", err
	}
	actualSHA := fmt.Sprintf("%x", sha256.Sum256(body))
	if tool.ArchiveSHA256 != "" && !strings.EqualFold(actualSHA, tool.ArchiveSHA256) {
		return "", fmt.Errorf("%w pour %s (obtenu: %s, attendu: %s)", ErrArchiveHashMismatch, key, actualSHA, tool.ArchiveSHA256)
	}
	if err := installTree(body, archiveURL, cacheDir, tool.BinaryInArchive); err != nil {
		return "", fmt.Errorf("extraction du bundle pour %s: %w", key, err)
	}
	dest := resolvedBundlePath(cacheDir, platform, key, tool)
	if dest != "" && runtime.GOOS != "windows" && !strings.HasSuffix(dest, ".psd1") {
		_ = os.Chmod(dest, 0755)
	}
	if err := qualifyExtracted(key, tool, dest); err != nil {
		return "", err
	}
	return dest, nil
}

func installBinary(cacheDir, platform, key string, tool ToolEntry, client *http.Client, opts SyncOptions, registryBase string) (string, error) {
	binDir := filepath.Join(cacheDir, "bin", platform)
	dest := filepath.Join(binDir, executableFileName(key, tool))
	if needsQualification(key, tool) && executablePresent(dest) {
		if err := qualifyExtracted(key, tool, dest); err == nil {
			return dest, nil
		}
	}
	archiveURL := tool.resolveURL(registryBase)
	body, err := loadArchive(key, archiveURL, client, opts)
	if err != nil {
		return "", err
	}
	actualSHA := fmt.Sprintf("%x", sha256.Sum256(body))
	if tool.ArchiveSHA256 != "" && !strings.EqualFold(actualSHA, tool.ArchiveSHA256) {
		return "", fmt.Errorf("%w pour %s (obtenu: %s, attendu: %s)", ErrArchiveHashMismatch, key, actualSHA, tool.ArchiveSHA256)
	}
	binBytes, err := extractBinary(body, tool.BinaryInArchive, archiveURL)
	if err != nil {
		return "", fmt.Errorf("extraction du binaire pour %s: %w", key, err)
	}
	if tool.BinarySHA256 != "" {
		actualBinSHA := fmt.Sprintf("%x", sha256.Sum256(binBytes))
		if !strings.EqualFold(actualBinSHA, tool.BinarySHA256) {
			return "", fmt.Errorf("%w pour %s (obtenu: %s, attendu: %s)", ErrBinaryHashMismatch, key, actualBinSHA, tool.BinarySHA256)
		}
	}
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return "", err
	}
	tempPath := fmt.Sprintf("%s.tmp.%d", dest, time.Now().UnixNano())
	if err := os.WriteFile(tempPath, binBytes, 0755); err != nil {
		return "", fmt.Errorf("écriture temporaire de l'exécutable %s: %w", tempPath, err)
	}
	if needsQualification(key, tool) {
		if err := qualifyExtracted(key, tool, tempPath); err != nil {
			_ = os.Remove(tempPath)
			return "", err
		}
	}
	if err := os.Rename(tempPath, dest); err != nil {
		_ = os.Remove(tempPath)
		return "", fmt.Errorf("renommage atomique vers %s: %w", dest, err)
	}
	if err := os.Chmod(dest, 0755); err != nil && runtime.GOOS != "windows" {
		return "", fmt.Errorf("permission d'exécution sur %s: %w", dest, err)
	}
	return dest, nil
}

func needsQualification(key string, tool ToolEntry) bool {
	return key == "checkov" || tool.PythonModule == "checkov.main" || key == "trivy" || strings.EqualFold(tool.Name, "trivy")
}

func qualifyExtracted(key string, tool ToolEntry, dest string) error {
	if !needsQualification(key, tool) {
		return nil
	}
	if dest == "" {
		return fmt.Errorf("outil %s extrait sans exécutable à qualifier", key)
	}
	ctx, cancel := context.WithTimeout(context.Background(), osutil.ProbeTimeoutFor(key))
	defer cancel()
	var err error
	switch {
	case key == "checkov" || tool.PythonModule == "checkov.main":
		err = osutil.QualifyCheckov(ctx, dest)
	default:
		err = osutil.QualifyTrivy(ctx, dest)
	}
	if err != nil {
		return fmt.Errorf("qualification de %s après installation: %w", key, err)
	}
	return nil
}

func materialize(path string) string {
	if runtime.GOOS != "windows" || path == "" || strings.HasPrefix(path, `\\?\`) || strings.HasPrefix(path, `\\`) {
		return path
	}
	abs, err := filepath.Abs(path)
	if err != nil || len(abs) < 248 {
		return path
	}
	return `\\?\` + abs
}

func mkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(materialize(path), perm)
}

func resolvedBundlePath(cacheDir, platform, key string, tool ToolEntry) string {
	if tool.BinaryInArchive != "" {
		candidate := filepath.Join(cacheDir, filepath.FromSlash(tool.BinaryInArchive))
		if executablePresent(candidate) || (strings.HasSuffix(candidate, ".psd1") && fileExists(candidate)) {
			return candidate
		}
	}
	bundle := tool.Bundle
	if bundle == "" {
		bundle = key
	}
	switch bundle {
	case "python":
		return findPython(filepath.Join(cacheDir, "python"))
	case "node":
		if key == "eslint" || key == "tsc" {
			ext := ""
			if runtime.GOOS == "windows" {
				ext = ".cmd"
			}
			return filepath.Join(cacheDir, "node", "node_modules", ".bin", key+ext)
		}
		if runtime.GOOS == "windows" {
			return filepath.Join(cacheDir, "node", "node.exe")
		}
		return filepath.Join(cacheDir, "node", "bin", "node")
	case "powershell-modules", "PSScriptAnalyzer", "Invoke-ScriptAnalyzer":
		manifest := filepath.Join(cacheDir, "powershell-modules", "PSScriptAnalyzer", "PSScriptAnalyzer.psd1")
		if fileExists(manifest) {
			return manifest
		}
		entries, _ := os.ReadDir(filepath.Join(cacheDir, "powershell-modules", "PSScriptAnalyzer"))
		for _, e := range entries {
			if e.IsDir() {
				sub := filepath.Join(cacheDir, "powershell-modules", "PSScriptAnalyzer", e.Name(), "PSScriptAnalyzer.psd1")
				if fileExists(sub) {
					return sub
				}
			}
		}
		return manifest
	}
	return ""
}

func executableFileName(key string, tool ToolEntry) string {
	name := tool.Name
	if name == "" {
		name = key
	}
	if key == "opentofu" || name == "opentofu" {
		name = "tofu"
	}
	if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(name), ".exe") {
		name += ".exe"
	}
	return name
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func findNode(root string) string {
	if runtime.GOOS == "windows" {
		winExe := filepath.Join(root, "node.exe")
		if executablePresent(winExe) {
			return winExe
		}
	} else {
		posixExe := filepath.Join(root, "bin", "node")
		if executablePresent(posixExe) {
			return posixExe
		}
	}
	var found string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		base := strings.ToLower(d.Name())
		if base == "node.exe" || base == "node" {
			found = path
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

func pythonBinaryName(base string) bool {
	name := strings.TrimSuffix(base, ".exe")
	rest, ok := strings.CutPrefix(name, "python3.")
	if !ok || rest == "" {
		return false
	}
	for _, r := range rest {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func findPython(root string) string {
	var found string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		slash := filepath.ToSlash(path)
		if strings.Contains(slash, "/venv/") || strings.Contains(slash, "/Scripts/") {
			return nil
		}
		base := strings.ToLower(d.Name())
		if base == "python.exe" || base == "python3" || base == "python" || pythonBinaryName(base) {
			found = path
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

func loadArchive(key, archiveURL string, client *http.Client, opts SyncOptions) ([]byte, error) {
	if archiveURL == "" {
		return nil, fmt.Errorf("URL d'archive manquante pour l'outil %s", key)
	}
	archiveFileName := filepath.Base(strings.Split(archiveURL, "?")[0])
	if opts.ArchiveCacheDir != "" {
		for _, candidate := range []string{
			filepath.Join(opts.ArchiveCacheDir, archiveFileName),
			filepath.Join(opts.ArchiveCacheDir, "wheels", archiveFileName),
		} {
			if body, err := os.ReadFile(candidate); err == nil && len(body) > 0 {
				return body, nil
			}
		}
	}
	if opts.OfflineOnly {
		return nil, fmt.Errorf("%w pour %s: mode hors-ligne actif et archive introuvable localement", ErrToolNotFound, key)
	}
	if err := requireHTTPSArchive(archiveURL); err != nil {
		return nil, fmt.Errorf("téléchargement de l'outil %s: %w", key, err)
	}
	body, err := fetchBytes(archiveURL, client, opts.RegistryToken)
	if err != nil {
		return nil, fmt.Errorf("téléchargement de l'outil %s: %w", key, err)
	}
	if opts.ArchiveCacheDir != "" {
		_ = os.MkdirAll(opts.ArchiveCacheDir, 0755)
		_ = os.WriteFile(filepath.Join(opts.ArchiveCacheDir, archiveFileName), body, 0644)
	}
	return body, nil
}

func extractTree(body []byte, sourceURL, dest string) error {
	lower := strings.ToLower(strings.Split(sourceURL, "?")[0])
	switch {
	case strings.HasSuffix(lower, ".zip") || strings.HasSuffix(lower, ".whl"):
		zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
		if err != nil {
			return fmt.Errorf("archive zip illisible: %w", err)
		}
		for _, file := range zr.File {
			target, err := safeJoin(dest, file.Name)
			if err != nil {
				return err
			}
			if file.FileInfo().IsDir() {
				if err := mkdirAll(target, 0755); err != nil {
					return err
				}
				continue
			}
			if err := mkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			rc, err := file.Open()
			if err != nil {
				return err
			}
			mode := file.Mode()
			if mode&0111 != 0 {
				mode = 0755
			} else {
				mode = 0644
			}
			if err := writeFile(target, rc, mode); err != nil {
				rc.Close()
				return err
			}
			rc.Close()
		}
		return nil
	case strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz"):
		gzr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("archive tar.gz illisible: %w", err)
		}
		defer gzr.Close()
		return extractTarTree(tar.NewReader(gzr), dest)
	case strings.HasSuffix(lower, ".tar.xz") || strings.HasSuffix(lower, ".txz"):
		xr, err := xz.NewReader(bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("archive tar.xz illisible: %w", err)
		}
		return extractTarTree(tar.NewReader(xr), dest)
	default:
		return fmt.Errorf("format d'archive non reconnu pour le runtime: %s", sourceURL)
	}
}

func extractTarTree(tr *tar.Reader, dest string) error {
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		target, err := safeJoin(dest, hdr.Name)
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := mkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := mkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			mode := os.FileMode(0644)
			if hdr.FileInfo().Mode()&0111 != 0 {
				mode = 0755
			}
			if err := writeFile(target, tr, mode); err != nil {
				return err
			}
		case tar.TypeSymlink, tar.TypeLink:
			rawLink := strings.TrimSpace(hdr.Linkname)
			if filepath.IsAbs(rawLink) || strings.HasPrefix(rawLink, "/") || strings.HasPrefix(rawLink, "\\") || filepath.VolumeName(rawLink) != "" {
				return fmt.Errorf("lien symbolique absolu interdit dans l'archive: %s -> %s", hdr.Name, hdr.Linkname)
			}
			linkTarget := filepath.Clean(strings.ReplaceAll(rawLink, "\\", "/"))
			if filepath.IsAbs(linkTarget) || strings.HasPrefix(linkTarget, "/") || strings.HasPrefix(linkTarget, "\\") || filepath.VolumeName(linkTarget) != "" {
				return fmt.Errorf("lien symbolique absolu interdit dans l'archive: %s -> %s", hdr.Name, hdr.Linkname)
			}
			resolvedTarget := filepath.Clean(filepath.Join(filepath.Dir(target), filepath.FromSlash(linkTarget)))
			rel, err := filepath.Rel(dest, resolvedTarget)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
				return fmt.Errorf("lien symbolique sortant du répertoire de destination interdit: %s -> %s", hdr.Name, hdr.Linkname)
			}
			if err := mkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			_ = os.Remove(target)
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				// Repli sécurisé pour les environnements sans privilèges de lien symbolique (ex: Windows non-dev) :
				// uniquement si la source résolue existe DÉJÀ à l'intérieur de la destination vérifiée.
				sourceInfo, statErr := os.Stat(resolvedTarget)
				if statErr == nil && !sourceInfo.IsDir() {
					data, readErr := os.ReadFile(resolvedTarget)
					if readErr == nil {
						if err := os.WriteFile(target, data, 0755); err != nil {
							return err
						}
					}
				}
			}
		}
	}
}

func writeFile(path string, r io.Reader, mode os.FileMode) error {
	file, err := os.OpenFile(materialize(path), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := io.Copy(file, r); err != nil {
		return err
	}
	return os.Chmod(materialize(path), mode)
}

func safeJoin(dest, name string) (string, error) {
	clean := filepath.Clean(strings.ReplaceAll(name, "\\", "/"))
	if clean == "." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "..\\") || clean == ".." || filepath.IsAbs(clean) || strings.HasPrefix(clean, "/") || strings.HasPrefix(clean, "\\") {
		return "", fmt.Errorf("chemin d'archive refusé: %s", name)
	}
	target := filepath.Join(dest, filepath.FromSlash(clean))
	rel, err := filepath.Rel(dest, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("chemin d'archive refusé: %s", name)
	}
	return target, nil
}
