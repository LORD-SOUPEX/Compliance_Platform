package distribution

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ulikunitz/xz"
)

func (tool ToolEntry) kind() string {
	switch strings.ToLower(strings.TrimSpace(tool.Install)) {
	case "pip", "runtime":
		return strings.ToLower(tool.Install)
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

func installEntry(cacheDir, platform, key string, tool ToolEntry, tools map[string]ToolEntry, client *http.Client, opts SyncOptions) (string, error) {
	switch tool.kind() {
	case "pip":
		return installPip(cacheDir, key, tool, tools, client, opts)
	case "runtime":
		return installRuntime(cacheDir, tool, client, opts)
	default:
		return installBinary(cacheDir, platform, key, tool, client, opts)
	}
}

func installBinary(cacheDir, platform, key string, tool ToolEntry, client *http.Client, opts SyncOptions) (string, error) {
	body, err := loadArchive(key, tool, client, opts)
	if err != nil {
		return "", err
	}
	binBytes, err := extractBinary(body, tool.BinaryInArchive, tool.ArchiveURL)
	if err != nil {
		return "", fmt.Errorf("extraction du binaire pour %s: %w", key, err)
	}
	binDir := filepath.Join(cacheDir, "bin", platform)
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return "", err
	}
	dest := filepath.Join(binDir, executableFileName(key, tool))
	tempPath := fmt.Sprintf("%s.tmp.%d", dest, time.Now().UnixNano())
	if err := os.WriteFile(tempPath, binBytes, 0755); err != nil {
		return "", fmt.Errorf("écriture temporaire de l'exécutable %s: %w", tempPath, err)
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

func installRuntime(cacheDir string, tool ToolEntry, client *http.Client, opts SyncOptions) (string, error) {
	dest := filepath.Join(cacheDir, "python")
	if py := findPython(dest); py != "" && pythonWorks(py) {
		return py, nil
	}
	body, err := loadArchive("python", tool, client, opts)
	if err != nil {
		return "", err
	}
	if err := os.RemoveAll(dest); err != nil {
		return "", err
	}
	if err := os.MkdirAll(dest, 0755); err != nil {
		return "", err
	}
	if err := extractTree(body, tool.ArchiveURL, dest); err != nil {
		return "", fmt.Errorf("extraction du runtime Python: %w", err)
	}
	py := findPython(dest)
	if py == "" {
		return "", fmt.Errorf("interpréteur Python introuvable dans %s", dest)
	}
	_ = os.Chmod(py, 0755)
	return py, nil
}

func installPip(cacheDir, key string, tool ToolEntry, tools map[string]ToolEntry, client *http.Client, opts SyncOptions) (string, error) {
	python, err := ensurePython(cacheDir, tools, client, opts)
	if err != nil {
		return "", err
	}
	venvPython, err := ensureVenv(cacheDir, python)
	if err != nil {
		return "", err
	}
	pkg := tool.Package
	if pkg == "" {
		pkg = tool.Name
	}
	if pkg == "" {
		pkg = key
	}
	cmd := exec.Command(venvPython, "-m", "pip", "install", "--disable-pip-version-check", "--upgrade", pkg+"=="+tool.Version)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		text := strings.TrimSpace(string(out))
		if text == "" {
			text = err.Error()
		}
		return "", fmt.Errorf("pip install %s==%s : %s", pkg, tool.Version, text)
	}
	for _, name := range []string{key, tool.Name, pkg} {
		if name == "" {
			continue
		}
		script := venvExecutable(cacheDir, name)
		if executablePresent(script) {
			return script, nil
		}
	}
	return "", fmt.Errorf("pip install %s==%s a réussi mais l'exécutable est introuvable dans le venv", pkg, tool.Version)
}

func ensurePython(cacheDir string, tools map[string]ToolEntry, client *http.Client, opts SyncOptions) (string, error) {
	if py := findPython(filepath.Join(cacheDir, "python")); py != "" && pythonWorks(py) {
		return py, nil
	}
	entry, ok := tools["python"]
	var runtimeErr error
	if ok {
		if _, runtimeErr = installRuntime(cacheDir, entry, client, opts); runtimeErr == nil {
			if py := findPython(filepath.Join(cacheDir, "python")); py != "" && pythonWorks(py) {
				return py, nil
			}
			runtimeErr = fmt.Errorf("interpréteur absent après extraction")
		}
	} else {
		runtimeErr = fmt.Errorf("python absent du manifeste")
	}
	if py := systemPython(); py != "" {
		return py, nil
	}
	return "", fmt.Errorf("runtime Python indisponible: %v", runtimeErr)
}

func ensureVenv(cacheDir, python string) (string, error) {
	venv := filepath.Join(cacheDir, "venv")
	if py := venvPython(venv); executablePresent(py) && pythonWorks(py) {
		return py, nil
	}
	_ = os.RemoveAll(venv)
	cmd := exec.Command(python, "-m", "venv", venv)
	out, err := cmd.CombinedOutput()
	if err != nil {
		text := strings.TrimSpace(string(out))
		if text == "" {
			text = err.Error()
		}
		return "", fmt.Errorf("création du venv (%s) : %s", python, text)
	}
	py := venvPython(venv)
	if !executablePresent(py) {
		return "", fmt.Errorf("venv sans interpréteur: %s", py)
	}
	return py, nil
}

func venvPython(venv string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(venv, "Scripts", "python.exe")
	}
	for _, name := range []string{"python3", "python"} {
		path := filepath.Join(venv, "bin", name)
		if executablePresent(path) {
			return path
		}
	}
	return filepath.Join(venv, "bin", "python3")
}

func venvExecutable(cacheDir, tool string) string {
	if runtime.GOOS == "windows" {
		base := filepath.Join(cacheDir, "venv", "Scripts", tool)
		for _, ext := range []string{".exe", ".cmd", ".bat", ""} {
			path := base + ext
			if executablePresent(path) {
				return path
			}
		}
		return base + ".exe"
	}
	return filepath.Join(cacheDir, "venv", "bin", tool)
}

func systemPython() string {
	for _, name := range []string{"python3", "python"} {
		path, err := exec.LookPath(name)
		if err == nil && pythonWorks(path) {
			return path
		}
	}
	return ""
}

func pythonWorks(path string) bool {
	cmd := exec.Command(path, "--version")
	out, err := cmd.CombinedOutput()
	return err == nil && strings.Contains(strings.ToLower(string(out)), "python")
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

func loadArchive(key string, tool ToolEntry, client *http.Client, opts SyncOptions) ([]byte, error) {
	if opts.ArchiveCacheDir != "" {
		archiveFileName := filepath.Base(tool.ArchiveURL)
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
	if err := requireHTTPSArchive(tool.ArchiveURL); err != nil {
		return nil, fmt.Errorf("téléchargement de l'outil %s: %w", key, err)
	}
	body, err := fetchBytes(tool.ArchiveURL, client)
	if err != nil {
		return nil, fmt.Errorf("téléchargement de l'outil %s: %w", key, err)
	}
	if opts.ArchiveCacheDir != "" {
		_ = os.MkdirAll(opts.ArchiveCacheDir, 0755)
		_ = os.WriteFile(filepath.Join(opts.ArchiveCacheDir, filepath.Base(tool.ArchiveURL)), body, 0644)
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
				if err := os.MkdirAll(target, 0755); err != nil {
					return err
				}
				continue
			}
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
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
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
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
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			_ = os.Remove(target)
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				source := hdr.Linkname
				if !filepath.IsAbs(source) {
					source = filepath.Join(filepath.Dir(target), source)
				}
				data, readErr := os.ReadFile(source)
				if readErr != nil {
					continue
				}
				if err := os.WriteFile(target, data, 0755); err != nil {
					return err
				}
			}
		}
	}
}

func writeFile(path string, r io.Reader, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := io.Copy(file, r); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func safeJoin(dest, name string) (string, error) {
	clean := filepath.Clean(strings.ReplaceAll(name, "\\", "/"))
	if clean == "." || strings.HasPrefix(clean, "../") || clean == ".." || filepath.IsAbs(clean) {
		return "", fmt.Errorf("chemin d'archive refusé: %s", name)
	}
	target := filepath.Join(dest, filepath.FromSlash(clean))
	rel, err := filepath.Rel(dest, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("chemin d'archive refusé: %s", name)
	}
	return target, nil
}
