package osutil

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	caMu         sync.RWMutex
	configuredCA string
)

// SetEnterpriseCABundle records the CA bundle selected by a flag or a setting.
func SetEnterpriseCABundle(path string) {
	caMu.Lock()
	configuredCA = strings.TrimSpace(path)
	caMu.Unlock()
}

// EnterpriseCABundle resolves one PEM bundle: explicit path, environment,
// a file shipped with the tools, then the Windows certificate store.
func EnterpriseCABundle() string {
	caMu.RLock()
	explicit := configuredCA
	caMu.RUnlock()
	candidates := []string{
		explicit,
		os.Getenv("COMPLIANCE_CA_BUNDLE"),
		os.Getenv("SSL_CERT_FILE"),
		filepath.Join(".tools", "cache", "windows-root-ca.pem"),
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		candidates = append(candidates, filepath.Join(home, ".compliance", "cache", "windows-root-ca.pem"))
	}
	for _, candidate := range candidates {
		if fileNonEmpty(candidate) {
			return candidate
		}
	}
	exported, err := exportSystemRoots()
	if err != nil || !fileNonEmpty(exported) {
		return ""
	}
	return exported
}

func fileNonEmpty(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Size() > 0
}

func pythonCommand(command string) bool {
	switch command {
	case "checkov", "bandit", "pylint", "pytest", "pip-audit", "yamllint", "ansible-lint":
		return true
	default:
		return false
	}
}

// ToolEnviron is the environment of a qualification or a control.
// Python is isolated from the machine site. Trivy does not phone home and
// keeps its cache under the Compliance directory. Proxy variables already
// present in the process are kept. An enterprise CA bundle is injected.
func ToolEnviron(command string) []string {
	drop := map[string]struct{}{}
	if pythonCommand(command) {
		drop["PYTHONPATH"] = struct{}{}
		drop["PYTHONHOME"] = struct{}{}
	}
	if command == "trivy" {
		drop["TRIVY_CONFIG"] = struct{}{}
	}
	base := AugmentedEnviron()
	env := make([]string, 0, len(base)+8)
	for _, entry := range base {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if _, skip := drop[strings.ToUpper(key)]; skip {
			continue
		}
		env = append(env, entry)
	}
	if pythonCommand(command) {
		env = append(env,
			"PYTHONNOUSERSITE=1",
			"PYTHONPATH=",
			"PYTHONDONTWRITEBYTECODE=1",
		)
	}
	if command == "trivy" {
		cache := trivyCacheDir()
		_ = os.MkdirAll(cache, 0o755)
		env = append(env,
			"TRIVY_SKIP_VERSION_CHECK=true",
			"TRIVY_SKIP_DB_UPDATE=true",
			"TRIVY_DISABLE_TELEMETRY=true",
			"TRIVY_CACHE_DIR="+cache,
		)
	}
	if ca := EnterpriseCABundle(); ca != "" {
		env = append(env,
			"SSL_CERT_FILE="+ca,
			"REQUESTS_CA_BUNDLE="+ca,
			"CURL_CA_BUNDLE="+ca,
			"PIP_CERT="+ca,
		)
	}
	return env
}

// TrivyCacheDir is the cache Trivy receives (TRIVY_CACHE_DIR).
func TrivyCacheDir() string { return trivyCacheDir() }

// TrivyDBPresent reports whether the vulnerability database was downloaded once.
func TrivyDBPresent() bool {
	info, err := os.Stat(filepath.Join(trivyCacheDir(), "db", "trivy.db"))
	return err == nil && info.Size() > 0
}

func trivyCacheDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".compliance", "cache", "trivy")
	}
	return filepath.Join(home, ".compliance", "cache", "trivy")
}
