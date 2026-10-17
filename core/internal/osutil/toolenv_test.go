package osutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestToolEnvironIsolatesPythonAndTrivy(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(bundle, []byte("enterprise-ca"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("COMPLIANCE_CA_BUNDLE", bundle)
	t.Setenv("PYTHONPATH", `C:\corporate\site`)
	t.Setenv("TRIVY_CONFIG", `C:\corporate\trivy.yaml`)
	t.Setenv("HTTPS_PROXY", "http://proxy.example:8080")

	python := strings.Join(ToolEnviron("checkov"), "\n")
	if !strings.Contains(python, "PYTHONNOUSERSITE=1") || !strings.Contains(python, "PYTHONDONTWRITEBYTECODE=1") || !strings.Contains(python, "PYTHONPATH=") {
		t.Fatalf("python isolation missing: %s", python)
	}
	if strings.Contains(python, `corporate\site`) {
		t.Fatalf("PYTHONPATH leaked: %s", python)
	}
	if !strings.Contains(python, "SSL_CERT_FILE="+bundle) || !strings.Contains(python, "REQUESTS_CA_BUNDLE="+bundle) || !strings.Contains(python, "CURL_CA_BUNDLE="+bundle) || !strings.Contains(python, "PIP_CERT="+bundle) {
		t.Fatalf("CA bundle missing: %s", python)
	}

	trivy := strings.Join(ToolEnviron("trivy"), "\n")
	if strings.Contains(trivy, "trivy.yaml") {
		t.Fatalf("TRIVY_CONFIG leaked: %s", trivy)
	}
	for _, needle := range []string{"TRIVY_SKIP_VERSION_CHECK=true", "TRIVY_SKIP_DB_UPDATE=true", "TRIVY_DISABLE_TELEMETRY=true", "TRIVY_CACHE_DIR=", "HTTPS_PROXY=http://proxy.example:8080", "SSL_CERT_FILE=" + bundle} {
		if !strings.Contains(trivy, needle) {
			t.Fatalf("missing %s in %s", needle, trivy)
		}
	}
}

func TestFormatProbeFailureNamesEmptyOutputAndBinary(t *testing.T) {
	text := FormatProbeFailure(`C:\tools\trivy.exe`, os.ErrClosed, "", "", 0)
	if !strings.Contains(text, "aucune sortie") || !strings.Contains(text, `C:\tools\trivy.exe`) || strings.Contains(text, "installable") {
		t.Fatal(text)
	}
}
