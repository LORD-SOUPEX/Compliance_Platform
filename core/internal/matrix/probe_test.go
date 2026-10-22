package matrix

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"compliance/internal/osutil"
)

const probeStub = `package main

import (
	"os"
	"strings"
	"time"
)

func main() {
	joined := strings.Join(os.Args[1:], " ")
	if strings.Contains(joined, "import") && strings.Contains(joined, "checkov") {
		if os.Getenv("COMPLIANCE_PROBE_SLOW") == "1" {
			time.Sleep(5 * time.Second)
		}
		os.Stderr.WriteString("Traceback (most recent call last): checkov import failed\n")
		os.Exit(1)
	}
	if strings.Contains(joined, "bandit") {
		os.Stdout.WriteString("bandit 1.9.4\n")
		os.Exit(0)
	}
	if strings.Contains(joined, "--version") {
		os.Exit(1)
	}
	os.Exit(0)
}
`

func goTool(t *testing.T) string {
	t.Helper()
	if found, err := exec.LookPath("go"); err == nil {
		return found
	}
	candidate := filepath.Join("..", "..", "..", ".tools", "go", "bin", "go.exe")
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	t.Fatal("go introuvable")
	return ""
}

func buildStub(t *testing.T, dir, name string) string {
	t.Helper()
	source := filepath.Join(dir, "stub.go")
	if err := os.WriteFile(source, []byte(probeStub), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module stub\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, name)
	cmd := exec.Command(goTool(t), "build", "-o", exe, "stub.go")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build stub: %v\n%s", err, out)
	}
	return exe
}

func TestCheckovFailureAndTrivySilenceStayProbeErrors(t *testing.T) {
	dir := t.TempDir()
	stub := buildStub(t, dir, "stub.exe")
	root := filepath.Join(dir, "platform")
	pythonDir := filepath.Join(root, ".tools", "python")
	binDir := filepath.Join(root, ".tools", "bin")
	if err := os.MkdirAll(pythonDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	python := filepath.Join(pythonDir, "python.exe")
	trivy := filepath.Join(binDir, "trivy.exe")
	if err := copyFile(stub, python); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(stub, trivy); err != nil {
		t.Fatal(err)
	}
	resolver := &DefaultCandidateResolver{PlatformRoot: root, CacheRoot: filepath.Join(dir, "empty-cache")}
	platform := PlatformInfo{OS: "windows", Architecture: "x64", ID: "windows-x64"}

	checkov := resolver.ResolveCandidate("Checkov", "checkov", platform, root)
	if checkov.Status != "runtime_error" || !strings.Contains(checkov.Reason, "Traceback") || strings.Contains(checkov.Reason, "installable") {
		t.Fatalf("checkov = %+v", checkov)
	}
	bandit := resolver.ResolveCandidate("Bandit", "bandit", platform, root)
	if bandit.Status != "available" {
		t.Fatalf("bandit = %+v", bandit)
	}
	scanned := resolver.ResolveCandidate("Trivy", "trivy", platform, root)
	if scanned.Status != "runtime_error" || !strings.Contains(scanned.Reason, "aucune sortie") || !strings.Contains(strings.ToLower(scanned.Reason), "trivy.exe") || strings.Contains(scanned.Reason, "installable") {
		t.Fatalf("trivy = %+v", scanned)
	}
}

func TestCheckovProbeTimeoutIsNotInstallable(t *testing.T) {
	previous := osutil.ProbeTimeoutFor
	osutil.ProbeTimeoutFor = func(command string) time.Duration {
		if command == "checkov" {
			return 200 * time.Millisecond
		}
		return previous(command)
	}
	t.Cleanup(func() { osutil.ProbeTimeoutFor = previous })
	t.Setenv("COMPLIANCE_PROBE_SLOW", "1")

	dir := t.TempDir()
	stub := buildStub(t, dir, "stub.exe")
	root := filepath.Join(dir, "platform")
	pythonDir := filepath.Join(root, ".tools", "python")
	if err := os.MkdirAll(pythonDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(stub, filepath.Join(pythonDir, "python.exe")); err != nil {
		t.Fatal(err)
	}
	resolver := &DefaultCandidateResolver{PlatformRoot: root, CacheRoot: filepath.Join(dir, "empty-cache")}
	state := resolver.ResolveCandidate("Checkov", "checkov", PlatformInfo{OS: "windows", Architecture: "x64", ID: "windows-x64"}, root)
	if state.Status != "runtime_error" || !strings.Contains(state.Reason, "délai de sonde") || strings.Contains(state.Reason, "installable") {
		t.Fatalf("timeout = %+v", state)
	}
}

func copyFile(src, dest string) error {
	body, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dest, body, 0o755)
}
