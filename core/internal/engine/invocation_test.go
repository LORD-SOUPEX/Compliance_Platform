package engine

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"compliance/internal/embedded"
	"compliance/internal/report"
)

// writeFakeESLint installs a repository ESLint that prints one line per stream.
// Windows gets a .cmd launcher, Linux and macOS an executable shell script.
func writeFakeESLint(t *testing.T, repo string) {
	t.Helper()
	bin := filepath.Join(repo, "node_modules", ".bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		script := "@echo fake-eslint-stdout\r\n@echo fake-eslint-stderr 1>&2\r\n@exit /b 0\r\n"
		if err := os.WriteFile(filepath.Join(bin, "eslint.cmd"), []byte(script), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	script := "#!/bin/sh\necho fake-eslint-stdout\necho fake-eslint-stderr >&2\nexit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "eslint"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestInvocationIsRecordedWithCompleteStreamsOnDisk(t *testing.T) {
	t.Setenv("COMPLIANCE_NODE_TOOLS", filepath.Join(t.TempDir(), "node"))
	repo := t.TempDir()
	for name, body := range map[string]string{
		"package.json":     `{"name":"web"}`,
		"index.js":         "export const value = 1\n",
		"eslint.config.js": "export default []\n",
	} {
		if err := os.WriteFile(filepath.Join(repo, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeFakeESLint(t, repo)
	catalog, err := embedded.ResolveAsset("control-catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	session := t.TempDir()
	logDir := filepath.Join(session, "logs")
	var announced []report.Invocation
	rep, err := RunCompliance(context.Background(), ComplianceOptions{
		RepoRoot:      repo,
		CatalogPath:   catalog,
		SourceAdapter: "test",
		LogDir:        logDir,
		OnInvocation: func(ctrl *PlannedControl, inv report.Invocation) {
			if ctrl.ID == "javascript/linting/eslint/." {
				announced = append(announced, inv)
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var result *report.ExecutionResult
	for i := range rep.ExecutionResults {
		if rep.ExecutionResults[i].ControlId == "javascript/linting/eslint/." {
			result = &rep.ExecutionResults[i]
		}
	}
	if result == nil || result.Status != "success" {
		t.Fatalf("eslint result = %+v", result)
	}
	if len(result.Invocations) == 0 || len(announced) != len(result.Invocations) {
		t.Fatalf("invocations = %d, announced = %d", len(result.Invocations), len(announced))
	}
	inv := result.Invocations[0]
	if inv.ExitCode == nil || *inv.ExitCode != 0 || inv.Cwd == "" || inv.StartedAt == "" || inv.TimeoutMs <= 0 {
		t.Fatalf("invocation = %+v", inv)
	}
	if inv.StdoutPath == nil || inv.StderrPath == nil || strings.Contains(*inv.StdoutPath, "\\") {
		t.Fatalf("stream paths = %v %v", inv.StdoutPath, inv.StderrPath)
	}
	stdout, err := os.ReadFile(filepath.Join(session, filepath.FromSlash(*inv.StdoutPath)))
	if err != nil || !strings.Contains(string(stdout), "fake-eslint-stdout") {
		t.Fatalf("stdout file = %q err=%v", stdout, err)
	}
	stderr, err := os.ReadFile(filepath.Join(session, filepath.FromSlash(*inv.StderrPath)))
	if err != nil || !strings.Contains(string(stderr), "fake-eslint-stderr") || strings.Contains(string(stderr), "fake-eslint-stdout") {
		t.Fatalf("stderr file = %q err=%v", stderr, err)
	}
	if inv.StdoutBytes == 0 || inv.StderrBytes == 0 {
		t.Fatalf("byte counters = %d %d", inv.StdoutBytes, inv.StderrBytes)
	}
}

func TestLogFileBaseIsPortable(t *testing.T) {
	for id, want := range map[string]string{
		"javascript/linting/eslint/.": "javascript__linting__eslint",
		`python\lint\ruff\a:b`:        "python__lint__ruff__a_b",
		"":                            "control",
	} {
		if got := LogFileBase(id); got != want {
			t.Fatalf("LogFileBase(%q) = %q, want %q", id, got, want)
		}
	}
}
