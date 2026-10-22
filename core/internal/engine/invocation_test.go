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

// A Node package in a sub-folder carries its own node_modules and ESLint config
// (this repository: vscode-extension/ beside core/). Both must be found there.
func TestNodeToolsAndConfigAreFoundInTheControlRoot(t *testing.T) {
	t.Setenv("COMPLIANCE_NODE_TOOLS", filepath.Join(t.TempDir(), "node"))
	repo := t.TempDir()
	web := filepath.Join(repo, "web")
	if err := os.MkdirAll(web, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"package.json":      `{"name":"web"}`,
		"index.js":          "export const value = 1\n",
		"eslint.config.mjs": "export default []\n",
	} {
		if err := os.WriteFile(filepath.Join(web, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeFakeESLint(t, web)
	catalog, err := embedded.ResolveAsset("control-catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	rep, err := RunCompliance(context.Background(), ComplianceOptions{RepoRoot: repo, CatalogPath: catalog, SourceAdapter: "test"})
	if err != nil {
		t.Fatal(err)
	}
	var found *report.ExecutionResult
	for i := range rep.ExecutionResults {
		if strings.HasPrefix(rep.ExecutionResults[i].ControlId, "javascript/linting/eslint/") {
			found = &rep.ExecutionResults[i]
		}
	}
	if found == nil || found.Status != "success" || len(found.Invocations) == 0 {
		t.Fatalf("eslint in web/ = %+v", found)
	}
	for _, arg := range found.Invocations[0].Args {
		if arg == "--no-config-lookup" {
			t.Fatal("the config in web/ was ignored and the fallback used")
		}
	}
	if raw := found.Invocations[0].RawCommandLine; raw != nil && strings.Contains(*raw, "--no-config-lookup") {
		t.Fatal("the config in web/ was ignored and the fallback used")
	}
}

func TestAncestorsWithinStopsAtTheRepository(t *testing.T) {
	repo := filepath.Join(t.TempDir(), "repo")
	got := ancestorsWithin(repo, "a/b")
	want := []string{filepath.Join(repo, "a", "b"), filepath.Join(repo, "a"), repo}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("ancestors = %v, want %v", got, want)
	}
	if escaped := ancestorsWithin(repo, "../outside"); len(escaped) != 1 || escaped[0] != repo {
		t.Fatalf("escaping root = %v", escaped)
	}
}

func TestBuiltInSecretsAreAlwaysMasked(t *testing.T) {
	redactor, err := NewRedactor(nil, "")
	if err != nil {
		t.Fatal(err)
	}
	out := redactor.Redact("token=ghp_abcdefghijklmnopqrstuvwxyz0123 key=AKIAABCDEFGHIJKLMNOP -----BEGIN RSA PRIVATE KEY-----")
	if strings.Contains(out, "ghp_abcdef") || strings.Contains(out, "AKIAABCD") || strings.Contains(out, "BEGIN RSA PRIVATE KEY") {
		t.Fatalf("secret left in output: %s", out)
	}
	custom, err := NewRedactor([]string{"internal-[0-9]+"}, "")
	if err != nil || strings.Contains(custom.Redact("host internal-42 ghp_abcdefghijklmnopqrstuvwxyz0123"), "internal-42") {
		t.Fatalf("user pattern not applied with the built-in ones: %v", err)
	}
}

// ESLint is one repository-wide control: it must receive every JavaScript root,
// not only the one the merged control is named after.
func TestRepositoryWideESLintLintsEveryRoot(t *testing.T) {
	tools := t.TempDir()
	writeFakeESLint(t, tools)
	t.Setenv("COMPLIANCE_NODE_TOOLS", tools)
	repo := t.TempDir()
	for _, root := range []string{"apps/web", "legacy/old"} {
		dir := filepath.Join(repo, filepath.FromSlash(root))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, body := range map[string]string{"package.json": `{"name":"x"}`, "index.js": "var a = 1\n"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	catalog, err := embedded.ResolveAsset("control-catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	rep, err := RunCompliance(context.Background(), ComplianceOptions{RepoRoot: repo, CatalogPath: catalog, SourceAdapter: "test"})
	if err != nil {
		t.Fatal(err)
	}
	var command string
	for _, result := range rep.ExecutionResults {
		if !strings.HasPrefix(result.ControlId, "javascript/linting/eslint/") {
			continue
		}
		if len(result.Invocations) != 2 {
			t.Fatalf("one ESLint run per root expected, got %d", len(result.Invocations))
		}
		for _, inv := range result.Invocations {
			command += " cwd=" + inv.Cwd + " " + strings.Join(inv.Args, " ")
			if inv.RawCommandLine != nil {
				command += " " + *inv.RawCommandLine
			}
		}
	}
	normalized := strings.ReplaceAll(command, `\`, "/")
	// The engine works on the canonical path (macOS: /var is /private/var).
	if resolved, err := filepath.EvalSymlinks(repo); err == nil {
		repo = resolved
	}
	for _, root := range []string{"apps/web", "legacy/old"} {
		// Each run happens inside its root: ESLint ignores files outside its working folder.
		if !strings.Contains(normalized, "/"+root) || !strings.Contains(normalized, "cwd="+filepath.ToSlash(filepath.Join(repo, filepath.FromSlash(root)))) {
			t.Fatalf("eslint did not run in %s: %s", root, command)
		}
	}
}
