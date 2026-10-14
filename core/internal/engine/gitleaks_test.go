package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"compliance/internal/matrix"
	"compliance/internal/report"
)

func TestGitleaksInvocationExcludesDependencies(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "gitleaks.exe")
	inv, err := BuildInvocation(&PlannedControl{
		Tool: &matrix.CandidateToolState{Command: "gitleaks", Source: &source},
		Root: ".",
	}, dir, dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, path := range inv.Cleanup {
			_ = os.Remove(path)
		}
	})
	joined := strings.Join(inv.Arguments, "\n")
	for _, flag := range []string{"--no-git", "--redact", "--no-color", "--no-banner", "--report-format", "json"} {
		if !strings.Contains(joined, flag) {
			t.Fatalf("argument manquant %s dans %s", flag, joined)
		}
	}
	var configPath string
	for i, arg := range inv.Arguments {
		if arg == "--config" && i+1 < len(inv.Arguments) {
			configPath = inv.Arguments[i+1]
		}
	}
	body, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"node_modules", ".git", "dist", "build", ".venv", ".vscode-test", "vsix"} {
		if !strings.Contains(string(body), name) {
			t.Fatalf("exclusion absente: %s", name)
		}
	}
}

func TestGitleaksFindingsOmitTheSecret(t *testing.T) {
	dir := t.TempDir()
	secret := "super-secret-value"
	body := `[{"Description":"Detected a Generic API Key","StartLine":12,"StartColumn":3,"File":"src/app.js","RuleID":"generic-api-key","Secret":"` + secret + `","Match":"` + secret + `"}]`
	path := filepath.Join(dir, "report.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	leaks := readGitleaksFindings(path, dir)
	if len(leaks) != 1 || leaks[0].File != "src/app.js" || leaks[0].Line != 12 || leaks[0].RuleID != "generic-api-key" || leaks[0].Description != "Detected a Generic API Key" {
		t.Fatalf("leaks = %+v", leaks)
	}
	encoded, err := json.Marshal(leaks)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatalf("secret recopié: %s", encoded)
	}
	exit := 1
	built := report.BuildComplianceReport(report.ReportOptions{
		Repository: dir, RunID: "run", Platform: "windows-x64", ScanComplete: true,
		Results: []report.ExecutionResult{{
			ControlId: "javascript/security/gitleaks/.", Name: "JavaScript secrets", Technology: "javascript",
			Capability: "security", Root: ".", Severity: "high", Status: "fail", ExitCode: &exit, Leaks: leaks,
		}},
	})
	raw, err := json.Marshal(built)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secret) || len(built.Findings) != 1 || built.Findings[0].File != "src/app.js" || built.Findings[0].Line != 12 {
		t.Fatalf("findings = %+v", built.Findings)
	}
}

func TestStripANSI(t *testing.T) {
	got := stripANSI("leaks found: 3 \x1b[90mscan\x1b[0m")
	if got != "leaks found: 3 scan" {
		t.Fatalf("got %q", got)
	}
}
