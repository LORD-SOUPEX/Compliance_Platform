package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"compliance/internal/discovery"
	"compliance/internal/embedded"
	"compliance/internal/report"
	engineversion "compliance/internal/version"
)

func TestPlatformSupported(t *testing.T) {
	if !platformSupported(nil, "macos-arm64") {
		t.Fatal("an empty support list does not restrict the platform")
	}
	if !platformSupported([]string{"macos-x64", "macos-arm64"}, "macos-arm64") {
		t.Fatal("declared platform should be supported")
	}
	if platformSupported([]string{"linux-x64", "macos-arm64"}, "macos-x64") {
		t.Fatal("macos-x64 should be rejected when it is absent from platform_support")
	}
	if !platformSupported([]string{"windows-x64"}, "") {
		t.Fatal("an empty platform id skips the filter")
	}
}

func TestPowershellHostDoesNotUseWindowsPowerShellOnDarwin(t *testing.T) {
	got := powershellHost("darwin", "/opt/compliance/PSScriptAnalyzer.psd1")
	if got == "powershell.exe" {
		t.Fatal("darwin must not fall back to powershell.exe")
	}
	if got != "pwsh" && !hasSuffixFold(got, "pwsh") {
		t.Fatalf("powershellHost(darwin) = %q, want pwsh", got)
	}

	windows := powershellHost("windows", "/opt/compliance/PSScriptAnalyzer.psd1")
	if windows != "powershell.exe" {
		t.Fatalf("powershellHost(windows) = %q, want powershell.exe", windows)
	}
}

func TestNothingExecutableIsNotAFailure(t *testing.T) {
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "package.json"), []byte("{\n\t\"name\": \"empty\"\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	catalog, err := embedded.ResolveAsset("control-catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	rep, err := RunCompliance(context.Background(), ComplianceOptions{
		RepoRoot:      repo,
		PlatformRoot:  t.TempDir(),
		CatalogPath:   catalog,
		PlanOnly:      false,
		SourceAdapter: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Summary.Error != 0 || rep.Summary.Fail != 0 {
		for _, r := range rep.ExecutionResults {
			if r.Status == "fail" || r.Status == "error" {
				t.Logf("%s %s", r.ControlId, r.Status)
			}
		}
		t.Fatalf("summary = %+v, want no executed failure", rep.Summary)
	}
	status, message := controlOutcome(t, rep, "javascript/linting/eslint/.")
	switch status {
	case "skipped":
		if !strings.Contains(message, "npm install") {
			t.Fatalf("eslint status=%s message=%s", status, message)
		}
		if rep.Coverage.Complete {
			t.Fatal("coverage must not be complete when the repository ESLint cannot run")
		}
		if rep.Summary.Success == 0 && rep.Verdict != nil {
			t.Fatalf("verdict = %v, want null when nothing ran", *rep.Verdict)
		}
	case "success":
	default:
		t.Fatalf("eslint status=%s message=%s", status, message)
	}
	if !strings.Contains(rep.Coverage.Label, "Couverture") {
		t.Fatalf("label = %q", rep.Coverage.Label)
	}
	if rep.EngineVersion != engineversion.Version {
		t.Fatalf("engine_version = %s, want %s", rep.EngineVersion, engineversion.Version)
	}
	raw, _ := json.Marshal(rep)
	if !strings.Contains(string(raw), "javascript.lint.eslint") {
		t.Fatal("eslint control was not planned")
	}
}

func TestPlanJSONStaysUnderOneMegabyteWithNodeModules(t *testing.T) {
	repo := t.TempDir()
	write := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(repo, "package.json"), `{"name":"bforge"}`)
	write(filepath.Join(repo, "node_modules", "aria-query", "lib", "roles", "checkboxRole.js"), "module.exports = {}\n")
	for i := 0; i < 1500; i++ {
		write(filepath.Join(repo, "node_modules", "pkg", "file"+strconv.Itoa(i)+".js"), "x")
	}
	catalog, err := embedded.ResolveAsset("control-catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	rep, err := RunCompliance(context.Background(), ComplianceOptions{
		RepoRoot:      repo,
		CatalogPath:   catalog,
		PlanOnly:      true,
		SourceAdapter: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 1<<20 {
		t.Fatalf("plan JSON = %d bytes, want <= 1 MiB", len(raw))
	}
	found, ok := rep.Discovery.(*discovery.DiscoveryResult)
	if !ok {
		t.Fatalf("discovery type %T", rep.Discovery)
	}
	for _, item := range found.Technologies {
		if item.Technology == "ansible" && item.Status != "absent" {
			t.Fatalf("ansible detected in node_modules fixture: %+v", item)
		}
	}
}

func TestTypeScriptPlanHasOneControlPerTool(t *testing.T) {
	repo := t.TempDir()
	write := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(repo, "package.json"), `{"name":"ts"}`)
	write(filepath.Join(repo, "tsconfig.json"), `{"compilerOptions":{"noEmit":true}}`)
	write(filepath.Join(repo, "src", "main.ts"), "export const value = 1\n")
	write(filepath.Join(repo, "server", "tsconfig.json"), `{"compilerOptions":{"noEmit":true}}`)
	write(filepath.Join(repo, "server", "src", "main.ts"), "export const value = 1\n")
	catalog, err := embedded.ResolveAsset("control-catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	rep, err := RunCompliance(context.Background(), ComplianceOptions{
		RepoRoot:      repo,
		CatalogPath:   catalog,
		PlanOnly:      true,
		SourceAdapter: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	raw, _ := json.Marshal(rep.ExecutionPlan.Controls)
	var controls []struct {
		ID         string `json:"id"`
		Technology string `json:"technology"`
		Name       string `json:"name"`
	}
	if err := json.Unmarshal(raw, &controls); err != nil {
		t.Fatal(err)
	}
	for _, control := range controls {
		if control.Technology != "typescript" {
			continue
		}
		seen[control.Name]++
		if strings.Contains(control.Name, "(none)") {
			t.Fatalf("unconfigured control still planned: %s", control.Name)
		}
	}
	if seen["typescript: linting (eslint)"] != 1 || seen["typescript: typecheck (tsc)"] != 1 {
		t.Fatalf("typescript controls = %#v", seen)
	}
}

func TestRepositoryESLintDoesNotPassWithoutSetup(t *testing.T) {
	t.Setenv("COMPLIANCE_NODE_TOOLS", filepath.Join(t.TempDir(), "node"))
	catalog, err := embedded.ResolveAsset("control-catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	withoutDeps := t.TempDir()
	if err := os.WriteFile(filepath.Join(withoutDeps, "package.json"), []byte(`{"name":"web"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(withoutDeps, "index.js"), []byte("export const value = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	missing, err := RunCompliance(context.Background(), ComplianceOptions{RepoRoot: withoutDeps, PlatformRoot: t.TempDir(), CatalogPath: catalog, SourceAdapter: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if status, message := controlOutcome(t, missing, "javascript/linting/eslint/."); status == "success" || !strings.Contains(message, "npm install") {
		t.Fatalf("missing deps status=%s message=%s", status, message)
	}

	withoutConfig := t.TempDir()
	if err := os.MkdirAll(filepath.Join(withoutConfig, "node_modules", ".bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(withoutConfig, "package.json"), []byte(`{"name":"web"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(withoutConfig, "index.js"), []byte("export const value = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(withoutConfig, "node_modules", ".bin", "eslint.cmd"), []byte("@exit /b 0\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	unconfigured, err := RunCompliance(context.Background(), ComplianceOptions{RepoRoot: withoutConfig, CatalogPath: catalog, SourceAdapter: "test"})
	if err != nil {
		t.Fatal(err)
	}
	status, message := controlOutcome(t, unconfigured, "javascript/linting/eslint/.")
	if status != "success" || strings.Contains(message, "Configuration ESLint absente") {
		t.Fatalf("missing config should run with the fallback, status=%s message=%s", status, message)
	}
}

func TestManagedNodeToolchainRunsESLint(t *testing.T) {
	tools := t.TempDir()
	t.Setenv("COMPLIANCE_NODE_TOOLS", tools)
	bin := filepath.Join(tools, "node_modules", ".bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "eslint.cmd"), []byte("@exit /b 0\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "package.json"), []byte(`{"name":"web"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "index.js"), []byte("export const value = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "eslint.config.js"), []byte("export default []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	catalog, err := embedded.ResolveAsset("control-catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	rep, err := RunCompliance(context.Background(), ComplianceOptions{RepoRoot: repo, CatalogPath: catalog, SourceAdapter: "test"})
	if err != nil {
		t.Fatal(err)
	}
	status, message := controlOutcome(t, rep, "javascript/linting/eslint/.")
	if status != "success" {
		t.Fatalf("managed eslint status=%s message=%s", status, message)
	}
}

func controlOutcome(t *testing.T, rep *report.Report, id string) (string, string) {
	t.Helper()
	for _, result := range rep.ExecutionResults {
		if result.ControlId != id {
			continue
		}
		message := ""
		if len(result.Diagnostics) > 0 {
			message = result.Diagnostics[0].Message
		}
		return result.Status, message
	}
	t.Fatalf("control %s absent", id)
	return "", ""
}

func hasSuffixFold(value, suffix string) bool {
	if len(value) < len(suffix) {
		return false
	}
	return value[len(value)-len(suffix):] == suffix
}
