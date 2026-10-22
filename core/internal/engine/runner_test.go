package engine

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"compliance/internal/discovery"
	"compliance/internal/matrix"
	"compliance/internal/report"
)

func TestRumdlFindingsAreClickableAndLow(t *testing.T) {
	stdout := "GEMINI.md:14:1: [MD032] List should be preceded by blank line [*]\n" +
		"C:\\repo\\docs\\README.md:3:1: [MD018] No space after hash on atx style header\n" +
		"cli/testdata/README.md:1:1: [MD013] Line length exceeds 80 characters\n" +
		"not a finding\n"
	leaks := parseRumdlOutput(stdout, `C:\repo`)
	if len(leaks) != 2 {
		t.Fatalf("leaks = %+v", leaks)
	}
	if leaks[0].File != "GEMINI.md" || leaks[0].Line != 14 || leaks[0].Column != 1 || leaks[0].RuleID != "MD032" || leaks[0].Severity != "low" {
		t.Fatalf("first = %+v", leaks[0])
	}
	if !strings.Contains(leaks[0].Description, "blank line") {
		t.Fatalf("description = %q", leaks[0].Description)
	}
	if leaks[1].RuleID != "MD018" || !strings.Contains(leaks[1].File, "README.md") {
		t.Fatalf("second = %+v", leaks[1])
	}
	exit := 1
	built := report.BuildComplianceReport(report.ReportOptions{
		Repository: `C:\repo`, RunID: "run", Platform: "windows-x64", ScanComplete: true,
		Results: []report.ExecutionResult{{
			ControlId: "markdown/linting/rumdl/.", Name: "Markdown lint", Technology: "markdown",
			Capability: "linting", Root: ".", Severity: "medium", Status: "fail", ExitCode: &exit, Leaks: leaks,
		}},
	})
	if len(built.Findings) != 2 || built.Findings[0].File != "GEMINI.md" || built.Findings[0].Line != 14 || built.Findings[0].Severity != "low" {
		t.Fatalf("findings = %+v", built.Findings)
	}
	if built.Findings[0].Message == "" || strings.Contains(built.Findings[0].Message, "exit_nonzero") {
		t.Fatalf("message = %q", built.Findings[0].Message)
	}
}

func TestStructuredFindingsReplaceExitCode(t *testing.T) {
	checkov := `{"results":{"failed_checks":[{"check_id":"CKV_K8S_21","check_name":"The default namespace should not be used","file_path":"/modules/k8s/pod.yaml","file_line_range":[12,20],"resource":"kubernetes_pod.web"}]}}`
	leaks := parseToolFindings("checkov", checkov, `C:\repo`)
	if len(leaks) != 1 || leaks[0].RuleID != "CKV_K8S_21" || leaks[0].Line != 12 || !strings.Contains(leaks[0].File, "pod.yaml") {
		t.Fatalf("checkov = %+v", leaks)
	}
	tflint := `{"issues":[{"message":"module source must be a registry","rule":{"name":"terraform_module_pinned_source"},"range":{"filename":"modules/vpc/main.tf","start":{"line":4}}}]}`
	lint := parseToolFindings("tflint", tflint, `C:\repo`)
	if len(lint) != 1 || lint[0].RuleID != "terraform_module_pinned_source" || lint[0].Line != 4 || !strings.Contains(lint[0].File, "main.tf") {
		t.Fatalf("tflint = %+v", lint)
	}
	shell := `[{"file":"scripts/build.sh","line":8,"column":1,"code":2086,"level":"warning","message":"Double quote to prevent globbing."}]`
	scripts := parseToolFindings("shellcheck", shell, `C:\repo`)
	if len(scripts) != 1 || scripts[0].RuleID != "SC2086" || scripts[0].Line != 8 {
		t.Fatalf("shellcheck = %+v", scripts)
	}
	trivy := `{"Results":[{"Target":"deploy/pod.yaml","Misconfigurations":[{"ID":"KSV012","Title":"Default namespace","Severity":"LOW","CauseMetadata":{"StartLine":3}}]}]}`
	images := parseToolFindings("trivy", trivy, `C:\repo`)
	if len(images) != 1 || images[0].RuleID != "KSV012" || images[0].Line != 3 {
		t.Fatalf("trivy = %+v", images)
	}
	formatted := parseToolFindings("terraform", "modules/vpc/main.tf\n--- old\n+++ new\n", `C:\repo`)
	if len(formatted) != 1 || formatted[0].RuleID != "fmt" || !strings.Contains(formatted[0].File, "main.tf") {
		t.Fatalf("fmt = %+v", formatted)
	}
	skipped := parseToolFindings("checkov", "Check: CKV_TF_1: \"pin\"\nFile: cli/testdata/main.tf:9\n", `C:\repo`)
	if len(skipped) != 0 {
		t.Fatalf("testdata leaked: %+v", skipped)
	}
}

func TestBatchedAndStructuredFindings(t *testing.T) {
	shell := `[{"file":"a.sh","line":2,"column":1,"code":2086,"level":"warning","message":"quote"}]
[{"file":"/setters.sh","line":4,"column":1,"code":2034,"level":"error","message":"name"}]`
	scripts := parseToolFindings("shellcheck", shell, `C:\repo`)
	if len(scripts) != 2 || scripts[0].RuleID != "SC2086" || scripts[1].RuleID != "SC2034" || scripts[1].Line != 4 {
		t.Fatalf("batched shellcheck = %+v", scripts)
	}
	ruff := `[{"filename":"pkg/app.py","code":"F401","message":"unused","location":{"row":9,"column":1}}]`
	lint := parseToolFindings("ruff", ruff, `C:\repo`)
	if len(lint) != 1 || lint[0].File != "pkg/app.py" || lint[0].Line != 9 || lint[0].RuleID != "F401" {
		t.Fatalf("ruff = %+v", lint)
	}
	formatted := parseToolFindings("ruff", "Would reformat: pkg/app.py\n1 file would be reformatted\n", `C:\repo`)
	if len(formatted) != 1 || formatted[0].RuleID != "format" || formatted[0].File != "pkg/app.py" {
		t.Fatalf("ruff format = %+v", formatted)
	}
	diff := parseToolFindings("ruff", "unformatted: File would be reformatted\n --> app.py:2:1\n", `C:\repo`)
	if len(diff) != 1 || diff[0].File != "app.py" || diff[0].Line != 2 || diff[0].RuleID != "format" {
		t.Fatalf("ruff diff = %+v", diff)
	}
	docker := parseToolFindings("hadolint", `C:\repo\images\app.Dockerfile:2 DL3009 info: Delete the apt lists`+"\n", `C:\repo`)
	if len(docker) != 1 || docker[0].RuleID != "DL3009" || docker[0].Line != 2 || !strings.Contains(docker[0].File, "app.Dockerfile") {
		t.Fatalf("hadolint = %+v", docker)
	}
	eslint := parseToolFindings("eslint", `[{"filePath":"src/app.js","messages":[{"ruleId":"no-unused-vars","message":"unused","line":1,"column":5,"severity":2}]}]`, `C:\repo`)
	if len(eslint) != 1 || eslint[0].File != "src/app.js" || eslint[0].Line != 1 || eslint[0].RuleID != "no-unused-vars" {
		t.Fatalf("eslint = %+v", eslint)
	}
	tsc := parseToolFindings("tsc", "src/app.ts(1,14): error TS2322: Type 'number' is not assignable to type 'string'.\n", `C:\repo`)
	if len(tsc) != 1 || tsc[0].File != "src/app.ts" || tsc[0].Line != 1 || tsc[0].RuleID != "TS2322" {
		t.Fatalf("tsc = %+v", tsc)
	}
	quoted := windowsCmdScript(`C:\Users\Jean Clanch\eslint.cmd`, []string{`C:\Users\Jean Clanch\repo`})
	if !strings.Contains(quoted.RawCommandLine, `"C:\Users\Jean Clanch\eslint.cmd"`) || !strings.Contains(quoted.RawCommandLine, "/d /s /c") {
		t.Fatalf("cmd quote = %s", quoted.RawCommandLine)
	}
	pylint := `[{"path":"pkg/app.py","line":3,"column":0,"message":"missing docstring","message-id":"C0114","symbol":"missing-module-docstring","type":"convention"}]`
	py := parseToolFindings("pylint", pylint, `C:\repo`)
	if len(py) != 1 || py[0].RuleID != "C0114" || py[0].Line != 3 || py[0].File != "pkg/app.py" {
		t.Fatalf("pylint = %+v", py)
	}
	truncated := parseToolFindings("pylint", `[{"path":"a.py","line":4,"column":0,"message":"too long","message-id":"C0301","type":"convention"},{"path":"b.py","line":1,"message":"cut`, `C:\repo`)
	if len(truncated) != 1 || truncated[0].File != "a.py" || truncated[0].Line != 4 || truncated[0].RuleID != "C0301" {
		t.Fatalf("truncated pylint = %+v", truncated)
	}
	unpinned := parseToolFindings("pip-audit", "ERROR:pip_audit._cli:requirement cmakelint is not pinned: cmakelint (from RequirementLine(line_number=2, line='cmakelint', filename=WindowsPath('M:/Git/content/requirements.txt')))\n", `M:\Git\content`)
	if len(unpinned) != 1 || unpinned[0].Line != 2 || unpinned[0].RuleID != "non-épinglée" || !strings.Contains(unpinned[0].Description, "cmakelint") || !strings.Contains(unpinned[0].File, "requirements.txt") {
		t.Fatalf("pip-audit unpinned = %+v", unpinned)
	}
	collected := parseToolFindings("pytest", "INTERNALERROR>   File \"M:\\Git\\content\\utils\\nist_sync\\test_gemara_export.py\", line 23, in <module>\nINTERNALERROR>     from ruamel.yaml import YAML\nINTERNALERROR> ModuleNotFoundError: No module named 'ruamel'\n", `M:\Git\content`)
	if len(collected) != 1 || collected[0].Line != 23 || collected[0].RuleID != "collection" || !strings.Contains(collected[0].File, "test_gemara_export.py") {
		t.Fatalf("pytest collection = %+v", collected)
	}
	bandit := `{"results":[{"filename":"pkg/app.py","line_number":11,"test_id":"B602","issue_text":"shell","issue_severity":"HIGH"}]}`
	security := parseToolFindings("bandit", bandit, `C:\repo`)
	if len(security) != 1 || security[0].RuleID != "B602" || security[0].Line != 11 || security[0].Severity != "high" {
		t.Fatalf("bandit = %+v", security)
	}
	pytest := "tests/test_app.py:6: AssertionError\nFAILED tests/test_app.py::test_name - AssertionError: boom\n"
	tests := parseToolFindings("pytest", pytest, `C:\repo`)
	if len(tests) != 2 || tests[0].Line != 6 || tests[1].RuleID != "test_name" {
		t.Fatalf("pytest = %+v", tests)
	}
	audit := `{"dependencies":[{"name":"requests","version":"2.0","vulns":[{"id":"PYSEC-1","description":"issue","fix_versions":["2.1"]}]}]}`
	deps := parseToolFindings("pip-audit", audit, `C:\repo`)
	if len(deps) != 1 || deps[0].RuleID != "PYSEC-1" || deps[0].File != "requirements.txt" || !strings.Contains(deps[0].Description, "requests") {
		t.Fatalf("pip-audit = %+v", deps)
	}
	yaml := "playbooks/site.yml:2:1: [warning] missing document start (document-start)\n"
	playbooks := parseToolFindings("yamllint", yaml, `C:\repo`)
	if len(playbooks) != 1 || playbooks[0].RuleID != "document-start" || playbooks[0].Line != 2 || playbooks[0].File != "playbooks/site.yml" {
		t.Fatalf("yamllint = %+v", playbooks)
	}
	windowsYAML := `M:\Git\content\group_vars\all.yml:4:1: [error] syntax error (syntax)` + "\n" + `M:\Git\content\roles\app\tasks\main.yml:8:3: [warning] missing document start (document-start)`
	windowsPlaybooks := parseToolFindings("yamllint", windowsYAML, `M:\Git\content`)
	if len(windowsPlaybooks) != 2 || windowsPlaybooks[0].File != "group_vars/all.yml" || windowsPlaybooks[0].Line != 4 || windowsPlaybooks[1].Line != 8 {
		t.Fatalf("yamllint windows = %+v", windowsPlaybooks)
	}
	custom := `M:\Git\content\service.py:113:4: B104 MEDIUM: Possible binding to all interfaces.` + "\n" + `note: bandit preamble` + "\n" + `M:\Git\content\utils\app.py:2:1: B101 LOW: Use of assert detected.`
	customBandit := parseToolFindings("bandit", custom, `M:\Git\content`)
	if len(customBandit) != 2 || customBandit[0].RuleID != "B104" || customBandit[0].Line != 113 || customBandit[0].Column != 4 || customBandit[1].File != "utils/app.py" {
		t.Fatalf("bandit custom = %+v", customBandit)
	}
	cut := `{"errors":[],"metrics":{"_totals":{"loc":1}},"results":[{"filename":"pkg/a.py","line_number":3,"test_id":"B101","issue_text":"assert","issue_severity":"LOW"},{"filename":"pkg/b.py","line_number":`
	partial := parseToolFindings("bandit", cut, `C:\repo`)
	if len(partial) != 1 || partial[0].File != "pkg/a.py" || partial[0].RuleID != "B101" || partial[0].Line != 3 {
		t.Fatalf("truncated bandit = %+v", partial)
	}
	preamble := "Bandit 1.9.4\n" + bandit
	if got := parseToolFindings("bandit", preamble, `C:\repo`); len(got) != 1 || got[0].RuleID != "B602" {
		t.Fatalf("bandit preamble = %+v", got)
	}
	twoPins := "ERROR:pip_audit._cli:requirement cmakelint is not pinned: cmakelint (from RequirementLine(line_number=2, line='cmakelint', filename=WindowsPath('M:/Git/content/requirements.txt')))\nERROR:pip_audit._cli:requirement fastapi is not pinned: fastapi (from RequirementLine(line_number=9, line='fastapi', filename=WindowsPath('M:/Git/content/requirements.txt')))\n"
	pins := parseToolFindings("pip-audit", twoPins, `M:\Git\content`)
	if len(pins) != 2 || pins[0].Line != 2 || pins[1].Line != 9 {
		t.Fatalf("pip-audit pins = %+v", pins)
	}
}

func TestCommandLineBatchesStayUnderWindowsLimit(t *testing.T) {
	files := make([]string, 0, 800)
	for i := 0; i < 800; i++ {
		files = append(files, strings.Repeat("s", 80)+".sh")
	}
	batches := splitCommandArgs("shellcheck.exe", []string{"--format=json"}, files)
	if len(batches) < 2 {
		t.Fatalf("expected several batches, got %d", len(batches))
	}
	seen := 0
	for _, batch := range batches {
		width := len("shellcheck.exe") + 1
		for _, arg := range batch {
			width += argWidth(arg)
		}
		if width > 24000 {
			t.Fatalf("batch width %d", width)
		}
		seen += len(batch) - 1
	}
	if seen != len(files) {
		t.Fatalf("files %d vs %d", seen, len(files))
	}
}

func TestDockerCatalogTokenMatchesRenamedFiles(t *testing.T) {
	for _, name := range []string{".gitpod.Dockerfile", "app.Dockerfile", "Dockerfile.ci", "Containerfile"} {
		if !evidenceTokenMatches(name, "Dockerfile") && !evidenceTokenMatches(name, "Containerfile") {
			t.Fatalf("%s did not match a container catalog token", name)
		}
	}
	tech := discovery.TechnologyRecord{
		Evidence:  []string{"mod0/main.tf"},
		Roots:     []string{"mod0", "mod9"},
		RootProof: map[string][]string{"mod0": {".tf"}, "mod9": {".tf", "main.tf"}},
	}
	if samples := evidenceSamples(tech, "mod9"); len(samples) == 0 || !evidenceTokenMatches(samples[0], ".tf") {
		t.Fatalf("capped sample hid mod9: %+v", samples)
	}
}

func TestAnchorFindingPathUsesControlRoot(t *testing.T) {
	repo := t.TempDir()
	root := filepath.Join(repo, "infra", "vpc")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := anchorFindingPath(repo, root, "/setters.yaml"); got != "infra/vpc/setters.yaml" {
		t.Fatalf("slash = %s", got)
	}
	if got := anchorFindingPath(repo, root, `\main.tf`); got != "infra/vpc/main.tf" {
		t.Fatalf("backslash = %s", got)
	}
	abs := filepath.Join(root, "main.tf")
	if got := anchorFindingPath(repo, root, abs); got != "infra/vpc/main.tf" {
		t.Fatalf("absolute = %s", got)
	}
	script := filepath.Join(repo, "scripts", "bad.sh")
	if err := os.MkdirAll(filepath.Dir(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("echo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := anchorFindingPath(repo, filepath.Join(repo, "scripts"), "scripts/bad.sh"); got != "scripts/bad.sh" {
		t.Fatalf("already rooted = %s", got)
	}
	if got := anchorFindingPath(repo, filepath.Join(repo, "scripts"), "bad.sh"); got != "scripts/bad.sh" {
		t.Fatalf("cwd relative = %s", got)
	}
}

func TestRumdlLineLengthFollowsRepositoryConfig(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "rumdl.exe")
	without, err := BuildInvocation(&PlannedControl{
		Tool: &matrix.CandidateToolState{Command: "rumdl", Source: &source},
		Root: dir,
	}, dir, dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !containsArg(without.Arguments, "--disable") || !containsArg(without.Arguments, "MD013") {
		t.Fatalf("MD013 should be disabled: %v", without.Arguments)
	}
	if err := os.WriteFile(filepath.Join(dir, ".markdownlint.json"), []byte(`{"MD013":false}`), 0o644); err != nil {
		t.Fatal(err)
	}
	withConfig, err := BuildInvocation(&PlannedControl{
		Tool: &matrix.CandidateToolState{Command: "rumdl", Source: &source},
		Root: dir,
	}, dir, dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	if containsArg(withConfig.Arguments, "MD013") {
		t.Fatalf("repository config should keep MD013: %v", withConfig.Arguments)
	}
}

func TestPylintUsesRepositoryConfig(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "pylint.exe")
	if err := os.WriteFile(filepath.Join(dir, "sample.py"), []byte("print(1)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	without, err := BuildInvocation(&PlannedControl{
		Tool: &matrix.CandidateToolState{Command: "pylint", Source: &source},
		Root: dir,
	}, dir, dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	if containsArg(without.Arguments, "--rcfile") {
		t.Fatalf("rcfile inattendu: %v", without.Arguments)
	}
	rc := filepath.Join(dir, ".pylintrc")
	if err := os.WriteFile(rc, []byte("[FORMAT]\nmax-line-length = 120\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	withConfig, err := BuildInvocation(&PlannedControl{
		Tool: &matrix.CandidateToolState{Command: "pylint", Source: &source},
		Root: dir,
	}, dir, dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !containsArg(withConfig.Arguments, "--rcfile") || !containsArg(withConfig.Arguments, rc) {
		t.Fatalf("rcfile absent: %v", withConfig.Arguments)
	}
}

func TestPytestNoTestsIsNotAFailure(t *testing.T) {
	if !pytestCollectedNothing("pytest", 5, 0) {
		t.Fatal("exit 5 should be accepted")
	}
	if pytestCollectedNothing("pytest", 1, 0) || pytestCollectedNothing("ruff", 5, 0) || pytestCollectedNothing("pytest", 5, 1) {
		t.Fatal("only pytest exit 5 without findings is accepted")
	}
}

func TestYamllintOmitsMissingConfig(t *testing.T) {
	dir := t.TempDir()
	platform := t.TempDir()
	source := filepath.Join(dir, "python.exe")
	without, err := BuildInvocation(&PlannedControl{
		Tool:       &matrix.CandidateToolState{Command: "yamllint", Source: &source, RuntimeManaged: true},
		Parameters: map[string]interface{}{"configuration": ".yamllint.yml"},
		Root:       dir,
	}, dir, platform, dir)
	if err != nil {
		t.Fatal(err)
	}
	if containsArg(without.Arguments, "-c") {
		t.Fatalf("missing config should be omitted: %v", without.Arguments)
	}
	if !containsArg(without.Arguments, "-f") || !containsArg(without.Arguments, "parsable") {
		t.Fatalf("parsable format missing: %v", without.Arguments)
	}
	cfg := filepath.Join(dir, ".yamllint.yml")
	if err := os.WriteFile(cfg, []byte("extends: relaxed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	withConfig, err := BuildInvocation(&PlannedControl{
		Tool:       &matrix.CandidateToolState{Command: "yamllint", Source: &source, RuntimeManaged: true},
		Parameters: map[string]interface{}{"configuration": ".yamllint.yml"},
		Root:       dir,
	}, dir, platform, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !containsArg(withConfig.Arguments, cfg) {
		t.Fatalf("target config missing: %v", withConfig.Arguments)
	}
}

func TestPipAuditSkipsRootWithoutDependencies(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "python.exe")
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("print(1)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := BuildInvocation(&PlannedControl{
		Tool:       &matrix.CandidateToolState{Command: "pip-audit", Source: &source, RuntimeManaged: true},
		Parameters: map[string]interface{}{"arguments": []interface{}{"--no-deps", "--disable-pip", "--strict"}},
		Root:       dir,
	}, dir, dir, dir)
	var skipped *ControlSkip
	if !errors.As(err, &skipped) || skipped.Code != "not_applicable" {
		t.Fatalf("skip = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("requests==2.32.3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "requirements-dev.txt"), []byte("pytest==8.3.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	inv, err := BuildInvocation(&PlannedControl{
		Tool:       &matrix.CandidateToolState{Command: "pip-audit", Source: &source, RuntimeManaged: true},
		Parameters: map[string]interface{}{"arguments": []interface{}{"--no-deps", "--disable-pip", "--strict"}},
		Root:       dir,
	}, dir, dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, path := range inv.Cleanup {
			_ = os.Remove(path)
		}
	}()
	joined := strings.Join(inv.Arguments, " ")
	if strings.Contains(joined, "--strict") || !strings.Contains(joined, "--no-deps") || len(inv.Prefound) != 0 || len(inv.Cleanup) != 2 {
		t.Fatalf("pinned args = %v prefound=%d", inv.Arguments, len(inv.Prefound))
	}
}

func TestPipAuditListsEveryUnpinnedRequirement(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "python.exe")
	body := "-r requirements-base.txt\ncmakelint\n# comment\nruamel.yaml>=0.18.0\nrequests==2.32.3\n"
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	inv, err := BuildInvocation(&PlannedControl{
		Tool:       &matrix.CandidateToolState{Command: "pip-audit", Source: &source, RuntimeManaged: true},
		Parameters: map[string]interface{}{"arguments": []interface{}{"--no-deps", "--disable-pip", "--strict"}},
		Root:       dir,
	}, dir, dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, path := range inv.Cleanup {
			_ = os.Remove(path)
		}
	}()
	if len(inv.Prefound) != 2 || inv.Prefound[0].File != "requirements.txt" || inv.Prefound[0].Line != 2 || !strings.Contains(inv.Prefound[0].Description, "cmakelint") || inv.Prefound[1].Line != 4 || !strings.Contains(inv.Prefound[1].Description, "ruamel.yaml") {
		t.Fatalf("unpinned = %+v", inv.Prefound)
	}
	joined := strings.Join(inv.Arguments, " ")
	if strings.Contains(joined, "--strict") || !strings.Contains(joined, "--no-deps") || len(inv.Cleanup) != 1 || len(inv.Sources) != 1 || inv.Sources[0] != "requirements.txt" {
		t.Fatalf("exact pin should still be audited: %v sources=%v", inv.Arguments, inv.Sources)
	}
	reason := pipAuditResolutionReason("ERROR: Could not find a version that satisfies the requirement privatepkg==1.2.3 (from versions: none)\n")
	if !strings.Contains(reason, "privatepkg==1.2.3") {
		t.Fatalf("resolution reason = %q", reason)
	}
}

func TestPipAuditDoesNotSpawnWhenNothingIsPinned(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "python.exe")
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("pyyaml\nJinja2\nsetuptools\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	inv, err := BuildInvocation(&PlannedControl{
		Tool:       &matrix.CandidateToolState{Command: "pip-audit", Source: &source, RuntimeManaged: true},
		Parameters: map[string]interface{}{"arguments": []interface{}{"--no-deps", "--disable-pip", "--strict"}},
		Root:       dir,
	}, dir, dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Executable != "" || len(inv.Prefound) != 3 || inv.Prefound[0].File != "requirements.txt" || inv.Prefound[0].Line != 1 || inv.Prefound[1].Line != 2 || !strings.Contains(inv.Prefound[2].Description, "setuptools") {
		t.Fatalf("unpinned only = exe %q leaks %+v", inv.Executable, inv.Prefound)
	}
}

func TestParentRootOmitsFilesOwnedByNestedRoot(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "Dockerfiles"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".gitpod.Dockerfile"), []byte("FROM scratch\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Dockerfiles", "app.Dockerfile"), []byte("FROM scratch\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "hadolint.exe")
	parent, err := BuildInvocation(&PlannedControl{
		Tool:         &matrix.CandidateToolState{Command: "hadolint", Source: &source},
		ExcludeRoots: []string{"Dockerfiles"},
		Root:         ".",
	}, dir, dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(parent.Arguments, " ")
	if !strings.Contains(joined, ".gitpod.Dockerfile") || strings.Contains(joined, "app.Dockerfile") {
		t.Fatalf("parent files = %v", parent.Arguments)
	}
	child, err := BuildInvocation(&PlannedControl{
		Tool: &matrix.CandidateToolState{Command: "hadolint", Source: &source},
		Root: "Dockerfiles",
	}, filepath.Join(dir, "Dockerfiles"), dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(child.Arguments, " "), "app.Dockerfile") {
		t.Fatalf("child files = %v", child.Arguments)
	}
	controls := []*PlannedControl{
		{Technology: "docker", Applicability: "applicable", Root: ".", Tool: &matrix.CandidateToolState{Command: "hadolint"}},
		{Technology: "docker", Applicability: "applicable", Root: "Dockerfiles", Tool: &matrix.CandidateToolState{Command: "hadolint"}},
	}
	assignNestedExclusions(controls)
	if len(controls[0].ExcludeRoots) != 1 || controls[0].ExcludeRoots[0] != "Dockerfiles" || len(controls[1].ExcludeRoots) != 0 {
		t.Fatalf("excludes = %#v %#v", controls[0].ExcludeRoots, controls[1].ExcludeRoots)
	}
}

func TestESLintFallbackWhenRepositoryHasNoConfig(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "eslint.cmd")
	inv, err := BuildInvocation(&PlannedControl{
		Tool: &matrix.CandidateToolState{Command: "eslint", Source: &source},
		Root: dir,
	}, dir, dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, path := range inv.Cleanup {
			_ = os.Remove(path)
		}
	}()
	joined := strings.Join(append(inv.Arguments, inv.RawCommandLine), " ")
	if !strings.Contains(joined, "--no-config-lookup") || !strings.Contains(joined, "-c") || len(inv.Cleanup) != 1 {
		t.Fatalf("fallback = %#v", inv)
	}
	if err := os.WriteFile(filepath.Join(dir, "eslint.config.js"), []byte("export default [];\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	configured, err := BuildInvocation(&PlannedControl{
		Tool: &matrix.CandidateToolState{Command: "eslint", Source: &source},
		Root: dir,
	}, dir, dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	configuredLine := strings.Join(append(configured.Arguments, configured.RawCommandLine), " ")
	if strings.Contains(configuredLine, "--no-config-lookup") || len(configured.Cleanup) != 0 {
		t.Fatalf("repository config should be used: %#v", configured)
	}
}

func containsArg(arguments []string, want string) bool {
	for _, argument := range arguments {
		if argument == want {
			return true
		}
	}
	return false
}

func TestESLintFindingsFromSeveralRuns(t *testing.T) {
	stdout := `[{"filePath":"/repo/apps/a.js","messages":[]}]` + "\n" +
		`[{"filePath":"/repo/legacy/b.js","messages":[{"ruleId":"eqeqeq","message":"Expected '==='","line":3,"column":7,"severity":1}]}]` + "\n" +
		`[{"filePath":"/repo/legacy/c.ts","messages":[{"ruleId":null,"message":"Parsing error","line":0,"column":0,"severity":2}]}]`
	leaks := parseESLint(stdout, "/repo")
	if len(leaks) != 2 || leaks[0].RuleID != "eqeqeq" || leaks[0].Line != 3 || leaks[1].RuleID != "eslint" || leaks[1].Severity != "medium" {
		t.Fatalf("leaks = %+v", leaks)
	}
}

func TestFormatAndPowerShellParsers(t *testing.T) {
	fmtLeaks := parseFmtFiles("main.tofu\n--- old/main.tofu\n+++ new/main.tofu\n-a\n+b\nvars.tfvars\nREADME.md\n", "")
	if len(fmtLeaks) != 2 || fmtLeaks[0].File != "main.tofu" || fmtLeaks[1].File != "vars.tfvars" {
		t.Fatalf("fmt = %+v", fmtLeaks)
	}
	// Absolute paths differ per OS (C:\ on Windows): build them from a real folder.
	repo := t.TempDir()
	hcl := filepath.Join(repo, "live", "terragrunt.hcl")
	tg := parseTerragruntFmt("13:29:23 ERROR  File '"+hcl+"' needs formatting\n13:29:23 ERROR  File '"+hcl+"' needs formatting\n", repo)
	if len(tg) != 1 || tg[0].File != "live/terragrunt.hcl" || tg[0].RuleID != "hclfmt" {
		t.Fatalf("terragrunt = %+v", tg)
	}
	row := func(file, line, severity string) string {
		raw, _ := json.Marshal(map[string]interface{}{"file": filepath.Join(repo, filepath.FromSlash(file)), "line": json.RawMessage(line), "rule": "R", "severity": severity, "message": "m"})
		return string(raw)
	}
	ps := parsePSScriptAnalyzer("noise\n"+row("scripts/a.ps1", "12", "Warning")+"\n"+row("scripts/b.ps1", `"3"`, "Error")+"\n", repo)
	if len(ps) != 2 || ps[0].File != "scripts/a.ps1" || ps[0].Line != 12 || ps[0].Severity != "medium" || ps[1].Line != 3 || ps[1].Severity != "high" {
		t.Fatalf("psscriptanalyzer = %+v", ps)
	}
}

func TestToolCrashIsNotAComplianceFailure(t *testing.T) {
	if !toolCrashed("trivy", "FATAL Fatal error run error: init error: DB error", 0) {
		t.Fatal("trivy FATAL not seen as a crash")
	}
	if toolCrashed("trivy", "FATAL whatever", 2) || toolCrashed("terragrunt", "ERROR File 'x' needs formatting", 0) || toolCrashed("ruff", "FATAL", 0) {
		t.Fatal("findings or another tool taken for a crash")
	}
}

func TestShfmtAndKubeconformParsers(t *testing.T) {
	repo := t.TempDir()
	script := filepath.Join(repo, "scripts", "a.sh")
	shfmt := parseShfmt(script+"\nnot-a-script.txt\n", repo)
	if len(shfmt) != 1 || shfmt[0].File != "scripts/a.sh" || shfmt[0].RuleID != "shfmt" {
		t.Fatalf("shfmt = %+v", shfmt)
	}
	manifest := filepath.Join(repo, "k8s", "pod.yaml")
	raw, _ := json.Marshal(map[string]interface{}{"resources": []map[string]string{
		{"filename": manifest, "kind": "Pod", "name": "debug", "status": "statusInvalid", "msg": "spec.containers: Required value"},
		{"filename": manifest, "kind": "Service", "name": "ok", "status": "statusValid"},
	}})
	kube := parseKubeconform(string(raw), repo)
	if len(kube) != 1 || kube[0].File != "k8s/pod.yaml" || kube[0].Severity != "medium" || !strings.Contains(kube[0].Description, "Required value") {
		t.Fatalf("kubeconform = %+v", kube)
	}
}

func TestManifestAndYAMLFileSelection(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"pod.yaml":      "apiVersion: v1\nkind: Pod\n",
		"values.yaml":   "replicas: 2\n",
		"template.yaml": "apiVersion: v1\nkind: Pod\nname: {{ .Values.name }}\n",
		"notes.txt":     "x\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "other.yml"), []byte("a: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !kubernetesManifest(filepath.Join(dir, "pod.yaml")) || kubernetesManifest(filepath.Join(dir, "values.yaml")) || kubernetesManifest(filepath.Join(dir, "template.yaml")) {
		t.Fatal("manifest selection")
	}
	files := yamlFilesOf(dir)
	if len(files) != 2 {
		t.Fatalf("own YAML files without templates or sub-folders expected, got %v", files)
	}
}

func TestRuffFormatDiffWithBracesIsStillRead(t *testing.T) {
	stdout := "unformatted: File would be reformatted\n --> build.py:37:13\n   |\n   - x = {}\n   + x = []\n\nunformatted: File would be reformatted\n --> pkg/tool.py:3:1\n"
	leaks := parseRuff(stdout, "")
	if len(leaks) != 2 || leaks[0].File != "build.py" || leaks[0].Line != 37 || leaks[1].File != "pkg/tool.py" {
		t.Fatalf("ruff format = %+v", leaks)
	}
}

func TestTSConfigProjectsSkipDiscoveryFolders(t *testing.T) {
	repo := t.TempDir()
	for _, name := range []string{"tsconfig.json", "app/tsconfig.json", "app/tsconfig.build.json", ".vscode-test/vscode/ext/tsconfig.json", "node_modules/x/tsconfig.json"} {
		path := filepath.Join(repo, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	projects := tsconfigProjects(repo)
	if len(projects) != 2 {
		t.Fatalf("projects = %v", projects)
	}
}
