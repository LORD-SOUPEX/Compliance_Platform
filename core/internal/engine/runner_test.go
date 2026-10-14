package engine

import (
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
	if len(unpinned) != 1 || unpinned[0].Line != 2 || unpinned[0].RuleID != "unpinned" || !strings.Contains(unpinned[0].File, "requirements.txt") {
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

func containsArg(arguments []string, want string) bool {
	for _, argument := range arguments {
		if argument == want {
			return true
		}
	}
	return false
}
