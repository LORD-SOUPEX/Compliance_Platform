package engine

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"compliance/internal/discovery"
	"compliance/internal/distribution"
	"compliance/internal/embedded"
	"compliance/internal/matrix"
	"compliance/internal/osutil"
	"compliance/internal/report"
)

//go:embed eslint_fallback.cjs
var eslintFallbackSource []byte

// ControlSkip marks a control that has nothing to run. It is not a failure.
type ControlSkip struct {
	Code    string
	Message string
}

func (e *ControlSkip) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

var (
	reVersionFinder = regexp.MustCompile(`\b\d+\.\d+(?:\.\d+)?(?:[a-zA-Z0-9.+-]*)`)
	ansiEscape      = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

	defaultRedactionPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:ghp|glpat)_[a-zA-Z0-9]{20,}`),
		regexp.MustCompile(`(?i)(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}`),
		regexp.MustCompile(`-----BEGIN [A-Z ]+PRIVATE KEY-----`),
	}
)

// Redactor handles string sanitization.
type Redactor struct {
	Patterns    []*regexp.Regexp
	Replacement string
}

// NewRedactor creates a Redactor from pattern strings.
func NewRedactor(patterns []string, replacement string) (*Redactor, error) {
	if replacement == "" {
		replacement = "[REDACTED]"
	}
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pat := range patterns {
		if strings.TrimSpace(pat) == "" {
			continue
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("motif de masquage regex invalide: %s: %w", pat, err)
		}
		compiled = append(compiled, re)
	}
	return &Redactor{
		Patterns:    compiled,
		Replacement: replacement,
	}, nil
}

// Redact sanitizes text by replacing matches of all configured patterns.
func (r *Redactor) Redact(text string) string {
	if r == nil || len(r.Patterns) == 0 {
		return text
	}
	res := text
	for _, re := range r.Patterns {
		res = re.ReplaceAllString(res, r.Replacement)
	}
	return res
}

// Invocation represents the command line execution details for a control.
type Invocation struct {
	Executable      string               `json:"executable"`
	Arguments       []string             `json:"arguments"`
	Followups       []Invocation         `json:"-"`
	Cleanup         []string             `json:"-"`
	GitleaksReport  string               `json:"-"`
	ContinueOnError bool                 `json:"-"`
	RawCommandLine  string               `json:"-"`
	Env             []string             `json:"-"`
	Prefound        []report.LocatedLeak `json:"-"`
	Sources         []string             `json:"-"`
}

// BuildInvocation constructs the executable and arguments for a planned control.
func BuildInvocation(
	ctrl *PlannedControl,
	root string,
	platformRoot string,
	repoRoot string,
) (*Invocation, error) {
	if ctrl.Tool == nil || ctrl.Tool.Source == nil || *ctrl.Tool.Source == "" {
		return nil, errors.New("source executable absente du plan")
	}

	executable := *ctrl.Tool.Source
	command := ctrl.Tool.Command

	isPyRuntime := (ctrl.Tool != nil && ctrl.Tool.RuntimeManaged && isPythonTool(command)) ||
		(isPythonTool(command) && strings.Contains(strings.ToLower(filepath.Base(executable)), "python"))

	var catalogArgs []string
	if ctrl.Parameters != nil {
		if rawArgs, ok := ctrl.Parameters["arguments"]; ok {
			if argsSlice, ok := rawArgs.([]interface{}); ok {
				for _, a := range argsSlice {
					catalogArgs = append(catalogArgs, fmt.Sprintf("%v", a))
				}
			} else if argsStrSlice, ok := rawArgs.([]string); ok {
				catalogArgs = append(catalogArgs, argsStrSlice...)
			}
		}
	}

	relRoot, _ := filepath.Rel(repoRoot, root)
	filesInRoot, _ := discovery.CollectSources(repoRoot, filepath.ToSlash(relRoot), nil)

	var arguments []string
	var cleanup []string
	var gitleaksReport string

	switch command {
	case "ruff":
		pyFiles, skip := exclusiveFiles(filesInRoot, repoRoot, ctrl.ExcludeRoots, func(file string) bool {
			return strings.EqualFold(filepath.Ext(file), ".py")
		})
		if skip {
			return nil, coveredByNestedRoot()
		}
		if len(pyFiles) == 0 {
			return nil, errors.New("aucune source Python pour Ruff")
		}
		if len(catalogArgs) == 0 {
			return nil, errors.New("arguments Ruff absents du catalogue")
		}
		prefix := append([]string{}, catalogArgs...)
		if prefix[0] == "check" && !hasArg(prefix, "--output-format") {
			prefix = append(prefix, "--output-format", "json")
		}
		return invocationWithFiles(executable, prefix, pyFiles), nil

	case "pylint", "bandit":
		pyFiles, skip := exclusiveFiles(filesInRoot, repoRoot, ctrl.ExcludeRoots, func(file string) bool {
			return strings.EqualFold(filepath.Ext(file), ".py")
		})
		if skip {
			return nil, coveredByNestedRoot()
		}
		if len(pyFiles) == 0 {
			return nil, fmt.Errorf("aucune source Python pour %s", command)
		}
		prefix := append([]string{}, catalogArgs...)
		if command == "pylint" {
			if config := pylintConfig(repoRoot); config != "" {
				prefix = append(prefix, "--rcfile", config)
			}
			if !hasArg(prefix, "--output-format") && !hasArgPrefix(prefix, "--output-format=") {
				prefix = append(prefix, "--output-format=json")
			}
		}
		if command == "bandit" && !hasArg(prefix, "-f") && !hasArg(prefix, "--format") {
			prefix = append(prefix, "-f", "custom", "--msg-template", "{abspath}:{line}:{col}: {test_id} {severity}: {msg}")
		}
		if isPyRuntime {
			prefix = append([]string{"-m", pythonModuleName(command)}, prefix...)
		}
		return invocationWithFiles(executable, prefix, pyFiles), nil

	case "pytest":
		arguments = append(arguments, catalogArgs...)
		arguments = append(arguments, ignoreNestedArgs(repoRoot, ctrl.ExcludeRoots)...)
		arguments = append(arguments, root)
		if isPyRuntime {
			arguments = append([]string{"-m", "pytest"}, arguments...)
		}

	case "pip-audit":
		reqs, project := pythonDependencies(root)
		if len(reqs) == 0 && project == "" {
			return nil, &ControlSkip{
				Code:    "not_applicable",
				Message: "Aucun requirements*.txt ni pyproject.toml dans cette racine. L'environnement Python global n'est pas audité.",
			}
		}
		var prefound []report.LocatedLeak
		var pinned []string
		var sources []string
		for _, req := range reqs {
			exact, unpinned, splitErr := splitRequirements(req, repoRoot)
			if splitErr != nil {
				for _, path := range cleanup {
					_ = os.Remove(path)
				}
				return nil, splitErr
			}
			prefound = append(prefound, unpinned...)
			if len(exact) == 0 {
				continue
			}
			temp, writeErr := writePinnedRequirements(exact)
			if writeErr != nil {
				for _, path := range cleanup {
					_ = os.Remove(path)
				}
				return nil, writeErr
			}
			cleanup = append(cleanup, temp)
			pinned = append(pinned, temp)
			sources = append(sources, requirementSource(req, repoRoot))
		}
		if len(pinned) == 0 && project == "" {
			return &Invocation{Prefound: prefound, Cleanup: cleanup}, nil
		}
		if len(pinned) > 0 {
			arguments = append(arguments, dropFlags(catalogArgs, "--strict")...)
			if !hasArg(arguments, "--format") && !hasArg(arguments, "-f") {
				arguments = append(arguments, "--format", "json")
			}
			for _, req := range pinned {
				arguments = append(arguments, "-r", req)
			}
		} else {
			arguments = append(arguments, dropFlags(catalogArgs, "--strict", "--no-deps", "--disable-pip")...)
			if !hasArg(arguments, "--format") && !hasArg(arguments, "-f") {
				arguments = append(arguments, "--format", "json")
			}
			arguments = append(arguments, project)
			sources = []string{requirementSource(project, repoRoot)}
		}
		if isPyRuntime {
			arguments = append([]string{"-m", "pip_audit"}, arguments...)
		}
		return &Invocation{Executable: executable, Arguments: arguments, Cleanup: cleanup, Prefound: prefound, Sources: sources}, nil

	case "terraform", "tofu", "terragrunt":
		arguments = append(arguments, catalogArgs...)

	case "tflint":
		arguments = append(arguments, catalogArgs...)
		arguments = append(arguments, "--format", "json")

	case "shellcheck":
		shFiles, skip := exclusiveFiles(filesInRoot, repoRoot, ctrl.ExcludeRoots, func(file string) bool {
			return strings.EqualFold(filepath.Ext(file), ".sh")
		})
		if skip {
			return nil, coveredByNestedRoot()
		}
		if len(shFiles) == 0 {
			return nil, errors.New("aucun script Shell pour ShellCheck")
		}
		prefix := append([]string{"--format=json"}, catalogArgs...)
		return invocationWithFiles(executable, prefix, shFiles), nil

	case "hadolint":
		containerFiles, skip := exclusiveFiles(filesInRoot, repoRoot, ctrl.ExcludeRoots, discovery.IsContainerFile)
		if skip {
			return nil, coveredByNestedRoot()
		}
		if len(containerFiles) == 0 {
			return nil, errors.New("validation Compose non implementee par Hadolint")
		}
		return invocationWithFiles(executable, []string{"--format", "json"}, containerFiles), nil

	case "ansible-lint":
		arguments = append(arguments, catalogArgs...)
		arguments = append(arguments, root)
		if isPyRuntime {
			arguments = append([]string{"-m", "ansiblelint"}, arguments...)
		}

	case "yamllint":
		arguments = []string{"-f", "parsable"}
		configured := ""
		if ctrl.Parameters != nil {
			configured, _ = ctrl.Parameters["configuration"].(string)
		}
		if config := yamllintConfig(root, platformRoot, configured); config != "" {
			arguments = append(arguments, "-c", config)
		}
		arguments = append(arguments, root)
		if isPyRuntime {
			arguments = append([]string{"-m", "yamllint"}, arguments...)
		}

	case "eslint":
		eslintArgs := []string{"-f", "json"}
		var extraEnv []string
		if !eslintConfigured(repoRoot) {
			fallback, env, ferr := writeESLintFallback(executable, repoRoot)
			if ferr != nil {
				return nil, ferr
			}
			cleanup = append(cleanup, fallback)
			extraEnv = env
			eslintArgs = append([]string{"--no-config-lookup", "--no-error-on-unmatched-pattern", "-c", fallback}, eslintArgs...)
		}
		eslintArgs = append(eslintArgs, root)
		if inv, ok := nodeBinScript(executable, filepath.Join("..", "eslint", "bin", "eslint.js"), eslintArgs); ok {
			inv.Cleanup = cleanup
			inv.Env = extraEnv
			return &inv, nil
		}
		if strings.EqualFold(filepath.Ext(executable), ".cmd") || strings.EqualFold(filepath.Ext(executable), ".bat") {
			inv := windowsCmdScript(executable, eslintArgs)
			inv.Cleanup = cleanup
			inv.Env = extraEnv
			return &inv, nil
		}
		arguments = eslintArgs
		return &Invocation{Executable: executable, Arguments: arguments, Cleanup: cleanup, Env: extraEnv}, nil

	case "gitleaks":
		reportPath, configPath, sideErr := writeGitleaksSidecars()
		if sideErr != nil {
			return nil, sideErr
		}
		cleanup = []string{reportPath, configPath}
		gitleaksReport = reportPath
		arguments = []string{
			"detect", "--no-git", "--no-color", "--no-banner", "--redact",
			"--source", root,
			"--config", configPath,
			"--report-format", "json", "--report-path", reportPath,
		}

	case "tsc":
		projects := tsconfigProjects(repoRoot)
		if len(projects) == 0 {
			return nil, errors.New("aucun tsconfig.json pour la vérification de types")
		}
		first := tscInvocation(executable, projects[0])
		var followups []Invocation
		for _, project := range projects[1:] {
			followups = append(followups, tscInvocation(executable, project))
		}
		return &Invocation{Executable: first.Executable, Arguments: first.Arguments, Followups: followups, RawCommandLine: first.RawCommandLine}, nil

	case "rumdl":
		arguments = []string{"check", "--respect-gitignore=true", "--exclude", discovery.ToolExcludeGlobs()}
		if !markdownConfigPresent(repoRoot) {
			arguments = append(arguments, "--disable", "MD013")
		}
		arguments = append(arguments, root)

	case "pre-commit":
		hook, _ := ctrl.Parameters["hook"].(string)
		var mdFiles []string
		for _, f := range filesInRoot {
			if strings.EqualFold(filepath.Ext(f), ".md") {
				mdFiles = append(mdFiles, f)
			}
		}
		if len(mdFiles) == 0 {
			return nil, errors.New("aucun fichier Markdown pour le controle")
		}
		return invocationWithFiles(executable, []string{"run", hook, "--config", filepath.Join(platformRoot, ".pre-commit-config.yaml"), "--files"}, mdFiles), nil

	case "checkov":
		framework, _ := ctrl.Parameters["framework"].(string)
		if framework == "" {
			return nil, errors.New("framework Checkov absent du catalogue")
		}
		arguments = []string{"-d", root, "--framework", framework, "--quiet", "--output", "json"}
		for _, name := range discovery.SkipDirNames() {
			arguments = append(arguments, "--skip-path", name)
		}
		if isPyRuntime {
			arguments = append([]string{"-m", "checkov"}, arguments...)
		}

	case "trivy":
		var scanners []string
		if rawScanners, ok := ctrl.Parameters["scanners"].([]interface{}); ok {
			for _, s := range rawScanners {
				scanners = append(scanners, fmt.Sprintf("%v", s))
			}
		} else if strScanners, ok := ctrl.Parameters["scanners"].([]string); ok {
			scanners = strScanners
		}
		arguments = []string{
			"fs",
			"--scanners", strings.Join(scanners, ","),
			"--exit-code", "1",
			"--no-progress",
			"--skip-dirs", ".git",
			"--skip-dirs", ".venv",
			"--skip-dirs", ".tools",
			"--skip-dirs", "reports",
			"--skip-dirs", "testdata",
			"--skip-dirs", "fixtures",
			"--skip-dirs", "__snapshots__",
			"--skip-dirs", "node_modules",
			"--skip-dirs", "vendor",
			"--format", "json",
		}
		for _, nested := range ctrl.ExcludeRoots {
			arguments = append(arguments, "--skip-dirs", filepath.Join(canonicalOr(repoRoot), filepath.FromSlash(normalizePlanRoot(nested))))
		}
		arguments = append(arguments, root)

	case "Invoke-ScriptAnalyzer":
		if len(filesInRoot) == 0 {
			return nil, errors.New("aucun fichier PowerShell pour le controle")
		}
		filesJSON, _ := json.Marshal(filesInRoot)
		escapedFilesJSON := strings.ReplaceAll(string(filesJSON), "'", "''")
		escapedExec := strings.ReplaceAll(executable, "'", "''")
		settingsArg := powershellSettingsArg(ctrl, platformRoot)
		psCommand := fmt.Sprintf(
			"Set-StrictMode -Version Latest; $ErrorActionPreference = 'Stop'; if ('%s' -ne '' -and (Test-Path '%s' -PathType Leaf)) { Import-Module -Name '%s' -Force -ErrorAction SilentlyContinue }; $findings = @(); foreach ($file in ('%s' | ConvertFrom-Json)) { $tokens = $null; $parseErrors = $null; [Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$parseErrors) | Out-Null; if ($parseErrors.Count -gt 0) { foreach ($pe in $parseErrors) { $findings += [pscustomobject]@{ ScriptName = [IO.Path]::GetFileName($file); Line = $pe.Extent.StartLineNumber; RuleName = 'PowerShellSyntax'; Severity = 'Error'; Message = $pe.Message } } } elseif (Get-Command Invoke-ScriptAnalyzer -ErrorAction SilentlyContinue) { $findings += @(Invoke-ScriptAnalyzer -Path $file -Severity @('Error', 'Warning')%s -ErrorAction SilentlyContinue) } }; foreach ($f in $findings) { [pscustomobject]@{ file = $f.ScriptName; line = $f.Line; rule = $f.RuleName; severity = [string]$f.Severity; message = $f.Message } | ConvertTo-Json -Compress }; if (@($findings | Where-Object { $_.Severity -in @('Error', 'Warning') }).Count -gt 0) { exit 1 }; exit 0",
			escapedExec, escapedExec, escapedExec, escapedFilesJSON, settingsArg,
		)
		arguments = []string{
			"-NoProfile",
			"-ExecutionPolicy", "Bypass",
			"-Command", psCommand,
		}
		executable = powershellHost(runtime.GOOS, executable)

	default:
		return nil, fmt.Errorf("adaptateur de controle non implemente: %s", command)
	}

	return &Invocation{
		Executable:     executable,
		Arguments:      arguments,
		Followups:      nil,
		Cleanup:        cleanup,
		GitleaksReport: gitleaksReport,
	}, nil
}

func pytestCollectedNothing(command string, exitCode, leaks int) bool {
	return command == "pytest" && exitCode == 5 && leaks == 0
}

func pylintConfig(repoRoot string) string {
	for _, name := range []string{".pylintrc", "pylintrc", ".pylintrc.toml"} {
		path := filepath.Join(repoRoot, name)
		info, err := os.Stat(path)
		if err == nil && !info.IsDir() {
			return path
		}
	}
	for _, name := range []string{"pyproject.toml", "setup.cfg"} {
		path := filepath.Join(repoRoot, name)
		body, err := os.ReadFile(path)
		if err == nil && bytes.Contains(bytes.ToLower(body), []byte("pylint")) {
			return path
		}
	}
	return ""
}

func gitleaksAllowlist() string {
	names := discovery.SkipDirNames()
	var builder strings.Builder
	builder.WriteString("[extend]\nuseDefault = true\n\n[allowlist]\ndescription = \"Dependances et artefacts hors sources\"\npaths = [\n")
	for _, name := range names {
		fmt.Fprintf(&builder, "  '''(^|[\\\\/])%s([\\\\/]|$)''',\n", regexp.QuoteMeta(name))
	}
	builder.WriteString("  '''\\.(vsix|exe|dll|pdb|pyc|zip)$''',\n]\n")
	return builder.String()
}

func writeGitleaksSidecars() (string, string, error) {
	reportFile, err := os.CreateTemp("", "gitleaks-report-*.json")
	if err != nil {
		return "", "", err
	}
	reportPath := reportFile.Name()
	_ = reportFile.Close()
	configFile, err := os.CreateTemp("", "gitleaks-config-*.toml")
	if err != nil {
		_ = os.Remove(reportPath)
		return "", "", err
	}
	if _, err := configFile.WriteString(gitleaksAllowlist()); err != nil {
		path := configFile.Name()
		_ = configFile.Close()
		_ = os.Remove(path)
		_ = os.Remove(reportPath)
		return "", "", err
	}
	configPath := configFile.Name()
	if err := configFile.Close(); err != nil {
		_ = os.Remove(configPath)
		_ = os.Remove(reportPath)
		return "", "", err
	}
	return reportPath, configPath, nil
}

func readGitleaksFindings(path, repo string) []report.LocatedLeak {
	body, err := os.ReadFile(path)
	if err != nil || len(strings.TrimSpace(string(body))) == 0 {
		return nil
	}
	var rows []struct {
		Description string `json:"Description"`
		StartLine   int    `json:"StartLine"`
		StartColumn int    `json:"StartColumn"`
		File        string `json:"File"`
		RuleID      string `json:"RuleID"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil
	}
	leaks := make([]report.LocatedLeak, 0, len(rows))
	for _, row := range rows {
		if strings.TrimSpace(row.File) == "" {
			continue
		}
		file := relativeToRepo(repo, row.File)
		if discovery.PathHasSkippedDir(file) {
			continue
		}
		leaks = append(leaks, report.LocatedLeak{
			File:        file,
			Line:        row.StartLine,
			Column:      row.StartColumn,
			RuleID:      row.RuleID,
			Description: row.Description,
		})
	}
	return leaks
}

func relativeToRepo(repo, file string) string {
	cleaned := filepath.Clean(file)
	if filepath.IsAbs(cleaned) && repo != "" {
		if rel, err := filepath.Rel(repo, cleaned); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return filepath.ToSlash(rel)
		}
	}
	return filepath.ToSlash(cleaned)
}

func dropFlags(args []string, names ...string) []string {
	drop := map[string]bool{}
	for _, name := range names {
		drop[name] = true
	}
	out := make([]string, 0, len(args))
	for _, arg := range args {
		if !drop[arg] {
			out = append(out, arg)
		}
	}
	return out
}

func coveredByNestedRoot() error {
	return &ControlSkip{
		Code:    "not_applicable",
		Message: "Les fichiers de cette racine sont déjà couverts par une sous-racine du même outil.",
	}
}

func exclusiveFiles(files []string, repo string, nested []string, keep func(string) bool) ([]string, bool) {
	var matched []string
	for _, file := range files {
		if keep(file) {
			matched = append(matched, file)
		}
	}
	kept := omitNestedFiles(matched, repo, nested)
	return kept, len(matched) > 0 && len(kept) == 0
}

func omitNestedFiles(files []string, repo string, nested []string) []string {
	if len(nested) == 0 {
		return files
	}
	kept := make([]string, 0, len(files))
	for _, file := range files {
		if !fileInNestedRoot(file, repo, nested) {
			kept = append(kept, file)
		}
	}
	return kept
}

func fileInNestedRoot(file, repo string, nested []string) bool {
	repo = canonicalOr(repo)
	file = canonicalOr(file)
	rel, err := filepath.Rel(repo, file)
	if err != nil {
		rel = file
	}
	rel = strings.ToLower(filepath.ToSlash(rel))
	for _, root := range nested {
		root = strings.ToLower(normalizePlanRoot(root))
		if root == "." {
			continue
		}
		if rel == root || strings.HasPrefix(rel, root+"/") {
			return true
		}
	}
	return false
}

func ignoreNestedArgs(repo string, nested []string) []string {
	repo = canonicalOr(repo)
	var args []string
	for _, root := range nested {
		if normalizePlanRoot(root) == "." {
			continue
		}
		args = append(args, "--ignore", filepath.Join(repo, filepath.FromSlash(normalizePlanRoot(root))))
	}
	return args
}

func canonicalOr(path string) string {
	if resolved, err := osutil.CanonicalPath(path); err == nil && resolved != "" {
		return resolved
	}
	return path
}

func splitRequirements(path, repo string) ([]string, []report.LocatedLeak, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	rel := requirementSource(path, repo)
	var exact []string
	var leaks []report.LocatedLeak
	for number, line := range strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n") {
		name, pinned, ok := classifyRequirement(line)
		if !ok {
			continue
		}
		if pinned {
			exact = append(exact, strings.TrimSpace(stripRequirementComment(line)))
			continue
		}
		leaks = append(leaks, report.LocatedLeak{
			File: rel, Line: number + 1, Column: 1,
			RuleID: "non-épinglée", Description: name + " n'a pas de version exacte.", Severity: "medium",
		})
	}
	return exact, leaks, nil
}

func requirementSource(path, repo string) string {
	return relativeToRepo(canonicalOr(repo), canonicalOr(path))
}

func pipAuditResolutionReason(output string) string {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)could not find a version that satisfies the requirement[^\n]{0,180}`),
		regexp.MustCompile(`(?i)no matching distribution found for[^\n]{0,180}`),
		regexp.MustCompile(`(?i)failed to (?:install|resolve)[^\n]{0,180}`),
		regexp.MustCompile(`(?i)resolution impossible[^\n]{0,180}`),
	}
	for _, pattern := range patterns {
		if match := strings.TrimSpace(pattern.FindString(output)); match != "" {
			return strings.Trim(match, " \t:.")
		}
	}
	return ""
}

func stripRequirementComment(line string) string {
	if index := strings.Index(line, " #"); index >= 0 {
		return line[:index]
	}
	return line
}

func classifyRequirement(line string) (string, bool, bool) {
	raw := strings.TrimSpace(stripRequirementComment(line))
	if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "-") {
		return "", false, false
	}
	if index := strings.Index(raw, ";"); index >= 0 {
		raw = strings.TrimSpace(raw[:index])
	}
	name := raw
	for _, separator := range []string{"===", "==", ">=", "<=", "~=", "!=", ">", "<", "["} {
		if index := strings.Index(raw, separator); index > 0 {
			name = strings.TrimSpace(raw[:index])
			break
		}
	}
	if name == "" {
		return "", false, false
	}
	return name, strings.Contains(raw, "=="), true
}

func writePinnedRequirements(lines []string) (string, error) {
	file, err := os.CreateTemp("", "compliance-requirements-*.txt")
	if err != nil {
		return "", err
	}
	if _, err := file.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return "", err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(file.Name())
		return "", err
	}
	return file.Name(), nil
}

func dedupeLeaks(leaks []report.LocatedLeak) []report.LocatedLeak {
	seen := map[string]bool{}
	out := make([]report.LocatedLeak, 0, len(leaks))
	for _, leak := range leaks {
		key := leak.File + "\x00" + strconv.Itoa(leak.Line) + "\x00" + leak.RuleID + "\x00" + leak.Description
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, leak)
	}
	return out
}

func pythonDependencies(root string) (reqs []string, project string) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, ""
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "requirements") && strings.HasSuffix(lower, ".txt") {
			reqs = append(reqs, filepath.Join(root, name))
		}
	}
	sort.Strings(reqs)
	candidate := filepath.Join(root, "pyproject.toml")
	if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
		project = candidate
	}
	return reqs, project
}

func yamllintConfig(root, platformRoot, configured string) string {
	names := []string{}
	if strings.TrimSpace(configured) != "" {
		names = append(names, configured)
	}
	names = append(names, ".yamllint.yml", ".yamllint.yaml", ".yamllint")
	seen := map[string]bool{}
	var candidates []string
	for _, name := range names {
		add := func(path string) {
			if path == "" || seen[path] {
				return
			}
			seen[path] = true
			candidates = append(candidates, path)
		}
		if filepath.IsAbs(name) {
			add(name)
			continue
		}
		add(filepath.Join(root, name))
		add(filepath.Join(platformRoot, name))
	}
	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

func nodeModulesDir(executable string) string {
	dir := filepath.Dir(executable)
	for i := 0; i < 6; i++ {
		if strings.EqualFold(filepath.Base(dir), "node_modules") {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

func writeESLintFallback(executable, repoRoot string) (string, []string, error) {
	file, err := os.CreateTemp("", "compliance-eslint-*.cjs")
	if err != nil {
		return "", nil, err
	}
	if _, err := file.Write(eslintFallbackSource); err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return "", nil, err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(file.Name())
		return "", nil, err
	}
	var paths []string
	if info, err := os.Stat(filepath.Join(repoRoot, "node_modules")); err == nil && info.IsDir() {
		paths = append(paths, filepath.Join(repoRoot, "node_modules"))
	}
	if modules := nodeModulesDir(executable); modules != "" {
		paths = append(paths, modules)
	}
	var env []string
	if len(paths) > 0 {
		env = []string{"NODE_PATH=" + strings.Join(paths, string(os.PathListSeparator))}
	}
	return file.Name(), env, nil
}

func hasArg(args []string, name string) bool {
	for _, arg := range args {
		if arg == name {
			return true
		}
	}
	return false
}

func hasArgPrefix(args []string, prefix string) bool {
	for _, arg := range args {
		if strings.HasPrefix(arg, prefix) {
			return true
		}
	}
	return false
}

func argWidth(value string) int {
	width := len(value) + 1
	if strings.ContainsAny(value, " \t\"") {
		width += 2
	}
	return width
}

// splitCommandArgs keeps each command line under the Windows CreateProcess limit.
func splitCommandArgs(executable string, prefix, files []string) [][]string {
	const limit = 24000
	base := len(executable) + 1
	for _, arg := range prefix {
		base += argWidth(arg)
	}
	var batches [][]string
	var current []string
	size := base
	flush := func() {
		if len(current) == 0 {
			return
		}
		args := make([]string, 0, len(prefix)+len(current))
		args = append(args, prefix...)
		args = append(args, current...)
		batches = append(batches, args)
		current = nil
		size = base
	}
	for _, file := range files {
		width := argWidth(file)
		if len(current) > 0 && size+width > limit {
			flush()
		}
		current = append(current, file)
		size += width
	}
	flush()
	if len(batches) == 0 {
		return [][]string{append([]string{}, prefix...)}
	}
	return batches
}

func invocationWithFiles(executable string, prefix, files []string) *Invocation {
	batches := splitCommandArgs(executable, prefix, files)
	followups := make([]Invocation, 0, len(batches)-1)
	for _, args := range batches[1:] {
		followups = append(followups, Invocation{Executable: executable, Arguments: args, ContinueOnError: true})
	}
	return &Invocation{
		Executable:      executable,
		Arguments:       batches[0],
		Followups:       followups,
		ContinueOnError: len(batches) > 1,
	}
}

func anchorLeaks(leaks []report.LocatedLeak, repo, execRoot string) []report.LocatedLeak {
	for i := range leaks {
		if leaks[i].File == "" {
			continue
		}
		leaks[i].File = anchorFindingPath(repo, execRoot, leaks[i].File)
	}
	return leaks
}

// anchorFindingPath rebuilds a tool path that is relative to the control working
// directory. A leading slash or backslash is not a path from the drive root.
func anchorFindingPath(repo, execRoot, file string) string {
	cleaned := strings.TrimSpace(strings.Trim(file, `"'`))
	if cleaned == "" {
		return filepath.ToSlash(relativeToRepo(repo, execRoot))
	}
	if pathInsideRepo(repo, cleaned) {
		return relativeToRepo(repo, cleaned)
	}
	slash := filepath.ToSlash(cleaned)
	slash = strings.TrimPrefix(slash, "./")
	if vol := filepath.VolumeName(cleaned); vol != "" {
		slash = strings.TrimPrefix(filepath.ToSlash(cleaned), filepath.ToSlash(vol))
	}
	slash = strings.TrimLeft(slash, "/")
	if slash == "" || slash == "." {
		return filepath.ToSlash(relativeToRepo(repo, execRoot))
	}
	relRoot := filepath.ToSlash(relativeToRepo(repo, execRoot))
	if relRoot != "" && relRoot != "." && (slash == relRoot || strings.HasPrefix(slash, relRoot+"/")) {
		return slash
	}
	repoFile := filepath.Join(repo, filepath.FromSlash(slash))
	if info, err := os.Stat(repoFile); err == nil && !info.IsDir() && pathInsideRepo(repo, repoFile) {
		return relativeToRepo(repo, repoFile)
	}
	return relativeToRepo(repo, filepath.Join(execRoot, filepath.FromSlash(slash)))
}

func windowsCmdScript(script string, args []string) Invocation {
	comspec := os.Getenv("COMSPEC")
	if comspec == "" {
		comspec = "cmd.exe"
	}
	all := append([]string{script}, args...)
	spaced := false
	for _, part := range all {
		if strings.ContainsAny(part, " \t\"") {
			spaced = true
			break
		}
	}
	if !spaced {
		return Invocation{Executable: comspec, Arguments: append([]string{"/d", "/s", "/c", script}, args...)}
	}
	quoted := make([]string, 0, len(all))
	for _, part := range all {
		quoted = append(quoted, quoteCmd(part))
	}
	comspecText := comspec
	if strings.ContainsAny(comspec, " \t") {
		comspecText = quoteCmd(comspec)
	}
	return Invocation{
		Executable:     comspec,
		Arguments:      []string{"/d", "/s", "/c"},
		RawCommandLine: comspecText + " /d /s /c \"" + strings.Join(quoted, " ") + "\"",
	}
}

func quoteCmd(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

func pathInsideRepo(repo, file string) bool {
	if repo == "" || !filepath.IsAbs(file) {
		return false
	}
	rel, err := filepath.Rel(repo, file)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func stripANSI(value string) string {
	return ansiEscape.ReplaceAllString(value, "")
}

func withoutColor(env []string) []string {
	kept := make([]string, 0, len(env)+2)
	for _, item := range env {
		key, _, _ := strings.Cut(item, "=")
		if strings.EqualFold(key, "NO_COLOR") || strings.EqualFold(key, "CLICOLOR") {
			continue
		}
		kept = append(kept, item)
	}
	return append(kept, "NO_COLOR=1", "CLICOLOR=0")
}

func tscInvocation(executable, project string) Invocation {
	arguments := []string{"--noEmit", "--pretty", "false", "--project", project}
	if inv, ok := nodeBinScript(executable, filepath.Join("..", "typescript", "bin", "tsc"), arguments); ok {
		return inv
	}
	ext := strings.ToLower(filepath.Ext(executable))
	if ext == ".cmd" || ext == ".bat" {
		return windowsCmdScript(executable, arguments)
	}
	return Invocation{Executable: executable, Arguments: arguments}
}

func findNodeForScript(cmdPath string) string {
	curr := filepath.Dir(cmdPath)
	for i := 0; i < 4; i++ {
		if runtime.GOOS == "windows" {
			cand := filepath.Join(curr, "node.exe")
			if info, err := os.Stat(cand); err == nil && !info.IsDir() {
				return cand
			}
		} else {
			for _, name := range []string{"bin/node", "node"} {
				cand := filepath.Join(curr, filepath.FromSlash(name))
				if info, err := os.Stat(cand); err == nil && !info.IsDir() {
					return cand
				}
			}
		}
		parent := filepath.Dir(curr)
		if parent == curr {
			break
		}
		curr = parent
	}

	cacheNode := filepath.Join(osutil.DefaultToolCacheDir(), "node")
	if runtime.GOOS == "windows" {
		cand := filepath.Join(cacheNode, "node.exe")
		if info, err := os.Stat(cand); err == nil && !info.IsDir() {
			return cand
		}
	} else {
		cand := filepath.Join(cacheNode, "bin", "node")
		if info, err := os.Stat(cand); err == nil && !info.IsDir() {
			return cand
		}
	}

	return osutil.LookupExecutable("node")
}

func nodeBinScript(cmdPath, relativeJS string, args []string) (Invocation, bool) {
	script := filepath.Clean(filepath.Join(filepath.Dir(cmdPath), relativeJS))
	info, err := os.Stat(script)
	if err != nil || info.IsDir() {
		return Invocation{}, false
	}
	node := findNodeForScript(cmdPath)
	if node == "" {
		return Invocation{}, false
	}
	return Invocation{Executable: node, Arguments: append([]string{script}, args...)}, true
}

func isPythonTool(command string) bool {
	switch command {
	case "checkov", "bandit", "pylint", "pytest", "pip-audit", "yamllint", "ansible-lint":
		return true
	default:
		return false
	}
}

func pythonModuleName(command string) string {
	switch command {
	case "pip-audit":
		return "pip_audit"
	case "ansible-lint":
		return "ansiblelint"
	default:
		return command
	}
}

func tsconfigProjects(repoRoot string) []string {
	var projects []string
	_ = filepath.WalkDir(repoRoot, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		name := entry.Name()
		if entry.IsDir() {
			switch strings.ToLower(name) {
			case "node_modules", ".git", "dist", "build", ".tools", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "tsconfig") && strings.HasSuffix(lower, ".json") {
			projects = append(projects, path)
		}
		return nil
	})
	sort.Strings(projects)
	return projects
}

func explainNonExecution(ctrl *PlannedControl) string {
	command := ""
	if ctrl.Tool != nil {
		command = ctrl.Tool.Command
	}
	switch ctrl.Applicability {
	case "technology_absent":
		return "Technologie absente : aucun fichier correspondant dans la cible."
	case "capability_unavailable":
		return "Pas de contrôle exécutable au catalogue pour cette capacité."
	case "repository_unconfigured":
		if ctrl.Reason != "" {
			return ctrl.Reason
		}
		return "Le contrôle n'a pas pu s'exécuter : configuration ou dépendances du dépôt absentes."
	case "tool_unavailable":
		if ctrl.Reason != "" {
			return ctrl.Reason
		}
		if command == "" {
			command = "outil"
		}
		return fmt.Sprintf("Outil manquant : %s. L'extension peut l'installer depuis le manifeste, après accord, dans le dossier utilisateur.", command)
	case "platform_unsupported":
		if ctrl.Reason != "" {
			return ctrl.Reason
		}
		return "Contrôle non qualifié pour cette plateforme."
	case "platform_unavailable":
		if ctrl.Reason != "" {
			return ctrl.Reason
		}
		return "Outil non disponible sur cette plateforme."
	case "user_disabled":
		return "Ignoré par un réglage local de l'extension, pas par le dépôt."
	case "permission_denied":
		if ctrl.Reason != "" {
			return ctrl.Reason
		}
		return "Autorisation refusée pour cet effet."
	default:
		if ctrl.Reason != "" {
			return ctrl.Reason
		}
		return "Contrôle non exécuté."
	}
}

func powershellSettingsArg(ctrl *PlannedControl, platformRoot string) string {
	if ctrl == nil || ctrl.Parameters == nil {
		return ""
	}
	settings, _ := ctrl.Parameters["settings"].(string)
	settings = strings.TrimSpace(settings)
	if settings == "" {
		return ""
	}
	if !filepath.IsAbs(settings) {
		settings = filepath.Join(platformRoot, settings)
	}
	info, err := os.Stat(settings)
	if err != nil || info.IsDir() {
		return ""
	}
	escaped := strings.ReplaceAll(settings, "'", "''")
	return fmt.Sprintf(" -Settings '%s'", escaped)
}

// powershellHost selects the PowerShell executable for the target OS.
// goos is explicit so Darwin behavior can be tested on any host.
func powershellHost(goos, source string) string {
	lower := strings.ToLower(source)
	if strings.HasSuffix(lower, "pwsh") || strings.HasSuffix(lower, "pwsh.exe") {
		if goos == "windows" && !strings.HasSuffix(lower, ".exe") && !strings.Contains(source, `\`) && !strings.Contains(source, `/`) {
			return "pwsh.exe"
		}
		return source
	}
	if goos == "windows" {
		return "powershell.exe"
	}
	if goos == runtime.GOOS {
		if found := osutil.LookupExecutable("pwsh"); found != "" {
			return found
		}
	}
	return "pwsh"
}

// ProbeToolVersion runs the version command of a tool and returns the parsed version string.
func ProbeToolVersion(
	ctx context.Context,
	executable string,
	command string,
	dir string,
	timeout time.Duration,
) (string, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	args := []string{"--version"}
	if command == "terraform" || command == "tofu" || command == "opentofu" {
		args = []string{"version"}
	}

	exe, probeArgs := osutil.ScriptCommand(executable, args)
	res, err := osutil.RunBounded(ctx, osutil.CommandSpec{
		Executable:       exe,
		Args:             probeArgs,
		WorkingDirectory: dir,
		Limits: osutil.ProcessLimits{
			Timeout:        timeout,
			MaxOutputBytes: 64 * 1024,
		},
	})
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("probe exit code %d: %s", res.ExitCode, res.Stderr)
	}

	out := res.Stdout + " " + res.Stderr
	match := reVersionFinder.FindString(out)
	if match == "" {
		return "", errors.New("version de l outil non identifiable")
	}
	return match, nil
}

// ExecutionOptions configures execution of a compliance plan.
type ExecutionOptions struct {
	PlatformRoot   string
	GlobalTimeout  time.Duration
	Redactor       *Redactor
	OnControlStart func(ctrl *PlannedControl)
	OnControlDone  func(ctrl *PlannedControl, res *report.ExecutionResult)
}

// ExecuteCompliancePlan runs all planned controls in topological order and produces ExecutionResults.
func ExecuteCompliancePlan(
	ctx context.Context,
	plan *report.ExecutionPlan,
	controls []*PlannedControl,
	opts ExecutionOptions,
) ([]report.ExecutionResult, error) {
	globalTimeout := opts.GlobalTimeout
	if globalTimeout <= 0 {
		globalTimeout = time.Duration(plan.Budgets.TimeoutSeconds) * time.Second
	}
	if globalTimeout <= 0 {
		globalTimeout = 1800 * time.Second
	}

	planStart := time.Now()
	completed := make(map[string]*report.ExecutionResult)
	var results []report.ExecutionResult

	for _, ctrl := range controls {
		ctrlStart := time.Now()
		startTimeStr := ctrlStart.UTC().Format(time.RFC3339)

		var toolVer *string
		if ctrl.Tool != nil && ctrl.Tool.Version != nil {
			toolVer = ctrl.Tool.Version
		}

		res := report.ExecutionResult{
			ControlId:        ctrl.ID,
			ControlCatalogId: ctrl.ControlCatalogID,
			Name:             ctrl.Name,
			Technology:       ctrl.Technology,
			Capability:       ctrl.Capability,
			Root:             ctrl.Root,
			Severity:         ctrl.Severity,
			Status:           "skipped",
			ExecutionStart:   startTimeStr,
			ExecutionEnd:     startTimeStr,
			DurationMs:       0,
			ToolVersion:      toolVer,
			Stdout:           "",
			Stderr:           "",
			ExitCode:         nil,
			OutputTruncated:  false,
			Critical:         false,
			Diagnostics:      make([]report.Diagnostic, 0),
		}

		if ctx.Err() != nil {
			res.Status = "skipped"
			res.Diagnostics = append(res.Diagnostics, report.Diagnostic{
				Code:     "cancelled_before_start",
				Message:  "Controle non lance apres annulation.",
				Critical: false,
			})
			ctrlEnd := time.Now()
			res.ExecutionEnd = ctrlEnd.UTC().Format(time.RFC3339)
			res.DurationMs = ctrlEnd.Sub(ctrlStart).Milliseconds()
			completed[ctrl.ID] = &res
			results = append(results, res)
			if opts.OnControlDone != nil {
				opts.OnControlDone(ctrl, &res)
			}
			continue
		}

		var failedDeps []string
		for _, dep := range ctrl.Dependencies {
			depRes, ok := completed[dep]
			if !ok || depRes.Status != "success" {
				failedDeps = append(failedDeps, dep)
			}
		}

		if ctrl.Applicability == "applicable" && len(failedDeps) > 0 {
			if ctrl.Required {
				res.Status = "error"
				res.Critical = true
			} else {
				res.Status = "skipped"
			}
			res.Diagnostics = append(res.Diagnostics, report.Diagnostic{
				Code:     "dependency_failed",
				Message:  fmt.Sprintf("Prerequis non satisfaits: %s", strings.Join(failedDeps, ", ")),
				Critical: res.Critical,
			})
		} else if ctrl.Applicability == "applicable" && time.Since(planStart) >= globalTimeout {
			res.Status = "error"
			res.Critical = ctrl.Required
			res.Diagnostics = append(res.Diagnostics, report.Diagnostic{
				Code:     "global_timeout",
				Message:  fmt.Sprintf("Budget global depasse: %d secondes.", int(globalTimeout.Seconds())),
				Critical: res.Critical,
			})
		} else if ctrl.Applicability != "applicable" {
			res.Status = "skipped"
			res.Critical = false
			code := ctrl.ReasonCode
			if code == "" {
				code = ctrl.Applicability
			}
			msg := explainNonExecution(ctrl)
			res.Diagnostics = append(res.Diagnostics, report.Diagnostic{
				Code:     code,
				Message:  msg,
				Critical: false,
			})
		} else {
			if opts.OnControlStart != nil {
				opts.OnControlStart(ctrl)
			}
			execRoot := filepath.Clean(filepath.Join(plan.Repository, filepath.FromSlash(ctrl.Root)))
			prefix := filepath.Clean(plan.Repository) + string(filepath.Separator)
			if execRoot != filepath.Clean(plan.Repository) && !strings.HasPrefix(strings.ToLower(execRoot), strings.ToLower(prefix)) {
				res.Status = "error"
				res.Critical = ctrl.Required
				res.Diagnostics = append(res.Diagnostics, report.Diagnostic{
					Code:     "execution_error",
					Message:  "Racine d execution hors depot.",
					Critical: res.Critical,
				})
			} else if fi, err := os.Stat(execRoot); err != nil || !fi.IsDir() {
				res.Status = "error"
				res.Critical = ctrl.Required
				res.Diagnostics = append(res.Diagnostics, report.Diagnostic{
					Code:     "execution_error",
					Message:  "Racine d execution absente.",
					Critical: res.Critical,
				})
			} else {
				inv, invErr := BuildInvocation(ctrl, execRoot, opts.PlatformRoot, plan.Repository)
				if inv != nil {
					defer func() {
						for _, path := range inv.Cleanup {
							_ = os.Remove(path)
						}
					}()
				}
				var skipped *ControlSkip
				if errors.As(invErr, &skipped) {
					res.Status = "skipped"
					res.Diagnostics = append(res.Diagnostics, report.Diagnostic{
						Code:     skipped.Code,
						Message:  skipped.Message,
						Critical: false,
					})
				} else if invErr != nil {
					res.Status = "error"
					res.Critical = ctrl.Required
					res.Diagnostics = append(res.Diagnostics, report.Diagnostic{
						Code:     "execution_error",
						Message:  invErr.Error(),
						Critical: res.Critical,
					})
				} else {
					ctrlTimeout := time.Duration(ctrl.Timeout) * time.Second
					remainingPlan := globalTimeout - time.Since(planStart)
					remainingCtrl := ctrlTimeout - time.Since(ctrlStart)
					effectiveTimeout := remainingCtrl
					if remainingPlan < effectiveTimeout {
						effectiveTimeout = remainingPlan
					}

					if effectiveTimeout <= 0 {
						res.Status = "error"
						res.Critical = ctrl.Required
						res.Diagnostics = append(res.Diagnostics, report.Diagnostic{
							Code:     "timeout",
							Message:  "Budget du controle depasse avant execution.",
							Critical: res.Critical,
						})
					} else if inv.Executable == "" {
						res.Leaks = anchorLeaks(dedupeLeaks(inv.Prefound), plan.Repository, execRoot)
						code := 0
						if len(res.Leaks) > 0 {
							code = 1
							res.Status = "fail"
							res.Diagnostics = append(res.Diagnostics, report.Diagnostic{
								Code:     "unpinned_requirements",
								Message:  fmt.Sprintf("%d dépendance(s) sans version exacte. Le fichier et la ligne sont dans le contrôle.", len(res.Leaks)),
								Critical: false,
							})
						} else {
							res.Status = "success"
						}
						res.ExitCode = &code
					} else {
						if res.ToolVersion == nil && ctrl.Tool != nil && ctrl.Tool.Command != "" {
							ver, verErr := ProbeToolVersion(ctx, inv.Executable, ctrl.Tool.Command, execRoot, 5*time.Second)
							if verErr == nil && ver != "" {
								res.ToolVersion = &ver
							}
						}

						calls := append([]Invocation{*inv}, inv.Followups...)
						var stdoutBuf, stderrBuf strings.Builder
						exitCode := 0
						var ran time.Duration
						var truncated, cancelled, timedOut bool
						var procErr error
						for _, call := range calls {
							exe, args := call.Executable, call.Arguments
							if call.RawCommandLine == "" {
								exe, args = osutil.ScriptCommand(call.Executable, call.Arguments)
							}
							env := withoutColor(osutil.AugmentedEnviron())
							if len(call.Env) > 0 {
								env = append(env, call.Env...)
							}
							procRes, err := osutil.RunBounded(ctx, osutil.CommandSpec{
								Executable:       exe,
								Args:             args,
								CommandLine:      call.RawCommandLine,
								WorkingDirectory: execRoot,
								Env:              env,
								Limits: osutil.ProcessLimits{
									Timeout:        effectiveTimeout,
									MaxOutputBytes: ctrl.MaxOutputBytes,
								},
							})
							if err != nil {
								procErr = err
								break
							}
							if stdoutBuf.Len() > 0 && procRes.Stdout != "" {
								stdoutBuf.WriteString("\n")
							}
							stdoutBuf.WriteString(procRes.Stdout)
							if procRes.Stderr != "" {
								if stderrBuf.Len() > 0 {
									stderrBuf.WriteString("\n")
								}
								stderrBuf.WriteString(procRes.Stderr)
							}
							truncated = truncated || procRes.OutputTruncated
							ran += procRes.Duration
							if exitCode == 0 && procRes.ExitCode != 0 {
								exitCode = procRes.ExitCode
							}
							cancelled = procRes.Cancelled
							timedOut = procRes.TimedOut
							if cancelled || timedOut || (procRes.ExitCode != 0 && !call.ContinueOnError) {
								break
							}
						}
						procRes := &osutil.ProcessResult{
							Stdout:          stdoutBuf.String(),
							Stderr:          stderrBuf.String(),
							ExitCode:        exitCode,
							Duration:        ran,
							OutputTruncated: truncated,
							TimedOut:        timedOut,
							Cancelled:       cancelled,
						}

						if procErr != nil {
							res.Status = "error"
							res.Critical = ctrl.Required
							res.Diagnostics = append(res.Diagnostics, report.Diagnostic{
								Code:     "process_error",
								Message:  procErr.Error(),
								Critical: res.Critical,
							})
						} else {
							exitCode := procRes.ExitCode
							res.ExitCode = &exitCode
							stdout := stripANSI(procRes.Stdout)
							stderr := stripANSI(procRes.Stderr)
							if opts.Redactor != nil {
								stdout = opts.Redactor.Redact(stdout)
								stderr = opts.Redactor.Redact(stderr)
							}
							res.Stdout = stdout
							res.Stderr = stderr
							res.OutputTruncated = procRes.OutputTruncated
							if inv.GitleaksReport != "" {
								res.Leaks = readGitleaksFindings(inv.GitleaksReport, plan.Repository)
							}
							if ctrl.Tool != nil && ctrl.Tool.Command == "rumdl" {
								res.Leaks = append(res.Leaks, parseRumdlOutput(stdout, plan.Repository)...)
							} else if ctrl.Tool != nil {
								parsed := stdout
								switch ctrl.Tool.Command {
								case "pip-audit", "yamllint", "bandit":
									parsed = stdout + "\n" + stderr
								}
								res.Leaks = append(res.Leaks, parseToolFindings(ctrl.Tool.Command, parsed, plan.Repository)...)
							}
							res.Leaks = append(res.Leaks, inv.Prefound...)
							if ctrl.Tool != nil && ctrl.Tool.Command == "pip-audit" && exitCode != 0 {
								if reason := pipAuditResolutionReason(stdout + "\n" + stderr); reason != "" {
									for _, file := range inv.Sources {
										res.Leaks = append(res.Leaks, report.LocatedLeak{
											File: file, Line: 1, Column: 1,
											RuleID: "résolution", Description: reason, Severity: "medium",
										})
									}
								}
							}
							res.Leaks = dedupeLeaks(res.Leaks)
							res.Leaks = anchorLeaks(res.Leaks, plan.Repository, execRoot)

							if res.OutputTruncated {
								res.Diagnostics = append(res.Diagnostics, report.Diagnostic{
									Code:     "output_truncated",
									Message:  "Sorties tronquees par la limite de capture du controle.",
									Critical: false,
								})
							}

							if procRes.Cancelled {
								res.Status = "skipped"
								res.Diagnostics = append(res.Diagnostics, report.Diagnostic{
									Code:     "cancelled_during_execution",
									Message:  "Arbre du controle termine apres annulation.",
									Critical: false,
								})
							} else if procRes.TimedOut {
								res.Status = "error"
								res.Critical = ctrl.Required
								res.Diagnostics = append(res.Diagnostics, report.Diagnostic{
									Code:     "timeout",
									Message:  fmt.Sprintf("Delai depasse apres %v.", procRes.Duration),
									Critical: res.Critical,
								})
							} else if exitCode == 0 && len(res.Leaks) == 0 {
								res.Status = "success"
							} else if ctrl.Tool != nil && pytestCollectedNothing(ctrl.Tool.Command, exitCode, len(res.Leaks)) {
								res.Status = "success"
								res.Diagnostics = append(res.Diagnostics, report.Diagnostic{
									Code:     "no_tests_collected",
									Message:  "Aucun test collecté dans cette racine. Ce n'est pas un échec de conformité.",
									Critical: false,
								})
							} else {
								res.Status = "fail"
								message := fmt.Sprintf("Controle en echec (code %d).", exitCode)
								if len(res.Leaks) > 0 {
									kind := "finding(s)"
									if ctrl.Tool != nil && ctrl.Tool.Command == "gitleaks" {
										kind = "fuite(s)"
									}
									message = fmt.Sprintf("%d %s : fichier, ligne et règle dans le contrôle (code %d).", len(res.Leaks), kind, exitCode)
								}
								res.Diagnostics = append(res.Diagnostics, report.Diagnostic{
									Code:     "exit_nonzero",
									Message:  message,
									Critical: false,
								})
							}
						}
					}
				}
			}
		}

		ctrlEnd := time.Now()
		res.ExecutionEnd = ctrlEnd.UTC().Format(time.RFC3339)
		res.DurationMs = ctrlEnd.Sub(ctrlStart).Milliseconds()
		completed[ctrl.ID] = &res
		results = append(results, res)

		if opts.OnControlDone != nil {
			opts.OnControlDone(ctrl, &res)
		}
	}

	return results, nil
}

// PipelineOptions configures execution of the single Python pipeline.
type PipelineOptions struct {
	RepoRoot        string
	RuffPath        string
	BanditPath      string
	BanditArgs      []string // optional override (defaults to ["-q"])
	BanditEnv       []string // optional extra env vars (e.g. PYTHONPATH)
	CABundlePath    string   // Enterprise root CA bundle injected tool-by-tool
	Timeout         time.Duration
	MaxOutputBytes  int64
	ProgressHandler func(controlID, status string)
}

// RunPythonPipeline executes Ruff format, Ruff check, and Bandit on discovered Python files.
func RunPythonPipeline(ctx context.Context, opts PipelineOptions) (*report.Report, error) {
	startTime := time.Now()

	discStart := time.Now()
	discResult, err := discovery.DiscoverPython(opts.RepoRoot)
	if err != nil {
		return nil, fmt.Errorf("discovery échouée: %w", err)
	}
	discoveryMs := time.Since(discStart).Milliseconds()

	var pyFiles []string
	if len(discResult.Technologies) > 0 {
		for _, ev := range discResult.Technologies[0].Evidence {
			pyFiles = append(pyFiles, filepath.Join(opts.RepoRoot, filepath.FromSlash(ev)))
		}
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 300 * time.Second
	}
	maxOutput := opts.MaxOutputBytes
	if maxOutput <= 0 {
		maxOutput = 1024 * 1024
	}

	planControls := []interface{}{
		map[string]interface{}{"id": "python.format.ruff", "name": "Python format", "technology": "python", "capability": "formatting", "required": true},
		map[string]interface{}{"id": "python.lint.ruff", "name": "Python Ruff lint", "technology": "python", "capability": "linting", "required": true},
		map[string]interface{}{"id": "python.security.bandit", "name": "Python security", "technology": "python", "capability": "security", "required": true},
	}

	execPlan := report.ExecutionPlan{
		SchemaVersion: 1,
		Repository:    opts.RepoRoot,
		Budgets: report.Budgets{
			TimeoutSeconds:          int(timeout.Seconds()),
			MaxOutputBytesPerStream: maxOutput,
			MaxControls:             len(planControls),
		},
		Permissions: report.Permissions{
			Network:       false,
			CodeExecution: false,
		},
		Controls: planControls,
	}

	var results []report.ExecutionResult

	if len(pyFiles) == 0 {
		now := time.Now().UTC().Format(time.RFC3339)
		for _, pc := range planControls {
			pcm := pc.(map[string]interface{})
			id := pcm["id"].(string)
			name := pcm["name"].(string)
			cap := pcm["capability"].(string)
			catalogId := id
			results = append(results, report.ExecutionResult{
				ControlId:        id,
				ControlCatalogId: &catalogId,
				Name:             name,
				Technology:       "python",
				Capability:       cap,
				Root:             ".",
				Severity:         "medium",
				Status:           "skipped",
				ExecutionStart:   now,
				ExecutionEnd:     now,
				DurationMs:       0,
				Stdout:           "",
				Stderr:           "",
				ExitCode:         nil,
				OutputTruncated:  false,
				Critical:         false,
				Diagnostics: []report.Diagnostic{
					{Code: "not_applicable", Message: "Aucune source Python trouvée dans le dépôt.", Critical: false},
				},
			})
		}
	} else {
		steps := []struct {
			id           string
			name         string
			cap          string
			severity     string
			toolPath     string
			baseArgs     []string
			isPythonTool bool
		}{
			{
				id:           "python.format.ruff",
				name:         "Python format",
				cap:          "formatting",
				severity:     "medium",
				toolPath:     opts.RuffPath,
				baseArgs:     []string{"format", "--check", "--no-cache"},
				isPythonTool: false,
			},
			{
				id:           "python.lint.ruff",
				name:         "Python Ruff lint",
				cap:          "linting",
				severity:     "medium",
				toolPath:     opts.RuffPath,
				baseArgs:     []string{"check", "--no-cache"},
				isPythonTool: false,
			},
			{
				id:           "python.security.bandit",
				name:         "Python security",
				cap:          "security",
				severity:     "high",
				toolPath:     opts.BanditPath,
				baseArgs:     []string{"-q"},
				isPythonTool: true,
			},
		}

		for _, step := range steps {
			if opts.ProgressHandler != nil {
				opts.ProgressHandler(step.id, "running")
			}

			baseArgs := step.baseArgs
			if step.id == "python.security.bandit" && len(opts.BanditArgs) > 0 {
				baseArgs = opts.BanditArgs
			}

			args := append([]string{}, baseArgs...)
			args = append(args, pyFiles...)

			var env []string
			if step.isPythonTool {
				if len(opts.BanditEnv) > 0 {
					env = append(env, opts.BanditEnv...)
				}
				if opts.CABundlePath != "" {
					if len(env) == 0 {
						env = os.Environ()
					}
					env = append(env,
						"SSL_CERT_FILE="+opts.CABundlePath,
						"REQUESTS_CA_BUNDLE="+opts.CABundlePath,
						"PIP_CERT="+opts.CABundlePath,
					)
				}
			}
			if len(env) == 0 {
				env = osutil.AugmentedEnviron()
			}
			env = withoutColor(env)

			startCtrl := time.Now()
			spec := osutil.CommandSpec{
				Executable:       step.toolPath,
				Args:             args,
				WorkingDirectory: opts.RepoRoot,
				Env:              env,
				Limits: osutil.ProcessLimits{
					Timeout:        timeout,
					MaxOutputBytes: maxOutput,
				},
			}

			res, err := osutil.RunBounded(ctx, spec)
			endCtrl := time.Now()
			durationMs := endCtrl.Sub(startCtrl).Milliseconds()

			status := "success"
			var exitCodePtr *int
			diag := []report.Diagnostic{}
			isCritical := false

			if err != nil {
				status = "error"
				isCritical = true
				diag = append(diag, report.Diagnostic{
					Code:     "execution_error",
					Message:  err.Error(),
					Critical: true,
				})
			} else {
				exitCode := res.ExitCode
				exitCodePtr = &exitCode
				if res.TimedOut {
					status = "error"
					isCritical = true
					diag = append(diag, report.Diagnostic{
						Code:     "timeout",
						Message:  fmt.Sprintf("Délai d'exécution dépassé (%v).", timeout),
						Critical: true,
					})
				} else if res.Cancelled {
					status = "skipped"
					diag = append(diag, report.Diagnostic{
						Code:     "cancelled",
						Message:  "Contrôle annulé.",
						Critical: false,
					})
				} else if exitCode != 0 {
					status = "fail"
					diag = append(diag, report.Diagnostic{
						Code:     "exit_nonzero",
						Message:  fmt.Sprintf("Défaut détecté par l'outil (code %d).", exitCode),
						Critical: false,
					})
				}
				if res.OutputTruncated {
					diag = append(diag, report.Diagnostic{
						Code:     "output_truncated",
						Message:  "Sorties tronquées par le plafond mémoire de capture.",
						Critical: false,
					})
				}
			}

			if opts.ProgressHandler != nil {
				opts.ProgressHandler(step.id, status)
			}

			stdout, stderr := "", ""
			if res != nil {
				stdout = strings.TrimSpace(stripANSI(res.Stdout))
				stderr = strings.TrimSpace(stripANSI(res.Stderr))
			}
			catId := step.id
			results = append(results, report.ExecutionResult{
				ControlId:        step.id,
				ControlCatalogId: &catId,
				Name:             step.name,
				Technology:       "python",
				Capability:       step.cap,
				Root:             ".",
				Severity:         step.severity,
				Status:           status,
				ExecutionStart:   startCtrl.UTC().Format(time.RFC3339),
				ExecutionEnd:     endCtrl.UTC().Format(time.RFC3339),
				DurationMs:       durationMs,
				Stdout:           stdout,
				Stderr:           stderr,
				ExitCode:         exitCodePtr,
				OutputTruncated:  res != nil && res.OutputTruncated,
				Critical:         isCritical,
				Diagnostics:      diag,
			})
		}
	}

	complianceMs := time.Since(startTime).Milliseconds() - discoveryMs
	repMetrics := &report.Metrics{
		DiscoveryMs:     discoveryMs,
		ResolverMs:      0,
		ComplianceMs:    complianceMs,
		ReportingMs:     1,
		TotalDurationMs: discoveryMs + complianceMs + 1,
	}

	runID := fmt.Sprintf("%032x", time.Now().UnixNano())
	plat := distribution.DetectPlatform()

	finalReport := report.BuildReport(
		opts.RepoRoot,
		runID,
		plat,
		discResult,
		execPlan,
		results,
		repMetrics,
	)

	return finalReport, nil
}

// ComplianceOptions configures the full compliance run.
type ComplianceOptions struct {
	RepoRoot                string
	PlatformRoot            string
	CatalogPath             string
	TimeoutSeconds          int
	GlobalTimeoutSeconds    int
	MaxOutputBytesPerStream int64
	MaximumControls         int
	AllowNetwork            bool
	AllowCodeExecution      bool
	PlanOnly                bool
	RedactionPatterns       []string
	RedactionReplacement    string
	PlatformQualification   string
	RunID                   string
	SourceAdapter           string
	CandidateResolver       matrix.CandidateToolResolver
	OnPlanReady             func(planReport *report.Report)
	OnControlStart          func(ctrl *PlannedControl)
	OnControlDone           func(ctrl *PlannedControl, res *report.ExecutionResult)
	DisabledTechnologies    []string
	DisabledControls        []string
}

// RunCompliance executes the entire Phase 3 compliance workflow:
// Discovery -> Capability Matrix -> Tool Resolution -> Execution Plan -> Control Execution -> Canonical Report.
func RunCompliance(ctx context.Context, opts ComplianceOptions) (*report.Report, error) {
	totalStart := time.Now()

	repoRoot := opts.RepoRoot
	if repoRoot == "" {
		repoRoot = "."
	}
	absRepo, err := osutil.CanonicalPath(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("chemin de dépôt invalide: %w", err)
	}

	platformRoot := opts.PlatformRoot
	if platformRoot == "" {
		platformRoot = absRepo
	}

	catalogPath, err := embedded.ResolveAsset("control-catalog.json", opts.CatalogPath, filepath.Join(platformRoot, ".config", "control-catalog.json"))
	if err != nil {
		return nil, fmt.Errorf("catalogue de contrôles introuvable: %w", err)
	}

	// 1. Load catalog
	cat, err := matrix.LoadCatalog(catalogPath)
	if err != nil {
		return nil, fmt.Errorf("chargement du catalogue de contrôle impossible: %w", err)
	}

	// 2. Discovery
	discStart := time.Now()
	discResult, err := discovery.DiscoverAll(absRepo)
	if err != nil {
		return nil, fmt.Errorf("découverte des technologies échouée: %w", err)
	}
	discMs := time.Since(discStart).Milliseconds()

	// 3. Capability Matrix & Tool Resolution
	resolverStart := time.Now()
	plat := matrix.DetectPlatform()
	candidateResolver := opts.CandidateResolver
	if candidateResolver == nil {
		candidateResolver = &matrix.DefaultCandidateResolver{PlatformRoot: platformRoot}
	}

	matrixEntries := matrix.BuildCapabilityMatrix(discResult.Technologies, cat, plat, candidateResolver, absRepo)
	resolutionEntries := matrix.ResolveCapabilityTools(matrixEntries)
	resolverMs := time.Since(resolverStart).Milliseconds()

	matrix.PopulateDiscovery(discResult, cat, plat, candidateResolver, absRepo)

	// 4. Execution Plan
	planOpts := PlanOptions{
		TimeoutSeconds:          opts.TimeoutSeconds,
		GlobalTimeoutSeconds:    opts.GlobalTimeoutSeconds,
		MaxOutputBytesPerStream: opts.MaxOutputBytesPerStream,
		MaximumControls:         opts.MaximumControls,
		AllowNetwork:            opts.AllowNetwork,
		AllowCodeExecution:      opts.AllowCodeExecution,
		PlatformID:              plat.ID,
		DisabledTechnologies:    opts.DisabledTechnologies,
		DisabledControls:        opts.DisabledControls,
	}

	execPlan, plannedControls, err := BuildCompliancePlan(discResult.Technologies, matrixEntries, resolutionEntries, absRepo, planOpts)
	if err != nil {
		return nil, fmt.Errorf("construction du plan de conformité échouée: %w", err)
	}

	if opts.OnPlanReady != nil {
		sourceAdapter := opts.SourceAdapter
		if sourceAdapter == "" {
			sourceAdapter = "VSCode"
		}
		planRep := report.BuildComplianceReport(report.ReportOptions{
			Repository:    absRepo,
			RunID:         opts.RunID,
			Platform:      plat.ID,
			DiscoveryData: discResult,
			MatrixData:    matrixEntries,
			ResolverData:  resolutionEntries,
			Plan:          *execPlan,
			Results:       nil,
			ScanComplete:  discResult.ScanComplete,
			PlanOnly:      true,
			Adapter:       sourceAdapter,
		})
		planRep.Metadata.SourceAdapter = sourceAdapter
		opts.OnPlanReady(planRep)
	}

	// 5. Redactor
	redactor, err := NewRedactor(opts.RedactionPatterns, opts.RedactionReplacement)
	if err != nil {
		return nil, fmt.Errorf("initialisation du masquage regex échouée: %w", err)
	}

	// 6. Execution
	var results []report.ExecutionResult
	complianceStart := time.Now()

	if !opts.PlanOnly && discResult.ScanComplete {
		results, err = ExecuteCompliancePlan(ctx, execPlan, plannedControls, ExecutionOptions{
			PlatformRoot:   platformRoot,
			GlobalTimeout:  time.Duration(execPlan.Budgets.TimeoutSeconds) * time.Second,
			Redactor:       redactor,
			OnControlStart: opts.OnControlStart,
			OnControlDone:  opts.OnControlDone,
		})
		if err != nil {
			return nil, fmt.Errorf("exécution du plan de conformité échouée: %w", err)
		}
	}
	complianceMs := time.Since(complianceStart).Milliseconds()
	if opts.PlanOnly {
		complianceMs = 0
	}

	// 7. Build Canonical Report
	totalMs := time.Since(totalStart).Milliseconds()
	reportingMs := totalMs - discMs - resolverMs - complianceMs
	if reportingMs < 0 {
		reportingMs = 0
	}

	stageMetrics := &report.Metrics{
		DiscoveryMs:     discMs,
		ResolverMs:      resolverMs,
		ComplianceMs:    complianceMs,
		ReportingMs:     reportingMs,
		TotalDurationMs: totalMs,
	}

	var catSha *string
	if cat.ContentSHA256 != "" {
		s := cat.ContentSHA256
		catSha = &s
	}

	if opts.PlanOnly {
		discResult.CapabilityMatrix = []interface{}{}
		discResult.ToolResolution = []interface{}{}
	}

	rep := report.BuildComplianceReport(report.ReportOptions{
		Repository:                  absRepo,
		RunID:                       opts.RunID,
		Platform:                    plat.ID,
		DiscoveryData:               discResult,
		MatrixData:                  discResult.CapabilityMatrix,
		ResolverData:                discResult.ToolResolution,
		Plan:                        *execPlan,
		Results:                     results,
		Metrics:                     stageMetrics,
		CatalogSHA256:               catSha,
		PlatformQualificationStatus: opts.PlatformQualification,
		RedactionApplied:            redactor != nil && len(redactor.Patterns) > 0,
		PlanOnly:                    opts.PlanOnly,
		ScanComplete:                discResult.ScanComplete,
		Adapter:                     opts.SourceAdapter,
	})
	if opts.PlanOnly {
		rep.Matrix = []interface{}{}
		rep.Resolver = []interface{}{}
	}

	return rep, nil
}
