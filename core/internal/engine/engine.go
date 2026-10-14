package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"compliance/internal/discovery"
	"compliance/internal/distribution"
	"compliance/internal/embedded"
	"compliance/internal/matrix"
	"compliance/internal/osutil"
	"compliance/internal/report"
)

var (
	reVersionFinder = regexp.MustCompile(`\b\d+\.\d+(?:\.\d+)?(?:[a-zA-Z0-9.+-]*)`)

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
	Executable string   `json:"executable"`
	Arguments  []string `json:"arguments"`
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

	var filesInRoot []string
	prefix := filepath.Clean(root) + string(filepath.Separator)
	for _, rel := range ctrl.Files {
		full := filepath.Join(repoRoot, filepath.FromSlash(rel))
		if strings.EqualFold(filepath.Clean(root), repoRoot) || strings.HasPrefix(strings.ToLower(full), strings.ToLower(prefix)) {
			filesInRoot = append(filesInRoot, full)
		}
	}

	var arguments []string

	switch command {
	case "ruff":
		var pyFiles []string
		for _, f := range filesInRoot {
			if strings.EqualFold(filepath.Ext(f), ".py") {
				pyFiles = append(pyFiles, f)
			}
		}
		if len(pyFiles) == 0 {
			return nil, errors.New("aucune source Python pour Ruff")
		}
		if len(catalogArgs) == 0 {
			return nil, errors.New("arguments Ruff absents du catalogue")
		}
		arguments = append(arguments, catalogArgs...)
		arguments = append(arguments, pyFiles...)

	case "pylint", "bandit":
		var pyFiles []string
		for _, f := range filesInRoot {
			if strings.EqualFold(filepath.Ext(f), ".py") {
				pyFiles = append(pyFiles, f)
			}
		}
		if len(pyFiles) == 0 {
			return nil, fmt.Errorf("aucune source Python pour %s", command)
		}
		arguments = append(arguments, catalogArgs...)
		arguments = append(arguments, pyFiles...)

	case "pytest":
		arguments = append(arguments, catalogArgs...)
		arguments = append(arguments, root)

	case "pip-audit":
		reqPath := filepath.Join(root, "requirements.txt")
		if _, err := os.Stat(reqPath); err != nil {
			return nil, errors.New("audit consommateur: requirements.txt requis; le runtime de la plateforme n est pas audite a sa place")
		}
		arguments = append(arguments, catalogArgs...)
		arguments = append(arguments, "-r", reqPath)

	case "terraform", "tofu", "terragrunt", "tflint":
		arguments = append(arguments, catalogArgs...)

	case "shellcheck":
		var shFiles []string
		for _, f := range filesInRoot {
			if strings.EqualFold(filepath.Ext(f), ".sh") {
				shFiles = append(shFiles, f)
			}
		}
		if len(shFiles) == 0 {
			return nil, errors.New("aucun script Shell pour ShellCheck")
		}
		arguments = append(arguments, catalogArgs...)
		arguments = append(arguments, shFiles...)

	case "hadolint":
		var containerFiles []string
		for _, f := range filesInRoot {
			base := filepath.Base(f)
			if strings.HasPrefix(strings.ToLower(base), "dockerfile") || strings.HasPrefix(strings.ToLower(base), "containerfile") {
				containerFiles = append(containerFiles, f)
			}
		}
		if len(containerFiles) == 0 {
			return nil, errors.New("validation Compose non implementee par Hadolint")
		}
		arguments = containerFiles

	case "ansible-lint":
		arguments = append(arguments, catalogArgs...)
		arguments = append(arguments, root)

	case "yamllint":
		cfg, _ := ctrl.Parameters["configuration"].(string)
		if cfg == "" {
			cfg = ".yamllint.yml"
		}
		arguments = []string{"-c", filepath.Join(platformRoot, cfg), root}

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
		arguments = append([]string{"run", hook, "--config", filepath.Join(platformRoot, ".pre-commit-config.yaml"), "--files"}, mdFiles...)

	case "checkov":
		framework, _ := ctrl.Parameters["framework"].(string)
		if framework == "" {
			return nil, errors.New("framework Checkov absent du catalogue")
		}
		arguments = []string{"-d", root, "--framework", framework, "--quiet"}
		if strings.EqualFold(filepath.Ext(executable), ".cmd") {
			arguments = append([]string{"-x", executable}, arguments...)
			pyExe := filepath.Join(platformRoot, ".tools", "python", "python.exe")
			if _, err := os.Stat(pyExe); err != nil {
				pyExe = filepath.Join(platformRoot, ".venv", "Scripts", "python.exe")
			}
			executable = pyExe
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
			root,
		}

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
		Executable: executable,
		Arguments:  arguments,
	}, nil
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

	res, err := osutil.RunBounded(ctx, osutil.CommandSpec{
		Executable:       executable,
		Args:             args,
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
			if ctrl.Applicability == "ambiguous" || (ctrl.Required && ctrl.Technology != "powershell" && (ctrl.Applicability == "capability_unavailable" || ctrl.Applicability == "tool_unavailable")) {
				res.Status = "error"
				res.Critical = true
			}
			code := ctrl.ReasonCode
			if code == "" {
				code = ctrl.Applicability
			}
			msg := ctrl.Reason
			if msg == "" {
				msg = "Contrôle non exécuté selon le motif structuré du backend."
			}
			res.Diagnostics = append(res.Diagnostics, report.Diagnostic{
				Code:     code,
				Message:  msg,
				Critical: res.Critical,
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
				if invErr != nil {
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
					} else {
						if res.ToolVersion == nil && ctrl.Tool != nil && ctrl.Tool.Command != "" {
							ver, verErr := ProbeToolVersion(ctx, inv.Executable, ctrl.Tool.Command, execRoot, 5*time.Second)
							if verErr == nil && ver != "" {
								res.ToolVersion = &ver
							}
						}

						procRes, procErr := osutil.RunBounded(ctx, osutil.CommandSpec{
							Executable:       inv.Executable,
							Args:             inv.Arguments,
							WorkingDirectory: execRoot,
							Limits: osutil.ProcessLimits{
								Timeout:        effectiveTimeout,
								MaxOutputBytes: ctrl.MaxOutputBytes,
							},
						})

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
							stdout := procRes.Stdout
							stderr := procRes.Stderr
							if opts.Redactor != nil {
								stdout = opts.Redactor.Redact(stdout)
								stderr = opts.Redactor.Redact(stderr)
							}
							res.Stdout = stdout
							res.Stderr = stderr
							res.OutputTruncated = procRes.OutputTruncated

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
							} else if exitCode == 0 {
								res.Status = "success"
							} else {
								res.Status = "fail"
								res.Diagnostics = append(res.Diagnostics, report.Diagnostic{
									Code:     "exit_nonzero",
									Message:  fmt.Sprintf("Controle en echec (code %d).", exitCode),
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
				Stdout:           strings.TrimSpace(res.Stdout),
				Stderr:           strings.TrimSpace(res.Stderr),
				ExitCode:         exitCodePtr,
				OutputTruncated:  res != nil && res.OutputTruncated,
				Critical:         isCritical,
				Diagnostics:      diag,
			})
		}
	}

	complianceMs := time.Since(startTime).Milliseconds() - discoveryMs
	repMetrics := &report.Metrics{
		DiscoveryMs:  discoveryMs,
		ResolverMs:   0,
		ComplianceMs: complianceMs,
		ReportingMs:  1,
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
		DiscoveryMs:  discMs,
		ResolverMs:   resolverMs,
		ComplianceMs: complianceMs,
		ReportingMs:  reportingMs,
	}

	var catSha *string
	if cat.ContentSHA256 != "" {
		s := cat.ContentSHA256
		catSha = &s
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

	return rep, nil
}
