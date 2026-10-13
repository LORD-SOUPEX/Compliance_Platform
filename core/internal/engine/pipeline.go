package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"compliance/internal/discovery"
	"compliance/internal/distribution"
	"compliance/internal/osutil"
	"compliance/internal/report"
)

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

	// 1. Discovery
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
			TimeoutSeconds:         int(timeout.Seconds()),
			MaxOutputBytesPerStream: maxOutput,
			MaxControls:            len(planControls),
		},
		Permissions: report.Permissions{
			Network:       false,
			CodeExecution: false,
		},
		Controls: planControls,
	}

	var results []report.ExecutionResult

	if len(pyFiles) == 0 {
		// No Python files: all controls skipped
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
		// Define the 3 pipeline steps
		steps := []struct {
			id           string
			name         string
			cap          string
			severity     string
			toolPath     string
			baseArgs     []string
			isPythonTool bool // whether to inject Python enterprise CA bundle
		}{
			{
				id:           "python.format.ruff",
				name:         "Python format",
				cap:          "formatting",
				severity:     "medium",
				toolPath:     opts.RuffPath,
				baseArgs:     []string{"format", "--check", "--no-cache"},
				isPythonTool: false, // native Rust binary, does not use Python CA vars
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
				isPythonTool: true, // Python tool: receives enterprise CA bundle env vars!
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
					// TOOL-BY-TOOL ENTERPRISE CA INJECTION:
					// Injected strictly into Python-based tools, not globally for all tools
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
