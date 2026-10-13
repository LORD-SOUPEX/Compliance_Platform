package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"compliance/internal/osutil"
	"compliance/internal/report"
)

// ExecutionOptions configures execution of a compliance plan.
type ExecutionOptions struct {
	PlatformRoot    string
	GlobalTimeout   time.Duration
	Redactor        *Redactor
	OnControlStart  func(ctrl *PlannedControl)
	OnControlDone   func(ctrl *PlannedControl, res *report.ExecutionResult)
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

		if opts.OnControlStart != nil {
			opts.OnControlStart(ctrl)
		}

		// Check cancellation
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

		// Check failed dependencies
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
			if ctrl.Applicability == "ambiguous" || (ctrl.Required && (ctrl.Applicability == "capability_unavailable" || ctrl.Applicability == "tool_unavailable")) {
				res.Status = "error"
				res.Critical = true
			}
			code := ctrl.ReasonCode
			if code == "" {
				code = ctrl.Applicability
			}
			res.Diagnostics = append(res.Diagnostics, report.Diagnostic{
				Code:     code,
				Message:  ctrl.Reason,
				Critical: res.Critical,
			})
		} else {
			// Applicable: execute
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
						// Probe version if needed
						if res.ToolVersion == nil && ctrl.Tool != nil && ctrl.Tool.Command != "" {
							ver, verErr := ProbeToolVersion(ctx, inv.Executable, ctrl.Tool.Command, execRoot, 5*time.Second)
							if verErr == nil && ver != "" {
								res.ToolVersion = &ver
							}
						}

						// Run bounded process
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
