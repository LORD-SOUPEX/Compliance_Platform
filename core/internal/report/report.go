package report

import (
	"encoding/json"
	"fmt"
	"time"
)

// Report conforms strictly to .config/compliance-report.schema.json (v1).
type Report struct {
	SchemaVersion    int               `json:"schema_version"`
	EngineVersion    string            `json:"engine_version"`
	GeneratedAt      string            `json:"generated_at"`
	Metadata         Metadata          `json:"metadata"`
	Repository       string            `json:"repository"`
	ExecutionStatus  string            `json:"execution_status"` // planned, completed, blocked, error
	Discovery        interface{}       `json:"discovery"`
	Matrix           []interface{}     `json:"matrix"`
	Resolver         []interface{}     `json:"resolver"`
	ExecutionPlan    ExecutionPlan     `json:"execution_plan"`
	ExecutionResults []ExecutionResult `json:"execution_results"`
	Findings         []Finding         `json:"findings"`
	Diagnostics      []Diagnostic      `json:"diagnostics"`
	Summary          Summary           `json:"summary"`
	Coverage         Coverage          `json:"coverage"`
	Metrics          *Metrics          `json:"metrics,omitempty"`
	Limitations      []interface{}     `json:"limitations"`
	Verdict          *string           `json:"verdict"` // PASS, FAIL, null
	VerdictReasons   []string          `json:"verdict_reasons"`
	Advisory         bool              `json:"advisory"`
}

type Metadata struct {
	RunId                      string  `json:"run_id"`
	SourceMode                 string  `json:"source_mode"`
	SourceAdapter              string  `json:"source_adapter"` // PowerShell, Bash, VSCode, GitLab, Legacy
	Platform                   string  `json:"platform"`
	CatalogSchemaVersion       int     `json:"catalog_schema_version"`
	CatalogSha256              *string `json:"catalog_sha256"`
	PlatformQualificationStatus string `json:"platform_qualification_status,omitempty"`
	RedactionApplied           bool    `json:"redaction_applied"`
	NetworkAuthorized          bool    `json:"network_authorized"`
	CodeExecutionAuthorized    bool    `json:"code_execution_authorized"`
}

type ExecutionPlan struct {
	SchemaVersion int           `json:"schema_version"`
	Repository    string        `json:"repository"`
	Budgets       Budgets       `json:"budgets"`
	Permissions   Permissions   `json:"permissions"`
	Controls      []interface{} `json:"controls"`
}

type Budgets struct {
	TimeoutSeconds         int   `json:"timeout_seconds"`
	MaxOutputBytesPerStream int64 `json:"max_output_bytes_per_stream"`
	MaxControls            int   `json:"max_controls"`
}

type Permissions struct {
	Network       bool `json:"network"`
	CodeExecution bool `json:"code_execution"`
}

type ExecutionResult struct {
	ControlId        string       `json:"control_id"`
	ControlCatalogId *string      `json:"control_catalog_id"`
	Name             string       `json:"name"`
	Technology       string       `json:"technology"`
	Capability       string       `json:"capability"`
	Root             string       `json:"root"`
	Severity         string       `json:"severity"` // low, medium, high, critical
	Status           string       `json:"status"`   // success, fail, error, skipped
	ExecutionStart   string       `json:"execution_start"`
	ExecutionEnd     string       `json:"execution_end"`
	DurationMs       int64        `json:"duration_ms"`
	ToolVersion      *string      `json:"tool_version"`
	Stdout           string       `json:"stdout"`
	Stderr           string       `json:"stderr"`
	ExitCode         *int         `json:"exit_code"`
	OutputTruncated  bool         `json:"output_truncated"`
	Critical         bool         `json:"critical"`
	Diagnostics      []Diagnostic `json:"diagnostics"`
}

type Finding struct {
	Id          string       `json:"id"`
	ControlId   string       `json:"control_id"`
	Name        string       `json:"name"`
	Technology  string       `json:"technology"`
	Capability  string       `json:"capability"`
	Root        string       `json:"root"`
	Severity    string       `json:"severity"` // low, medium, high, critical
	Status      string       `json:"status"`   // fail, error
	Diagnostics []Diagnostic `json:"diagnostics"`
}

type Diagnostic struct {
	Code     string `json:"code"`
	Message  string `json:"message"`
	Critical bool   `json:"critical"`
}

type Summary struct {
	Success        int `json:"success"`
	Fail           int `json:"fail"`
	Error          int `json:"error"`
	Skipped        int `json:"skipped"`
	CriticalErrors int `json:"critical_errors"`
}

type Coverage struct {
	Complete                 bool          `json:"complete"`
	PlannedControls          int           `json:"planned_controls"`
	ExecutedControls         int           `json:"executed_controls"`
	OmittedRequiredControls  int           `json:"omitted_required_controls"`
	DependencySkips          int           `json:"dependency_skips"`
	Limitations              []interface{} `json:"limitations"`
}

type Metrics struct {
	DiscoveryMs  int64 `json:"discovery_ms"`
	ResolverMs   int64 `json:"resolver_ms"`
	ComplianceMs int64 `json:"compliance_ms"`
	ReportingMs  int64 `json:"reporting_ms"`
}

// ComputeVerdict calculates PASS or FAIL based on execution results.
func ComputeVerdict(results []ExecutionResult) (string, Summary, []string) {
	summary := Summary{}
	reasons := []string{}

	for _, r := range results {
		switch r.Status {
		case "success":
			summary.Success++
		case "fail":
			summary.Fail++
		case "error":
			summary.Error++
			if r.Critical {
				summary.CriticalErrors++
			}
		case "skipped":
			summary.Skipped++
		}
	}

	verdict := "PASS"
	if summary.Fail > 0 {
		verdict = "FAIL"
		reasons = append(reasons, "Au moins un controle de conformite echoue.")
	}
	if summary.CriticalErrors > 0 {
		verdict = "FAIL"
		reasons = append(reasons, "Au moins une erreur critique empeche une evaluation complete.")
	}

	return verdict, summary, reasons
}

// ReportOptions provides all parameters to build a fully compliant report.
type ReportOptions struct {
	Repository                  string
	RunID                       string
	Platform                    string
	DiscoveryData               interface{}
	MatrixData                  interface{}
	ResolverData                interface{}
	Plan                        ExecutionPlan
	Results                     []ExecutionResult
	Metrics                     *Metrics
	CatalogSHA256               *string
	PlatformQualificationStatus string
	RedactionApplied            bool
	PlanOnly                    bool
	ScanComplete                bool
	ScanErrors                  []discoveryScanErrorRef
	Adapter                     string
}

type discoveryScanErrorRef struct {
	Path      string `json:"path"`
	Operation string `json:"operation"`
	Message   string `json:"message"`
}

// BuildComplianceReport builds a complete Report matching New-ComplianceReport in PowerShell.
func BuildComplianceReport(opts ReportOptions) *Report {
	_, summary, reasons := ComputeVerdict(opts.Results)

	findings := make([]Finding, 0)
	allDiagnostics := make([]Diagnostic, 0)

	for _, r := range opts.Results {
		allDiagnostics = append(allDiagnostics, r.Diagnostics...)
		if r.Status == "fail" || r.Status == "error" {
			findingID := r.ControlId
			if r.ControlCatalogId != nil && *r.ControlCatalogId != "" {
				findingID = *r.ControlCatalogId
			}
			findings = append(findings, Finding{
				Id:          findingID,
				ControlId:   r.ControlId,
				Name:        r.Name,
				Technology:  r.Technology,
				Capability:  r.Capability,
				Root:        r.Root,
				Severity:    r.Severity,
				Status:      r.Status,
				Diagnostics: r.Diagnostics,
			})
		}
	}

	// Add discovery scan errors to findings and diagnostics if scan incomplete
	if !opts.ScanComplete && len(opts.ScanErrors) > 0 {
		summary.CriticalErrors++
		reasons = append(reasons, "Scan incomplet: erreur critique de preparation.")
		for _, se := range opts.ScanErrors {
			diag := Diagnostic{
				Code:     "scan_" + se.Operation + "_failed",
				Message:  se.Message,
				Critical: true,
			}
			allDiagnostics = append(allDiagnostics, diag)
			findings = append(findings, Finding{
				Id:          "engine/discovery/" + se.Operation + "/" + se.Path,
				ControlId:   "engine/discovery",
				Name:        "Discovery scan error",
				Technology:  "engine",
				Capability:  "discovery",
				Root:        se.Path,
				Severity:    "critical",
				Status:      "error",
				Diagnostics: []Diagnostic{diag},
			})
		}
	}

	// Calculate executed controls (exit_code != nil)
	executedControls := 0
	dependencySkips := 0
	for _, r := range opts.Results {
		if r.ExitCode != nil {
			executedControls++
		}
		for _, d := range r.Diagnostics {
			if d.Code == "dependency_failed" {
				dependencySkips++
				break
			}
		}
	}

	// Traiter les contrôles planifiés et détecter omissions / doublons / manquants
	planControlsMap := make(map[string]bool)
	requiredPlanControls := make(map[string]bool)
	nonApplicableIds := make(map[string]bool)

	for _, raw := range opts.Plan.Controls {
		var id, applicability string
		var required bool
		if m, ok := raw.(map[string]interface{}); ok {
			if s, ok := m["id"].(string); ok {
				id = s
			}
			if s, ok := m["applicability"].(string); ok {
				applicability = s
			}
			if r, ok := m["required"].(bool); ok {
				required = r
			}
		} else if b, err := json.Marshal(raw); err == nil {
			var m map[string]interface{}
			if err := json.Unmarshal(b, &m); err == nil {
				if s, ok := m["id"].(string); ok {
					id = s
				}
				if s, ok := m["applicability"].(string); ok {
					applicability = s
				}
				if r, ok := m["required"].(bool); ok {
					required = r
				}
			}
		}
		if id != "" {
			planControlsMap[id] = true
			if required {
				requiredPlanControls[id] = true
			}
			if applicability == "not_applicable" {
				nonApplicableIds[id] = true
			}
		}
	}

	blockingSkippedCount := 0
	omittedRequiredCount := 0
	seenResultIds := make(map[string]int)

	for _, r := range opts.Results {
		seenResultIds[r.ControlId]++
		if r.Status == "skipped" && !nonApplicableIds[r.ControlId] {
			blockingSkippedCount++
			if requiredPlanControls[r.ControlId] {
				omittedRequiredCount++
			}
		}
	}

	// Détecter si des contrôles requis manquent complètement des résultats
	hasDuplicates := false
	for _, count := range seenResultIds {
		if count > 1 {
			hasDuplicates = true
			break
		}
	}

	missingResults := false
	for id := range planControlsMap {
		if seenResultIds[id] == 0 {
			missingResults = true
			if requiredPlanControls[id] {
				omittedRequiredCount++
			}
		}
	}

	if hasDuplicates {
		summary.CriticalErrors++
		reasons = append(reasons, "Resultats d'execution dupliques pour au moins un controle.")
	}
	if missingResults && !opts.PlanOnly {
		summary.CriticalErrors++
		reasons = append(reasons, "Au moins un controle planifie n'a aucun resultat d'execution.")
	}
	if omittedRequiredCount > 0 && !opts.PlanOnly {
		reasons = append(reasons, fmt.Sprintf("%d controle(s) requis omis de l'evaluation.", omittedRequiredCount))
	}

	coverage := Coverage{
		Complete:                !opts.PlanOnly && opts.ScanComplete && len(opts.Results) == len(opts.Plan.Controls) && summary.Error == 0 && blockingSkippedCount == 0 && omittedRequiredCount == 0 && !hasDuplicates && !missingResults,
		PlannedControls:         len(opts.Plan.Controls),
		ExecutedControls:        executedControls,
		OmittedRequiredControls: omittedRequiredCount,
		DependencySkips:         dependencySkips,
		Limitations:             make([]interface{}, 0),
	}

	var verdictPtr *string
	if !opts.PlanOnly {
		if summary.Fail > 0 || summary.CriticalErrors > 0 || omittedRequiredCount > 0 {
			v := "FAIL"
			verdictPtr = &v
		} else {
			v := "PASS"
			verdictPtr = &v
		}
	}

	matrixList := make([]interface{}, 0)
	if opts.MatrixData != nil {
		if mSlice, ok := opts.MatrixData.([]interface{}); ok {
			matrixList = mSlice
		}
	}

	resolverList := make([]interface{}, 0)
	if opts.ResolverData != nil {
		if rSlice, ok := opts.ResolverData.([]interface{}); ok {
			resolverList = rSlice
		}
	}

	platformStatus := opts.PlatformQualificationStatus
	if platformStatus == "" {
		platformStatus = "experimental"
	}

	status := "completed"
	if opts.PlanOnly {
		status = "planned"
	} else if !opts.ScanComplete {
		status = "blocked"
	}

	engineVer := "0.1.0"
	resultsList := opts.Results
	if resultsList == nil {
		resultsList = make([]ExecutionResult, 0)
	}

	adapter := opts.Adapter
	if adapter == "" {
		adapter = "PowerShell"
	}

	return &Report{
		SchemaVersion:    1,
		EngineVersion:    engineVer,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		Repository:       opts.Repository,
		ExecutionStatus:  status,
		Discovery:        opts.DiscoveryData,
		Matrix:           matrixList,
		Resolver:         resolverList,
		ExecutionPlan:    opts.Plan,
		ExecutionResults: resultsList,
		Findings:         findings,
		Diagnostics:      allDiagnostics,
		Summary:          summary,
		Coverage:         coverage,
		Limitations:      make([]interface{}, 0),
		Verdict:          verdictPtr,
		VerdictReasons:   reasons,
		Advisory:         true,
		Metrics:          opts.Metrics,
		Metadata: Metadata{
			RunId:                       opts.RunID,
			SourceMode:                  "Compliance",
			SourceAdapter:               adapter,
			Platform:                    opts.Platform,
			CatalogSchemaVersion:        1,
			CatalogSha256:               opts.CatalogSHA256,
			PlatformQualificationStatus: platformStatus,
			RedactionApplied:            opts.RedactionApplied,
			NetworkAuthorized:           opts.Plan.Permissions.Network,
			CodeExecutionAuthorized:     opts.Plan.Permissions.CodeExecution,
		},
	}
}

// BuildReport maintains backward compatibility with Phase 0 callers.
func BuildReport(
	repo string,
	runID string,
	platform string,
	discoveryData interface{},
	plan ExecutionPlan,
	results []ExecutionResult,
	metrics *Metrics,
) *Report {
	return BuildComplianceReport(ReportOptions{
		Repository:       repo,
		RunID:            runID,
		Platform:         platform,
		DiscoveryData:    discoveryData,
		Plan:             plan,
		Results:          results,
		Metrics:          metrics,
		ScanComplete:     true,
		RedactionApplied: false,
	})
}

// ToJSON formats the report as JSON bytes.
func (r *Report) ToJSON(indent bool) ([]byte, error) {
	if indent {
		return json.MarshalIndent(r, "", "  ")
	}
	return json.Marshal(r)
}
