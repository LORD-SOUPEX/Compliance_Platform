package report

import (
	"encoding/json"
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

// BuildReport builds a complete Report object.
func BuildReport(
	repo string,
	runID string,
	platform string,
	discoveryData interface{},
	plan ExecutionPlan,
	results []ExecutionResult,
	metrics *Metrics,
) *Report {
	verdictStr, summary, reasons := ComputeVerdict(results)

	findings := []Finding{}
	allDiagnostics := []Diagnostic{}

	for _, r := range results {
		allDiagnostics = append(allDiagnostics, r.Diagnostics...)
		if r.Status == "fail" || r.Status == "error" {
			findings = append(findings, Finding{
				Id:          r.ControlId + "/finding",
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

	coverage := Coverage{
		Complete:                len(results) == len(plan.Controls),
		PlannedControls:         len(plan.Controls),
		ExecutedControls:        len(results),
		OmittedRequiredControls: 0,
		DependencySkips:         0,
		Limitations:             []interface{}{},
	}

	return &Report{
		SchemaVersion:   1,
		EngineVersion:   "0.1.0-phase0-go",
		GeneratedAt:     time.Now().UTC().Format(time.RFC3339),
		Repository:      repo,
		ExecutionStatus: "completed",
		Discovery:       discoveryData,
		Matrix:          []interface{}{},
		Resolver:        []interface{}{},
		ExecutionPlan:   plan,
		ExecutionResults: results,
		Findings:        findings,
		Diagnostics:     allDiagnostics,
		Summary:         summary,
		Coverage:        coverage,
		Limitations:     []interface{}{},
		Verdict:         &verdictStr,
		VerdictReasons:  reasons,
		Advisory:        true,
		Metrics:         metrics,
		Metadata: Metadata{
			RunId:                      runID,
			SourceMode:                 "Compliance",
			SourceAdapter:              "PowerShell", // For v1 schema enum compatibility
			Platform:                   platform,
			CatalogSchemaVersion:       1,
			CatalogSha256:              nil,
			PlatformQualificationStatus: "experimental",
			RedactionApplied:           false,
			NetworkAuthorized:          false,
			CodeExecutionAuthorized:    false,
		},
	}
}

// ToJSON formats the report as JSON bytes.
func (r *Report) ToJSON(indent bool) ([]byte, error) {
	if indent {
		return json.MarshalIndent(r, "", "  ")
	}
	return json.Marshal(r)
}
