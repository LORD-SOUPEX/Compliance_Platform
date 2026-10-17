package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"compliance/internal/version"
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
	RunId                       string  `json:"run_id"`
	SourceMode                  string  `json:"source_mode"`
	SourceAdapter               string  `json:"source_adapter"` // PowerShell, Bash, VSCode, GitLab, Legacy
	Platform                    string  `json:"platform"`
	CatalogSchemaVersion        int     `json:"catalog_schema_version"`
	CatalogSha256               *string `json:"catalog_sha256"`
	PlatformQualificationStatus string  `json:"platform_qualification_status,omitempty"`
	RedactionApplied            bool    `json:"redaction_applied"`
	NetworkAuthorized           bool    `json:"network_authorized"`
	CodeExecutionAuthorized     bool    `json:"code_execution_authorized"`
}

type ExecutionPlan struct {
	SchemaVersion int           `json:"schema_version"`
	Repository    string        `json:"repository"`
	Budgets       Budgets       `json:"budgets"`
	Permissions   Permissions   `json:"permissions"`
	Controls      []interface{} `json:"controls"`
}

type Budgets struct {
	TimeoutSeconds          int   `json:"timeout_seconds"`
	MaxOutputBytesPerStream int64 `json:"max_output_bytes_per_stream"`
	MaxControls             int   `json:"max_controls"`
}

type Permissions struct {
	Network       bool `json:"network"`
	CodeExecution bool `json:"code_execution"`
}

type ExecutionResult struct {
	ControlId        string        `json:"control_id"`
	ControlCatalogId *string       `json:"control_catalog_id"`
	Name             string        `json:"name"`
	Technology       string        `json:"technology"`
	Capability       string        `json:"capability"`
	Root             string        `json:"root"`
	Severity         string        `json:"severity"` // low, medium, high, critical
	Status           string        `json:"status"`   // success, fail, error, skipped
	ExecutionStart   string        `json:"execution_start"`
	ExecutionEnd     string        `json:"execution_end"`
	DurationMs       int64         `json:"duration_ms"`
	ToolVersion      *string       `json:"tool_version"`
	Stdout           string        `json:"stdout"`
	Stderr           string        `json:"stderr"`
	ExitCode         *int          `json:"exit_code"`
	OutputTruncated  bool          `json:"output_truncated"`
	Critical         bool          `json:"critical"`
	Diagnostics      []Diagnostic  `json:"diagnostics"`
	Leaks            []LocatedLeak `json:"-"`
}

// LocatedLeak is one secret location. The secret value itself is never stored.
type LocatedLeak struct {
	File        string
	Line        int
	Column      int
	RuleID      string
	Description string
	Severity    string
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
	Message     string       `json:"message,omitempty"`
	File        string       `json:"file,omitempty"`
	Line        int          `json:"line,omitempty"`
	Column      int          `json:"column,omitempty"`
	Diagnostics []Diagnostic `json:"diagnostics"`
}

type Diagnostic struct {
	Code     string `json:"code"`
	Message  string `json:"message"`
	Critical bool   `json:"critical"`
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
	Column   int    `json:"column,omitempty"`
}

type Summary struct {
	Success        int `json:"success"`
	Fail           int `json:"fail"`
	Error          int `json:"error"`
	Skipped        int `json:"skipped"`
	CriticalErrors int `json:"critical_errors"`
}

type Coverage struct {
	Complete                bool          `json:"complete"`
	PlannedControls         int           `json:"planned_controls"`
	ApplicableControls      int           `json:"applicable_controls"`
	ExecutedControls        int           `json:"executed_controls"`
	DetectedTechnologies    int           `json:"detected_technologies"`
	CoveredTechnologies     int           `json:"covered_technologies"`
	UncoveredTechnologies   []string      `json:"uncovered_technologies"`
	Label                   string        `json:"label"`
	OmittedRequiredControls int           `json:"omitted_required_controls"`
	DependencySkips         int           `json:"dependency_skips"`
	Limitations             []interface{} `json:"limitations"`
}

type Metrics struct {
	DiscoveryMs     int64 `json:"discovery_ms"`
	ResolverMs      int64 `json:"resolver_ms"`
	ComplianceMs    int64 `json:"compliance_ms"`
	ReportingMs     int64 `json:"reporting_ms"`
	TotalDurationMs int64 `json:"total_duration_ms"`
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
	}
	if summary.CriticalErrors > 0 {
		verdict = "FAIL"
		reasons = append(reasons, "Au moins une erreur critique empêche une évaluation complète.")
	}
	if summary.Success == 0 && summary.Fail == 0 && summary.Error == 0 && summary.Skipped > 0 {
		reasons = append(reasons, "Aucun contrôle exécuté. Les autres sont ignorés (technologie absente) ou indisponibles (outil manquant ou absent du catalogue).")
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
		if len(r.Leaks) > 0 {
			for index, leak := range r.Leaks {
				code := leak.RuleID
				if code == "" {
					code = "gitleaks"
				}
				message := leak.Description
				if leak.RuleID != "" && leak.Description != "" {
					message = leak.RuleID + " — " + leak.Description
				} else if message == "" {
					message = code
				}
				severity := leak.Severity
				if severity == "" {
					severity = r.Severity
				}
				diag := Diagnostic{Code: code, Message: message, File: leak.File, Line: leak.Line, Column: leak.Column}
				findings = append(findings, Finding{
					Id:          fmt.Sprintf("%s#%d", r.ControlId, index+1),
					ControlId:   r.ControlId,
					Name:        code,
					Technology:  r.Technology,
					Capability:  r.Capability,
					Root:        r.Root,
					Severity:    severity,
					Status:      "fail",
					Message:     message,
					File:        leak.File,
					Line:        leak.Line,
					Column:      leak.Column,
					Diagnostics: []Diagnostic{diag},
				})
			}
		} else if r.Status == "fail" || r.Status == "error" {
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

	// Calculate executed controls (exit_code != nil) and the applicable scope.
	executedControls := 0
	applicableControls := 0
	dependencySkips := 0
	for _, r := range opts.Results {
		if r.ExitCode != nil {
			executedControls++
		}
		if controlInApplicableScope(r) {
			applicableControls++
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
		if r.Status == "skipped" && len(r.Diagnostics) > 0 {
			switch r.Diagnostics[0].Code {
			case "technology_absent", "not_applicable", "platform_unsupported", "permission_denied", "ambiguous", "alternative_not_selected":
				continue
			case "capability_unavailable", "tool_unavailable", "probe_failed", "repository_unconfigured":
				blockingSkippedCount++
				continue
			}
		}
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

	detectedCount, coveredCount, uncovered := technologyCoverage(opts.DiscoveryData, opts.Results)
	label := coverageSentence(coveredCount, detectedCount, executedControls)
	coverageComplete := !opts.PlanOnly && opts.ScanComplete && detectedCount > 0 && coveredCount == detectedCount && executedControls > 0 && summary.Error == 0 && summary.Fail == 0 && blockingSkippedCount == 0 && omittedRequiredCount == 0 && !hasDuplicates && !missingResults
	coverage := Coverage{
		Complete:                coverageComplete,
		PlannedControls:         len(opts.Plan.Controls),
		ApplicableControls:      applicableControls,
		ExecutedControls:        executedControls,
		DetectedTechnologies:    detectedCount,
		CoveredTechnologies:     coveredCount,
		UncoveredTechnologies:   uncovered,
		Label:                   label,
		OmittedRequiredControls: omittedRequiredCount,
		DependencySkips:         dependencySkips,
		Limitations:             make([]interface{}, 0),
	}

	var verdictPtr *string
	if !opts.PlanOnly {
		switch {
		case summary.Success == 0 && summary.Fail == 0 && summary.Error == 0:
			verdictPtr = nil
			reasons = append([]string{label}, reasons...)
			if len(uncovered) > 0 {
				reasons = append(reasons, "Lacunes : "+strings.Join(uncovered, ", ")+".")
			}
		case summary.Fail > 0 || summary.CriticalErrors > 0 || omittedRequiredCount > 0:
			v := "FAIL"
			verdictPtr = &v
			reasons = append([]string{label}, reasons...)
		case !coverageComplete:
			v := "PASS"
			verdictPtr = &v
			reasons = append([]string{label}, reasons...)
			if len(uncovered) > 0 {
				reasons = append(reasons, "Lacunes : "+strings.Join(uncovered, ", ")+".")
			}
		default:
			v := "PASS"
			verdictPtr = &v
			reasons = append([]string{label}, reasons...)
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

	engineVer := version.Version
	resultsList := opts.Results
	if resultsList == nil {
		resultsList = make([]ExecutionResult, 0)
	}

	adapter := opts.Adapter
	if adapter == "" {
		adapter = "Go"
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

func controlInApplicableScope(r ExecutionResult) bool {
	if r.Status == "success" || r.Status == "fail" || r.Status == "error" {
		return true
	}
	if len(r.Diagnostics) == 0 {
		return false
	}
	switch r.Diagnostics[0].Code {
	case "technology_absent", "not_applicable", "platform_unsupported", "alternative_not_selected", "ambiguous", "user_disabled":
		return false
	default:
		return true
	}
}

func coverageSentence(covered, detected, executed int) string {
	if detected <= 0 {
		return "Aucune technologie détectée."
	}
	text := fmt.Sprintf("%d technologie(s) couverte(s) sur %d détectée(s)", covered, detected)
	switch {
	case covered == detected:
		return "Couverture complète : " + text + "."
	case executed == 0:
		return "Couverture nulle : " + text + "."
	default:
		return "Couverture partielle : " + text + "."
	}
}

func technologyCoverage(discovery interface{}, results []ExecutionResult) (int, int, []string) {
	detected := map[string]bool{}
	for _, name := range detectedTechnologies(discovery) {
		detected[name] = true
	}
	type state struct {
		executed bool
		gap      string
		disabled bool
		seen     bool
	}
	byTech := map[string]*state{}
	for name := range detected {
		byTech[name] = &state{}
	}
	for _, result := range results {
		if !detected[result.Technology] {
			continue
		}
		item := byTech[result.Technology]
		if result.ExitCode != nil {
			item.executed = true
		}
		if len(result.Diagnostics) == 0 {
			continue
		}
		item.seen = true
		switch result.Diagnostics[0].Code {
		case "user_disabled":
			item.disabled = true
		case "tool_unavailable", "probe_failed", "capability_unavailable", "repository_unconfigured", "platform_unavailable":
			if item.gap == "" {
				item.gap = result.Technology + " : " + result.Diagnostics[0].Message
			}
		}
	}
	names := make([]string, 0, len(detected))
	for name := range detected {
		names = append(names, name)
	}
	sort.Strings(names)
	covered := 0
	var gaps []string
	for _, name := range names {
		item := byTech[name]
		if item.disabled && item.gap == "" && !item.executed {
			continue
		}
		if item.gap == "" && !item.executed {
			item.gap = name + " : détectée, aucun contrôle au catalogue"
		}
		if item.gap != "" {
			gaps = append(gaps, item.gap)
			continue
		}
		covered++
	}
	if gaps == nil {
		gaps = []string{}
	}
	return covered + len(gaps), covered, gaps
}

func detectedTechnologies(discovery interface{}) []string {
	if discovery == nil {
		return nil
	}
	raw, err := json.Marshal(discovery)
	if err != nil {
		return nil
	}
	var view struct {
		Technologies []struct {
			Technology string `json:"technology"`
			Status     string `json:"status"`
		} `json:"technologies"`
	}
	if err := json.Unmarshal(raw, &view); err != nil {
		return nil
	}
	var names []string
	for _, tech := range view.Technologies {
		if tech.Status == "detected" && tech.Technology != "" {
			names = append(names, tech.Technology)
		}
	}
	sort.Strings(names)
	return names
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

// NormalizeReport returns a copy of a report with volatile timing, path separators,
// and engine versions standardized to canonical values for strict equality comparison.
func NormalizeReport(rawJSON []byte) (map[string]interface{}, error) {
	var m map[string]interface{}
	if err := json.Unmarshal(rawJSON, &m); err != nil {
		return nil, err
	}

	normalizeMap(m)
	return m, nil
}

func normalizeMap(m map[string]interface{}) {
	for k, v := range m {
		switch k {
		case "generated_at", "execution_start", "execution_end":
			m[k] = "2026-10-13T00:00:00Z"
		case "duration_ms", "discovery_ms", "resolver_ms", "compliance_ms", "reporting_ms":
			m[k] = float64(0)
		case "engine_version":
			m[k] = "CANONICAL_ENGINE_VERSION"
		case "run_id":
			m[k] = "CANONICAL_RUN_ID"
		}

		if str, ok := v.(string); ok {
			if strings.Contains(str, "\\") {
				m[k] = strings.ReplaceAll(str, "\\", "/")
			}
		} else if subMap, ok := v.(map[string]interface{}); ok {
			normalizeMap(subMap)
		} else if list, ok := v.([]interface{}); ok {
			for _, item := range list {
				if itemMap, ok := item.(map[string]interface{}); ok {
					normalizeMap(itemMap)
				}
			}
		}
	}
}

// CompareCanonicalReports compares two canonicalized report maps, returning differences.
func CompareCanonicalReports(rep1, rep2 map[string]interface{}) []string {
	var diffs []string

	v1, _ := rep1["verdict"].(string)
	v2, _ := rep2["verdict"].(string)
	if v1 != v2 {
		diffs = append(diffs, "Verdict mismatch: "+v1+" != "+v2)
	}

	s1, _ := rep1["summary"].(map[string]interface{})
	s2, _ := rep2["summary"].(map[string]interface{})
	if s1 != nil && s2 != nil {
		for _, key := range []string{"success", "fail", "error", "skipped"} {
			if s1[key] != s2[key] {
				diffs = append(diffs, "Summary "+key+" mismatch")
			}
		}
	}

	return diffs
}
