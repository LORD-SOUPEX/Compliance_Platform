package report

import "strings"
import "testing"

func TestCoverageUsesApplicableScope(t *testing.T) {
	exit := 0
	report := BuildComplianceReport(ReportOptions{
		Repository:   "repo",
		RunID:        "run",
		Platform:     "windows-x64",
		ScanComplete: true,
		DiscoveryData: map[string]interface{}{
			"technologies": []interface{}{
				map[string]interface{}{"technology": "javascript", "status": "detected"},
				map[string]interface{}{"technology": "markdown", "status": "detected"},
				map[string]interface{}{"technology": "terraform", "status": "absent"},
			},
		},
		Plan: ExecutionPlan{Controls: []interface{}{
			map[string]interface{}{"id": "javascript/linting/eslint/."},
			map[string]interface{}{"id": "javascript/security/gitleaks/."},
			map[string]interface{}{"id": "terraform/formatting/terraform/."},
		}},
		Results: []ExecutionResult{
			{ControlId: "javascript/linting/eslint/.", Technology: "javascript", Status: "success", ExitCode: &exit},
			{ControlId: "javascript/security/gitleaks/.", Technology: "javascript", Status: "skipped", Diagnostics: []Diagnostic{{Code: "tool_unavailable", Message: "Outil manquant : gitleaks."}}},
			{ControlId: "terraform/formatting/terraform/.", Technology: "terraform", Status: "skipped", Diagnostics: []Diagnostic{{Code: "technology_absent", Message: "absente"}}},
		},
	})
	if report.Coverage.DetectedTechnologies != 2 || report.Coverage.CoveredTechnologies != 0 {
		t.Fatalf("technologies = %d/%d, want 0 covered of 2 detected", report.Coverage.CoveredTechnologies, report.Coverage.DetectedTechnologies)
	}
	if report.Coverage.Complete || !strings.Contains(report.Coverage.Label, "Couverture partielle") || !strings.Contains(report.Coverage.Label, "0 technologie(s) couverte(s) sur 2 détectée(s)") {
		t.Fatalf("label = %q", report.Coverage.Label)
	}
	joined := strings.Join(report.VerdictReasons, " ")
	if report.VerdictReasons[0] != report.Coverage.Label || !strings.Contains(joined, "markdown") || !strings.Contains(joined, "gitleaks") {
		t.Fatalf("reasons = %v", report.VerdictReasons)
	}
}

func TestNothingExecutedStaysUnevaluated(t *testing.T) {
	report := BuildComplianceReport(ReportOptions{
		Repository:   "repo",
		RunID:        "run",
		Platform:     "windows-x64",
		ScanComplete: true,
		Plan:         ExecutionPlan{Controls: []interface{}{map[string]interface{}{"id": "terraform/formatting/terraform/."}}},
		Results: []ExecutionResult{
			{ControlId: "terraform/formatting/terraform/.", Technology: "terraform", Status: "skipped", Diagnostics: []Diagnostic{{Code: "technology_absent", Message: "absente"}}},
		},
	})
	if report.Verdict != nil {
		t.Fatalf("verdict = %s, want null", *report.Verdict)
	}
	if report.Coverage.ApplicableControls != 0 || report.Coverage.Complete {
		t.Fatalf("coverage = %+v", report.Coverage)
	}
}

func TestAmbiguousAndAlternativeStayOutsideApplicableScope(t *testing.T) {
	exit := 0
	report := BuildComplianceReport(ReportOptions{
		Repository:   "repo",
		RunID:        "run",
		Platform:     "windows-x64",
		ScanComplete: true,
		Plan: ExecutionPlan{Controls: []interface{}{
			map[string]interface{}{"id": "python/lint/ruff/."},
			map[string]interface{}{"id": "kubernetes/security/trivy/."},
			map[string]interface{}{"id": "helm/security/trivy/."},
			map[string]interface{}{"id": "javascript/linting/eslint/."},
		}},
		Results: []ExecutionResult{
			{ControlId: "python/lint/ruff/.", Technology: "python", Status: "success", ExitCode: &exit},
			{ControlId: "kubernetes/security/trivy/.", Technology: "kubernetes", Status: "skipped", Diagnostics: []Diagnostic{{Code: "ambiguous", Message: "template Helm"}}},
			{ControlId: "helm/security/trivy/.", Technology: "helm", Status: "skipped", Diagnostics: []Diagnostic{{Code: "alternative_not_selected", Message: "checkov retenu"}}},
			{ControlId: "javascript/linting/eslint/.", Technology: "javascript", Status: "skipped", Diagnostics: []Diagnostic{{Code: "repository_unconfigured", Message: "config absente"}}},
		},
	})
	if report.Coverage.ApplicableControls != 2 || report.Coverage.ExecutedControls != 1 {
		t.Fatalf("applicable=%d executed=%d", report.Coverage.ApplicableControls, report.Coverage.ExecutedControls)
	}
}
