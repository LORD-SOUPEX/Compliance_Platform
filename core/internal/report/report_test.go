package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestReportParityAndNormalization(t *testing.T) {
	goReportPath := filepath.Join("..", "..", "testdata", "go_report.json")
	goBytes, err := os.ReadFile(goReportPath)
	if err != nil {
		t.Fatalf("go_report.json introuvable: %v", err)
	}

	normGo, err := NormalizeReport(goBytes)
	if err != nil {
		t.Fatalf("NormalizeReport(go) failed: %v", err)
	}

	// Verify normalized values
	if normGo["generated_at"] != "2026-10-13T00:00:00Z" {
		t.Errorf("expected normalized generated_at, got %v", normGo["generated_at"])
	}
	if normGo["engine_version"] != "CANONICAL_ENGINE_VERSION" {
		t.Errorf("expected normalized engine_version, got %v", normGo["engine_version"])
	}

	meta, ok := normGo["metadata"].(map[string]interface{})
	if !ok || meta["run_id"] != "CANONICAL_RUN_ID" {
		t.Errorf("expected normalized run_id, got %v", meta["run_id"])
	}

	psReportPath := filepath.Join("..", "..", "testdata", "ps_report.json")
	psBytes, err := os.ReadFile(psReportPath)
	if err != nil {
		t.Fatalf("ps_report.json introuvable: %v", err)
	}

	normPS, err := NormalizeReport(psBytes)
	if err != nil {
		t.Fatalf("NormalizeReport(ps) failed: %v", err)
	}

	if normGo["schema_version"] != normPS["schema_version"] {
		t.Errorf("schema_version mismatch: %v vs %v", normGo["schema_version"], normPS["schema_version"])
	}
}

// TestCoverageOmittedRequiredControls valide qu'un contrôle requis omis (skipped ou manquant)
// force le verdict à FAIL et OmittedRequiredControls > 0.
func TestCoverageOmittedRequiredControls(t *testing.T) {
	plan := ExecutionPlan{
		SchemaVersion: 1,
		Repository:    "C:/repo",
		Budgets: Budgets{
			TimeoutSeconds:          1800,
			MaxOutputBytesPerStream: 1048576,
			MaxControls:             10,
		},
		Controls: []interface{}{
			map[string]interface{}{
				"id":            "control.required.one",
				"name":          "Required Control 1",
				"applicability": "applicable",
				"required":      true,
			},
			map[string]interface{}{
				"id":            "control.optional.two",
				"name":          "Optional Control 2",
				"applicability": "applicable",
				"required":      false,
			},
		},
	}

	// Scénario 1: Le contrôle requis a été omis (status: skipped)
	resultsSkippedRequired := []ExecutionResult{
		{
			ControlId: "control.required.one",
			Name:      "Required Control 1",
			Status:    "skipped",
		},
		{
			ControlId: "control.optional.two",
			Name:      "Optional Control 2",
			Status:    "success",
		},
	}

	rep := BuildComplianceReport(ReportOptions{
		Repository:   "C:/repo",
		RunID:        "run-omitted-test-01",
		Platform:     "windows-x64",
		Plan:         plan,
		Results:      resultsSkippedRequired,
		ScanComplete: true,
		PlanOnly:     false,
	})

	if rep.Coverage.Complete {
		t.Errorf("Coverage.Complete doit être false lorsqu'un contrôle requis est omis")
	}
	if rep.Coverage.OmittedRequiredControls != 1 {
		t.Errorf("OmittedRequiredControls attendu 1, obtenu %d", rep.Coverage.OmittedRequiredControls)
	}
	if rep.Verdict == nil || *rep.Verdict != "FAIL" {
		t.Errorf("Verdict attendu FAIL lorsqu'un contrôle requis est omis, obtenu %v", rep.Verdict)
	}

	// Scénario 2: Contrôle requis et optionnel tous deux en succès -> PASS et Complete=true
	resultsAllSuccess := []ExecutionResult{
		{
			ControlId: "control.required.one",
			Name:      "Required Control 1",
			Status:    "success",
		},
		{
			ControlId: "control.optional.two",
			Name:      "Optional Control 2",
			Status:    "success",
		},
	}

	repSuccess := BuildComplianceReport(ReportOptions{
		Repository:   "C:/repo",
		RunID:        "run-success-test-02",
		Platform:     "windows-x64",
		Plan:         plan,
		Results:      resultsAllSuccess,
		ScanComplete: true,
		PlanOnly:     false,
	})

	if !repSuccess.Coverage.Complete {
		t.Errorf("Coverage.Complete attendu true pour tous contrôles exécutés avec succès")
	}
	if repSuccess.Coverage.OmittedRequiredControls != 0 {
		t.Errorf("OmittedRequiredControls attendu 0, obtenu %d", repSuccess.Coverage.OmittedRequiredControls)
	}
	if repSuccess.Verdict == nil || *repSuccess.Verdict != "PASS" {
		t.Errorf("Verdict attendu PASS, obtenu %v", repSuccess.Verdict)
	}
}

// TestDuplicateAndMissingResultsDetection valide la détection de résultats corrompus ou dupliqués
func TestDuplicateAndMissingResultsDetection(t *testing.T) {
	plan := ExecutionPlan{
		SchemaVersion: 1,
		Repository:    "C:/repo",
		Controls: []interface{}{
			map[string]interface{}{
				"id":            "ctrl.alpha",
				"applicability": "applicable",
				"required":      true,
			},
			map[string]interface{}{
				"id":            "ctrl.beta",
				"applicability": "applicable",
				"required":      true,
			},
		},
	}

	// Résultat dupliqué pour ctrl.alpha
	resultsDup := []ExecutionResult{
		{ControlId: "ctrl.alpha", Status: "success"},
		{ControlId: "ctrl.alpha", Status: "success"},
		{ControlId: "ctrl.beta", Status: "success"},
	}

	repDup := BuildComplianceReport(ReportOptions{
		Repository:   "C:/repo",
		RunID:        "run-dup-test",
		Plan:         plan,
		Results:      resultsDup,
		ScanComplete: true,
		PlanOnly:     false,
	})

	if repDup.Verdict == nil || *repDup.Verdict != "FAIL" {
		t.Errorf("Verdict attendu FAIL en cas de doublon de résultats, obtenu %v", repDup.Verdict)
	}
	if repDup.Coverage.Complete {
		t.Errorf("Coverage.Complete attendu false en présence de doublon")
	}

	// Résultat manquant pour ctrl.beta
	resultsMissing := []ExecutionResult{
		{ControlId: "ctrl.alpha", Status: "success"},
	}

	repMissing := BuildComplianceReport(ReportOptions{
		Repository:   "C:/repo",
		RunID:        "run-missing-test",
		Plan:         plan,
		Results:      resultsMissing,
		ScanComplete: true,
		PlanOnly:     false,
	})

	if repMissing.Verdict == nil || *repMissing.Verdict != "FAIL" {
		t.Errorf("Verdict attendu FAIL en cas de résultat manquant, obtenu %v", repMissing.Verdict)
	}
	if repMissing.Coverage.Complete {
		t.Errorf("Coverage.Complete attendu false en cas de résultat manquant")
	}
}

// TestComplianceReportJSONSchemaConformity valide la conformité stricte du JSON produit
// avec tous les champs requis par le schéma draft 2020-12
func TestComplianceReportJSONSchemaConformity(t *testing.T) {
	plan := ExecutionPlan{
		SchemaVersion: 1,
		Repository:    "C:/repo",
		Budgets: Budgets{
			TimeoutSeconds:          300,
			MaxOutputBytesPerStream: 1048576,
			MaxControls:             5,
		},
		Permissions: Permissions{
			Network:       false,
			CodeExecution: false,
		},
		Controls: []interface{}{
			map[string]interface{}{
				"id":            "ctrl.one",
				"applicability": "applicable",
				"required":      true,
			},
		},
	}

	rep := BuildComplianceReport(ReportOptions{
		Repository:                  "C:/repo",
		RunID:                       "0123456789abcdef0123456789abcdef",
		Platform:                    "windows-x64",
		Plan:                        plan,
		Results:                     []ExecutionResult{{ControlId: "ctrl.one", Status: "success"}},
		Metrics:                     &Metrics{DiscoveryMs: 1, ResolverMs: 1, ComplianceMs: 10, ReportingMs: 2},
		ScanComplete:                true,
		PlatformQualificationStatus: "qualified",
		Adapter:                     "Go",
	})

	bytes, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("Marshal report failed: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(bytes, &raw); err != nil {
		t.Fatalf("Unmarshal to map failed: %v", err)
	}

	requiredFields := []string{
		"schema_version", "engine_version", "generated_at", "metadata",
		"repository", "execution_status", "discovery", "matrix", "resolver",
		"execution_plan", "execution_results", "findings", "diagnostics",
		"summary", "coverage", "limitations", "verdict", "verdict_reasons", "advisory",
	}

	for _, field := range requiredFields {
		if _, exists := raw[field]; !exists {
			t.Errorf("Champ requis manquant dans le rapport JSON: %s", field)
		}
	}

	meta, ok := raw["metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("metadata n'est pas un objet")
	}
	if meta["source_adapter"] != "Go" {
		t.Errorf("source_adapter attendu 'Go', obtenu %v", meta["source_adapter"])
	}
	if meta["platform_qualification_status"] != "qualified" {
		t.Errorf("platform_qualification_status attendu 'qualified', obtenu %v", meta["platform_qualification_status"])
	}
}
