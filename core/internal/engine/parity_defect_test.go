package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestExecutionParityOnDefectFixture valide le verdict et le contrat d'exécution sur defect_fixture
// en le comparant au golden file historique PowerShell ps_defect_report.json, de manière autonome.
func TestExecutionParityOnDefectFixture(t *testing.T) {
	platformRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("Abs platformRoot failed: %v", err)
	}
	defectDir, err := filepath.Abs(filepath.Join(platformRoot, "core", "testdata", "defect_fixture"))
	if err != nil {
		t.Fatalf("Abs defectDir failed: %v", err)
	}

	// 1. Exécuter le moteur Go avec AllowCodeExecution: true, AllowNetwork: true
	goRep, err := RunCompliance(context.Background(), ComplianceOptions{
		RepoRoot:           defectDir,
		PlatformRoot:       platformRoot,
		PlanOnly:           false,
		AllowCodeExecution: true,
		AllowNetwork:       true,
	})
	if err != nil {
		t.Fatalf("Go RunCompliance failed: %v", err)
	}

	// 2. Charger le golden file historique PowerShell
	psRepPath := filepath.Join(platformRoot, "core", "testdata", "ps_defect_report.json")
	psBytes, err := os.ReadFile(psRepPath)
	if err != nil {
		t.Fatalf("Lecture du golden file ps_defect_report.json impossible: %v", err)
	}

	type PSDefectReport struct {
		SchemaVersion   int         `json:"schema_version"`
		ExecutionStatus string      `json:"execution_status"`
		Verdict         *string     `json:"verdict"`
		VerdictReasons  []string    `json:"verdict_reasons"`
		Summary         struct {
			Success int `json:"success"`
			Fail    int `json:"fail"`
			Error   int `json:"error"`
			Skipped int `json:"skipped"`
		} `json:"summary"`
		Coverage struct {
			Complete        bool `json:"complete"`
			PlannedControls int  `json:"planned_controls"`
		} `json:"coverage"`
	}

	var psRep PSDefectReport
	if err := json.Unmarshal(psBytes, &psRep); err != nil {
		t.Fatalf("Failed to parse golden file ps_defect_report.json: %v", err)
	}

	// 3. Assertions strictes de parité de contrat et verdict
	if goRep.SchemaVersion != psRep.SchemaVersion {
		t.Errorf("schema_version mismatch: Go=%d, Golden=%d", goRep.SchemaVersion, psRep.SchemaVersion)
	}

	if goRep.ExecutionStatus != "completed" {
		t.Errorf("execution_status attendu 'completed', obtenu: %s", goRep.ExecutionStatus)
	}

	if goRep.Verdict == nil || *goRep.Verdict != "FAIL" {
		t.Errorf("Verdict defect_fixture attendu 'FAIL', obtenu: %v", goRep.Verdict)
	}

	if psRep.Verdict != nil && (goRep.Verdict == nil || *goRep.Verdict != *psRep.Verdict) {
		t.Errorf("Verdict mismatch: Go=%v, Golden=%v", goRep.Verdict, psRep.Verdict)
	}

	if goRep.Coverage.Complete != false {
		t.Errorf("Coverage complete sur defect_fixture attendu 'false', obtenu: %v", goRep.Coverage.Complete)
	}

	if len(goRep.ExecutionPlan.Controls) != 28 {
		t.Errorf("Nombre de contrôles planifiés attendu 28, obtenu: %d", len(goRep.ExecutionPlan.Controls))
	}

	t.Logf("PARITÉ DEFECT VALIDÉE: Verdict Go=%s (FAIL strict), %d contrôles planifiés, couverture partielle confirmée",
		*goRep.Verdict, len(goRep.ExecutionPlan.Controls))
}
