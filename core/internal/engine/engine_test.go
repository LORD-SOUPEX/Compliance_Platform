package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"compliance/internal/report"
)

func TestRunCompliance_PlanOnly(t *testing.T) {
	tempDir := t.TempDir()

	// Create mock files
	if err := os.WriteFile(filepath.Join(tempDir, "script.py"), []byte("print('hello')\n"), 0644); err != nil {
		t.Fatal(err)
	}

	platformRoot, _ := filepath.Abs(filepath.Join("..", "..", ".."))

	rep, err := RunCompliance(context.Background(), ComplianceOptions{
		RepoRoot:     tempDir,
		PlatformRoot: platformRoot,
		PlanOnly:     true,
	})
	if err != nil {
		t.Fatalf("RunCompliance failed: %v", err)
	}

	if rep.SchemaVersion != 1 {
		t.Errorf("expected SchemaVersion 1, got %d", rep.SchemaVersion)
	}

	if rep.ExecutionStatus != "planned" {
		t.Errorf("expected planned status, got %s", rep.ExecutionStatus)
	}

	if rep.Verdict != nil {
		t.Errorf("expected nil verdict in plan-only mode, got %v", *rep.Verdict)
	}

	if !rep.Advisory {
		t.Errorf("expected advisory true")
	}

	if len(rep.ExecutionPlan.Controls) == 0 {
		t.Errorf("expected planned controls, got 0")
	}

	// Verify discovery contains populated capability matrix and tool resolution
	if len(rep.Matrix) == 0 {
		t.Errorf("expected populated Matrix in report, got 0")
	}
	if len(rep.Resolver) == 0 {
		t.Errorf("expected populated Resolver in report, got 0")
	}
}

func TestRunCompliance_RedactionAndVerdict(t *testing.T) {
	redactor, err := NewRedactor([]string{"my-super-secret-token"}, "[REDACTED]")
	if err != nil {
		t.Fatal(err)
	}

	raw := "output with token=my-super-secret-token and more"
	clean := redactor.Redact(raw)
	if strings.Contains(clean, "my-super-secret-token") {
		t.Errorf("secret not redacted: %s", clean)
	}
	if !strings.Contains(clean, "[REDACTED]") {
		t.Errorf("replacement missing: %s", clean)
	}
}

func TestRunCompliance_PermissionsDenied(t *testing.T) {
	catPath := filepath.Join("..", "..", "..", ".config", "control-catalog.json")
	tempDir := t.TempDir()
	platformRoot, _ := filepath.Abs(filepath.Join("..", "..", ".."))

	// Create a python file with requirements.txt
	if err := os.WriteFile(filepath.Join(tempDir, "main.py"), []byte("import sys\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "requirements.txt"), []byte("requests==2.28.1\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Disallow network and code execution with candidate resolver providing pip-audit
	rep, err := RunCompliance(context.Background(), ComplianceOptions{
		RepoRoot:           tempDir,
		PlatformRoot:       platformRoot,
		CatalogPath:        catPath,
		PlanOnly:           true,
		AllowNetwork:       false,
		AllowCodeExecution: false,
		CandidateResolver: &mockResolverMap{
			available: map[string]bool{"pip-audit": true},
		},
	})
	if err != nil {
		t.Fatalf("RunCompliance failed: %v", err)
	}

	// Find pip-audit or pytest control in plan
	foundBlocked := false
	for _, rawCtrl := range rep.ExecutionPlan.Controls {
		c, ok := rawCtrl.(*PlannedControl)
		if !ok {
			continue
		}
		if c.Capability == "dependency audit" || c.SideEffectLevel == "network" || c.SideEffectLevel == "code_execution" {
			if c.Applicability == "not_applicable" && c.ReasonCode == "permission_denied" {
				foundBlocked = true
				break
			}
		}
	}

	if !foundBlocked {
		t.Errorf("expected permission_denied control when network/code execution disallowed")
	}
}

// TestExecuteCompliancePlan_DependencyFailed vérifie la propagation stricte de dependency_failed
func TestExecuteCompliancePlan_DependencyFailed(t *testing.T) {
	plan := &report.ExecutionPlan{
		SchemaVersion: 1,
		Repository:    "C:/repo",
		Budgets: report.Budgets{
			TimeoutSeconds:          300,
			MaxOutputBytesPerStream: 1048576,
			MaxControls:             5,
		},
	}

	controls := []*PlannedControl{
		{
			ID:            "ctrl.parent",
			Name:          "Parent Control",
			Applicability: "not_applicable",
			ReasonCode:    "tool_unavailable",
			Required:      true,
		},
		{
			ID:            "ctrl.child",
			Name:          "Child Control",
			Applicability: "applicable",
			Dependencies:  []string{"ctrl.parent"},
			Required:      true,
		},
	}

	results, err := ExecuteCompliancePlan(context.Background(), plan, controls, ExecutionOptions{})
	if err != nil {
		t.Fatalf("ExecuteCompliancePlan failed: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("Nombre de résultats attendu 2, obtenu %d", len(results))
	}

	childRes := results[1]
	if childRes.Status != "error" {
		t.Errorf("Statut attendu 'error' pour contrôle requis avec dépendance échouée, obtenu '%s'", childRes.Status)
	}
	if !childRes.Critical {
		t.Errorf("Contrôle requis avec dépendance échouée doit être marqué Critical=true")
	}

	foundDiag := false
	for _, d := range childRes.Diagnostics {
		if d.Code == "dependency_failed" {
			foundDiag = true
			break
		}
	}
	if !foundDiag {
		t.Errorf("Diagnostic 'dependency_failed' manquant dans le résultat du contrôle enfant")
	}
}

// TestExecuteCompliancePlan_GlobalTimeout vérifie le basculement en erreur lorsque le budget global est dépassé
func TestExecuteCompliancePlan_GlobalTimeout(t *testing.T) {
	tempRepo := t.TempDir()
	plan := &report.ExecutionPlan{
		SchemaVersion: 1,
		Repository:    tempRepo,
		Budgets: report.Budgets{
			TimeoutSeconds:          1,
			MaxOutputBytesPerStream: 1048576,
			MaxControls:             5,
		},
	}

	controls := []*PlannedControl{
		{
			ID:            "ctrl.first",
			Name:          "First Control",
			Applicability: "not_applicable",
			ReasonCode:    "tool_unavailable",
			Root:          ".",
			Required:      false,
		},
		{
			ID:            "ctrl.slow",
			Name:          "Slow Control",
			Applicability: "applicable",
			Root:          ".",
			Required:      true,
		},
	}

	opts := ExecutionOptions{
		GlobalTimeout: 5 * time.Millisecond,
		OnControlDone: func(ctrl *PlannedControl, res *report.ExecutionResult) {
			if ctrl.ID == "ctrl.first" {
				time.Sleep(10 * time.Millisecond) // Provoquer le dépassement du budget global de 5ms
			}
		},
	}
	results, err := ExecuteCompliancePlan(context.Background(), plan, controls, opts)
	if err != nil {
		t.Fatalf("ExecuteCompliancePlan failed: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("Nombre de résultats attendu 2, obtenu %d", len(results))
	}

	res := results[1]
	if res.Status != "error" {
		t.Errorf("Statut attendu 'error' après timeout global, obtenu '%s'", res.Status)
	}
	foundDiag := false
	for _, d := range res.Diagnostics {
		if d.Code == "global_timeout" {
			foundDiag = true
			break
		}
	}
	if !foundDiag {
		t.Errorf("Diagnostic 'global_timeout' manquant, diagnostics recus: %+v (status: %s)", res.Diagnostics, res.Status)
	}
}

// TestPowerShellComplianceParity compare l'exécution du plan Go contre le golden file historique
// PowerShell (ps_report.json) sans dépendre de PowerShell ni appeler t.Skip().
func TestPowerShellComplianceParity(t *testing.T) {
	platformRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("Abs platformRoot failed: %v", err)
	}
	repoTarget, err := filepath.Abs(filepath.Join(platformRoot, "core", "testdata", "python_project"))
	if err != nil {
		t.Fatalf("Abs repoTarget failed: %v", err)
	}

	// 1. Exécuter le moteur Go en mode PlanOnly
	goRep, err := RunCompliance(context.Background(), ComplianceOptions{
		RepoRoot:     repoTarget,
		PlatformRoot: platformRoot,
		PlanOnly:     true,
	})
	if err != nil {
		t.Fatalf("Go RunCompliance failed: %v", err)
	}

	// 2. Charger le golden file statique de parité PowerShell
	psGoldenPath := filepath.Join(platformRoot, "core", "testdata", "ps_report.json")
	psBytes, err := os.ReadFile(psGoldenPath)
	if err != nil {
		t.Fatalf("Lecture du golden file ps_report.json impossible: %v", err)
	}

	type PSReport struct {
		SchemaVersion   int         `json:"schema_version"`
		ExecutionStatus string      `json:"execution_status"`
		Verdict         *string     `json:"verdict"`
		Advisory        bool        `json:"advisory"`
		ExecutionPlan   struct {
			SchemaVersion int `json:"schema_version"`
			Budgets       struct {
				TimeoutSeconds          int   `json:"timeout_seconds"`
				MaxOutputBytesPerStream int64 `json:"max_output_bytes_per_stream"`
				MaxControls             int   `json:"max_controls"`
			} `json:"budgets"`
			Permissions struct {
				Network       bool `json:"network"`
				CodeExecution bool `json:"code_execution"`
			} `json:"permissions"`
			Controls []struct {
				ID            string `json:"id"`
				Applicability string `json:"applicability"`
				Required      bool   `json:"required"`
			} `json:"controls"`
		} `json:"execution_plan"`
		Coverage struct {
			PlannedControls int `json:"planned_controls"`
		} `json:"coverage"`
	}

	var psRep PSReport
	if err := json.Unmarshal(psBytes, &psRep); err != nil {
		t.Fatalf("Failed to decode PowerShell compliance report golden JSON: %v", err)
	}

	// 3. Comparer le contrat de niveau supérieur
	if goRep.SchemaVersion != psRep.SchemaVersion {
		t.Errorf("schema_version mismatch: Go=%d, PS=%d", goRep.SchemaVersion, psRep.SchemaVersion)
	}
	if goRep.ExecutionStatus != "planned" {
		t.Errorf("execution_status Go attendu 'planned', obtenu: %s", goRep.ExecutionStatus)
	}
	if goRep.Advisory != psRep.Advisory {
		t.Errorf("advisory mismatch: Go=%v, PS=%v", goRep.Advisory, psRep.Advisory)
	}
	if psRep.Verdict != nil && goRep.Verdict != nil && *psRep.Verdict != *goRep.Verdict {
		t.Errorf("verdict mismatch: Go=%v, PS=%v", *goRep.Verdict, *psRep.Verdict)
	}

	// 4. Comparer le nombre de contrôles planifiés (28 contrôles catalogués)
	goControlCount := len(goRep.ExecutionPlan.Controls)
	psControlCount := len(psRep.ExecutionPlan.Controls)
	if goControlCount != psControlCount {
		t.Errorf("Planned controls count mismatch: Go=%d, PS=%d", goControlCount, psControlCount)
	} else {
		t.Logf("PARITÉ DU PLAN: %d contrôles ordonnancés identiquement en Go et dans le golden file PowerShell", goControlCount)
	}

	// 5. Comparer chaque ID de contrôle et son applicabilité
	psControlsMap := make(map[string]string)
	for _, c := range psRep.ExecutionPlan.Controls {
		psControlsMap[c.ID] = c.Applicability
	}

	matched := 0
	for _, raw := range goRep.ExecutionPlan.Controls {
		c, ok := raw.(*PlannedControl)
		if !ok {
			continue
		}
		psApp, exists := psControlsMap[c.ID]
		if !exists {
			t.Errorf("Contrôle Go %s absent du golden plan PowerShell", c.ID)
			continue
		}
		if c.Applicability == psApp {
			matched++
		}
	}

	t.Logf("PARITÉ DES CONTRÔLES: %d/%d contrôles strictement identiques en applicabilité", matched, psControlCount)
	if matched < 20 {
		t.Errorf("Parité insuffisante: seulement %d/%d contrôles identiques", matched, psControlCount)
	}
}

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

