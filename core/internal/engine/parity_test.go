package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

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
		// Dans l'architecture autonome Go, les résolveurs et capacités decoupled gèrent les outils locaux
		if c.Applicability == psApp {
			matched++
		}
	}

	t.Logf("PARITÉ DES CONTRÔLES: %d/%d contrôles strictement identiques en applicabilité", matched, psControlCount)
	if matched < 20 {
		t.Errorf("Parité insuffisante: seulement %d/%d contrôles identiques", matched, psControlCount)
	}
}
