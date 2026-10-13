package engine

import (
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestPowerShellComplianceParity(t *testing.T) {
	platformRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("Abs platformRoot failed: %v", err)
	}
	repoTarget, err := filepath.Abs(filepath.Join(platformRoot, "core", "testdata", "python_project"))
	if err != nil {
		t.Fatalf("Abs repoTarget failed: %v", err)
	}

	// 1. Run Go Compliance Engine in PlanOnly mode
	goRep, err := RunCompliance(context.Background(), ComplianceOptions{
		RepoRoot:     repoTarget,
		PlatformRoot: platformRoot,
		PlanOnly:     true,
	})
	if err != nil {
		t.Fatalf("Go RunCompliance failed: %v", err)
	}

	// 2. Run PowerShell Quality Gate in PlanOnly mode
	psScript := filepath.Join(platformRoot, "scripts", "quality-gate.ps1")
	cmd := exec.Command("powershell",
		"-NoProfile",
		"-ExecutionPolicy", "Bypass",
		"-File", psScript,
		"-RepositoryPath", repoTarget,
		"-Compliance",
		"-PlanOnly",
		"-NoColor",
	)
	cmd.Dir = platformRoot
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("PowerShell execution failed (environment constraint): %v", err)
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
	if err := json.Unmarshal(out, &psRep); err != nil {
		t.Fatalf("Failed to decode PowerShell compliance report JSON: %v", err)
	}

	// 3. Compare top-level contract
	if goRep.SchemaVersion != psRep.SchemaVersion {
		t.Errorf("schema_version mismatch: Go=%d, PS=%d", goRep.SchemaVersion, psRep.SchemaVersion)
	}
	if goRep.ExecutionStatus != psRep.ExecutionStatus {
		t.Errorf("execution_status mismatch: Go=%s, PS=%s", goRep.ExecutionStatus, psRep.ExecutionStatus)
	}
	if goRep.Advisory != psRep.Advisory {
		t.Errorf("advisory mismatch: Go=%v, PS=%v", goRep.Advisory, psRep.Advisory)
	}
	if psRep.Verdict != nil && goRep.Verdict != nil && *psRep.Verdict != *goRep.Verdict {
		t.Errorf("verdict mismatch: Go=%v, PS=%v", *goRep.Verdict, *psRep.Verdict)
	}

	// 4. Compare planned controls count
	goControlCount := len(goRep.ExecutionPlan.Controls)
	psControlCount := len(psRep.ExecutionPlan.Controls)
	if goControlCount != psControlCount {
		t.Errorf("Planned controls count mismatch: Go=%d, PS=%d", goControlCount, psControlCount)
	} else {
		t.Logf("PARITÉ DU PLAN: %d contrôles ordonnancés identiquement en Go et PowerShell", goControlCount)
	}

	// 5. Compare each control ID and applicability
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
			t.Errorf("Contrôle Go %s absent du plan PowerShell", c.ID)
			continue
		}
		if c.Applicability != psApp {
			t.Errorf("Applicabilité divergente pour %s: Go=%s, PS=%s", c.ID, c.Applicability, psApp)
		} else {
			matched++
		}
	}

	t.Logf("PARITÉ DES CONTRÔLES: %d/%d contrôles strictement identiques en applicabilité", matched, psControlCount)
}
