package engine

import (
	"context"
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
