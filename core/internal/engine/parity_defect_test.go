package engine

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"compliance/internal/osutil"
)

func TestExecutionParityOnDefectFixture(t *testing.T) {
	platformRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("Abs platformRoot failed: %v", err)
	}
	defectDir, err := filepath.Abs(filepath.Join(platformRoot, "core", "testdata", "defect_fixture"))
	if err != nil {
		t.Fatalf("Abs defectDir failed: %v", err)
	}

	// 1. Exécuter le moteur Go avec PlanOnly: false, AllowCodeExecution: true, AllowNetwork: true
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

	goBytes, err := json.MarshalIndent(goRep, "", "  ")
	if err != nil {
		t.Fatalf("Go Marshal failed: %v", err)
	}
	outPath := filepath.Join(platformRoot, "core", "testdata", "go_defect_report.json")
	if err := os.WriteFile(outPath, goBytes, 0644); err != nil {
		t.Fatalf("Failed to write go_defect_report.json: %v", err)
	}

	// 2. Exécuter le moteur PowerShell avec -Compliance -AllowCodeExecution -AllowNetwork
	psScript := filepath.Join(platformRoot, "scripts", "quality-gate.ps1")
	psRepPath := filepath.Join(platformRoot, "core", "testdata", "ps_defect_report.json")
	psCmd := exec.Command("powershell",
		"-NoProfile",
		"-ExecutionPolicy", "Bypass",
		"-File", psScript,
		"-RepositoryPath", defectDir,
		"-Compliance",
		"-AllowCodeExecution",
		"-AllowNetwork",
		"-NoColor",
		"-ReportPath", psRepPath,
	)
	psCmd.Dir = platformRoot
	osutil.SetHideWindow(psCmd)
	_ = psCmd.Run() // exit code 1 is expected on defect fixture

	t.Logf("Go defect report generated at %s, verdict=%v, reasons=%v", outPath, goRep.Verdict, goRep.VerdictReasons)
}
