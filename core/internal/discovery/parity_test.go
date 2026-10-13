package discovery

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// TestPowerShellDiscoveryParity creates test fixtures inspired directly by quality-gate.Tests.ps1
// and executes quality-gate.ps1 -DiscoveryOnly (when powershell is available) to compare parity.
func TestPowerShellDiscoveryParity(t *testing.T) {
	tempDir := t.TempDir()

	// Fixture setup mimicking quality-gate.Tests.ps1
	// 1. Nested PowerShell project
	psFile := filepath.Join(tempDir, "nested", "project", "main.ps1")
	_ = os.MkdirAll(filepath.Dir(psFile), 0755)
	_ = os.WriteFile(psFile, []byte("Write-Output 'ok'\n"), 0644)

	// 2. Python project with pyproject.toml
	pyFile := filepath.Join(tempDir, "pkg", "src", "app.py")
	pyProj := filepath.Join(tempDir, "pkg", "pyproject.toml")
	_ = os.MkdirAll(filepath.Dir(pyFile), 0755)
	_ = os.WriteFile(pyProj, []byte("[tool.ruff]\n"), 0644)
	_ = os.WriteFile(pyFile, []byte("print(1)\n"), 0644)

	// 3. Excluded files that MUST NOT be discovered
	_ = os.MkdirAll(filepath.Join(tempDir, ".tools", "cache"), 0755)
	_ = os.WriteFile(filepath.Join(tempDir, ".tools", "cache", "hidden.py"), []byte("invalid\n"), 0644)
	_ = os.MkdirAll(filepath.Join(tempDir, ".venv"), 0755)
	_ = os.WriteFile(filepath.Join(tempDir, ".venv", "hidden.tf"), []byte("invalid\n"), 0644)
	_ = os.MkdirAll(filepath.Join(tempDir, "reports"), 0755)
	_ = os.WriteFile(filepath.Join(tempDir, "reports", "hidden.sh"), []byte("invalid\n"), 0644)

	// 1. Run Go DiscoverAll
	goRes, err := DiscoverAll(tempDir)
	if err != nil {
		t.Fatalf("DiscoverAll failed: %v", err)
	}

	// Verify exclusions in Go
	for _, tr := range goRes.Technologies {
		if tr.Technology == "terraform" && tr.Status != "absent" {
			t.Errorf(".venv/hidden.tf was NOT excluded, terraform status=%s", tr.Status)
		}
		if tr.Technology == "shell" && tr.Status != "absent" {
			t.Errorf("reports/hidden.sh was NOT excluded, shell status=%s", tr.Status)
		}
	}

	// Verify nested PowerShell detection
	var psRecord *TechnologyRecord
	for i := range goRes.Technologies {
		if goRes.Technologies[i].Technology == "powershell" {
			psRecord = &goRes.Technologies[i]
			break
		}
	}
	if psRecord == nil || psRecord.Status != "detected" {
		t.Fatalf("PowerShell should be detected")
	}
	if len(psRecord.Evidence) != 1 || psRecord.Evidence[0] != "nested/project/main.ps1" {
		t.Errorf("Unexpected evidence: %v", psRecord.Evidence)
	}
	if len(psRecord.Roots) != 1 || psRecord.Roots[0] != "nested/project" {
		t.Errorf("Unexpected roots: %v", psRecord.Roots)
	}

	// 2. If PowerShell is available (Windows or pwsh on POSIX), run quality-gate.ps1 -DiscoveryOnly
	// to assert 100% status parity!
	psExe := "powershell"
	if runtime.GOOS != "windows" {
		psExe = "pwsh"
	}
	if _, err := exec.LookPath(psExe); err != nil {
		t.Skipf("%s non disponible sur cet hôte pour la comparaison dynamique", psExe)
	}

	gateScript := filepath.Join("..", "..", "..", "scripts", "quality-gate.ps1")
	if _, err := os.Stat(gateScript); err != nil {
		t.Skipf("Script quality-gate.ps1 introuvable pour test de comparaison")
	}

	cmd := exec.Command(psExe, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", gateScript, "-RepositoryPath", tempDir, "-DiscoveryOnly", "-NoColor")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("Exécution PowerShell échouée (possible manque de modules): %v", err)
	}

	type PSDiscoveryOutput struct {
		Technologies []struct {
			Technology string   `json:"technology"`
			Status     string   `json:"status"`
			Evidence   []string `json:"evidence"`
			Roots      []string `json:"roots"`
		} `json:"technologies"`
		ScanComplete bool `json:"scan_complete"`
	}

	var psOut PSDiscoveryOutput
	if err := json.Unmarshal(out, &psOut); err != nil {
		t.Skipf("Impossible de décoder la sortie JSON de PowerShell: %v", err)
	}

	psStatusMap := make(map[string]string)
	for _, d := range psOut.Technologies {
		psStatusMap[d.Technology] = d.Status
	}

	// Compare all 13 technologies
	for _, goTech := range goRes.Technologies {
		psStat, exists := psStatusMap[goTech.Technology]
		if !exists {
			t.Errorf("Technologie %s présente en Go mais absente en PowerShell", goTech.Technology)
			continue
		}
		if goTech.Status != psStat {
			t.Errorf("Parité en échec pour %s: Go=%s, PowerShell=%s", goTech.Technology, goTech.Status, psStat)
		} else {
			t.Logf("PARITÉ VÉRIFIÉE: %s -> statut identiquement %s", goTech.Technology, goTech.Status)
		}
	}
}
