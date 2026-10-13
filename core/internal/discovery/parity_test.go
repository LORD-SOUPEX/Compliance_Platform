package discovery

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDiscoveryParityAndExclusions valide la détection multi-technologies,
// les racines et les exclusions strictes sans dépendre de PowerShell ni appeler t.Skip().
func TestDiscoveryParityAndExclusions(t *testing.T) {
	tempDir := t.TempDir()

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

	// 3. Fichiers exclus devant être STRICTEMENT ignorés
	_ = os.MkdirAll(filepath.Join(tempDir, ".tools", "cache"), 0755)
	_ = os.WriteFile(filepath.Join(tempDir, ".tools", "cache", "hidden.py"), []byte("invalid\n"), 0644)
	_ = os.MkdirAll(filepath.Join(tempDir, ".venv"), 0755)
	_ = os.WriteFile(filepath.Join(tempDir, ".venv", "hidden.tf"), []byte("invalid\n"), 0644)
	_ = os.MkdirAll(filepath.Join(tempDir, "reports"), 0755)
	_ = os.WriteFile(filepath.Join(tempDir, "reports", "hidden.sh"), []byte("invalid\n"), 0644)

	// Exécution du moteur Go DiscoverAll
	goRes, err := DiscoverAll(tempDir)
	if err != nil {
		t.Fatalf("DiscoverAll failed: %v", err)
	}

	// Vérification stricte des exclusions
	for _, tr := range goRes.Technologies {
		if tr.Technology == "terraform" && tr.Status != "absent" {
			t.Errorf(".venv/hidden.tf non exclu, terraform status=%s", tr.Status)
		}
		if tr.Technology == "shell" && tr.Status != "absent" {
			t.Errorf("reports/hidden.sh non exclu, shell status=%s", tr.Status)
		}
	}

	// Vérification de la détection PowerShell dans le sous-dossier nested
	var psRecord *TechnologyRecord
	for i := range goRes.Technologies {
		if goRes.Technologies[i].Technology == "powershell" {
			psRecord = &goRes.Technologies[i]
			break
		}
	}
	if psRecord == nil || psRecord.Status != "detected" {
		t.Fatalf("PowerShell aurait dû être détecté")
	}
	if len(psRecord.Evidence) != 1 || psRecord.Evidence[0] != "nested/project/main.ps1" {
		t.Errorf("Preuve inattendue pour PowerShell: %v", psRecord.Evidence)
	}
	if len(psRecord.Roots) != 1 || psRecord.Roots[0] != "nested/project" {
		t.Errorf("Racines inattendues pour PowerShell: %v", psRecord.Roots)
	}

	// Vérification de la détection Python dans pkg
	var pyRecord *TechnologyRecord
	for i := range goRes.Technologies {
		if goRes.Technologies[i].Technology == "python" {
			pyRecord = &goRes.Technologies[i]
			break
		}
	}
	if pyRecord == nil || pyRecord.Status != "detected" {
		t.Fatalf("Python aurait dû être détecté")
	}
	if len(pyRecord.Roots) != 1 || pyRecord.Roots[0] != "pkg" {
		t.Errorf("Racines inattendues pour Python: %v", pyRecord.Roots)
	}

	// Vérification de l'intégrité du scan
	if !goRes.ScanComplete {
		t.Errorf("ScanComplete doit être true")
	}
	if len(goRes.ScanErrors) != 0 {
		t.Errorf("ScanErrors doit être vide, reçu: %v", goRes.ScanErrors)
	}
}
