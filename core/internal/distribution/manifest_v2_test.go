package distribution

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPhase1ManifestAndSignature(t *testing.T) {
	manifestPath := filepath.Join("..", "..", "..", ".config", "runtime-manifest.json")
	sigPath := filepath.Join("..", "..", "..", ".config", "runtime-manifest.json.sig")

	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("Lecture du manifeste impossible: %v", err)
	}

	sigBytes, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatalf("Lecture de la signature impossible: %v", err)
	}

	// 1. Parser en Go selon RuntimeManifest v2
	var manifest RuntimeManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("Désérialisation RuntimeManifest échouée: %v", err)
	}

	if manifest.SchemaVersion != 2 {
		t.Errorf("Attendu SchemaVersion=2, obtenu %d", manifest.SchemaVersion)
	}
	if manifest.ManifestVersion != "2.0.0" {
		t.Errorf("Attendu ManifestVersion='2.0.0', obtenu %s", manifest.ManifestVersion)
	}

	// Vérifier la présence des plateformes clés
	for _, plat := range []string{"windows-x64", "linux-x64", "macos-arm64"} {
		if _, ok := manifest.Platforms[plat]; !ok {
			t.Errorf("Plateforme %s absente du manifeste", plat)
		}
	}

	// 2. Vérification cryptographique Ed25519 avec la clé publique par défaut
	pubBytes, err := hex.DecodeString(DefaultPhase0PublicKeyHex)
	if err != nil {
		t.Fatalf("Décodage de la clé publique échoué: %v", err)
	}

	pubKey := ed25519.PublicKey(pubBytes)
	if err := VerifyManifest(manifestBytes, string(sigBytes), pubKey); err != nil {
		t.Fatalf("Vérification Ed25519 du manifeste officiel échouée: %v", err)
	}

	// 3. Test de non-régression : altération d'un octet doit échouer
	tamperedBytes := append([]byte(nil), manifestBytes...)
	tamperedBytes[len(tamperedBytes)-2] = ' '
	if err := VerifyManifest(tamperedBytes, string(sigBytes), pubKey); err == nil {
		t.Errorf("L'altération du manifeste aurait dû être rejetée par VerifyManifest")
	}
}

func TestManifestHashesUniqueness(t *testing.T) {
	manifestPath := filepath.Join("..", "..", "..", ".config", "runtime-manifest.json")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("Lecture du manifeste impossible: %v", err)
	}

	var manifest RuntimeManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("Désérialisation échouée: %v", err)
	}

	seenHashes := make(map[string]string) // hash -> provenance

	for platName, plat := range manifest.Platforms {
		for toolName, tool := range plat.Tools {
			// Check archive hash
			if len(tool.ArchiveSHA256) != 64 {
				t.Errorf("ArchiveSHA256 invalide pour %s/%s: %s", platName, toolName, tool.ArchiveSHA256)
			}
			if prev, exists := seenHashes[tool.ArchiveSHA256]; exists {
				if !strings.Contains(prev, "/"+toolName) {
					t.Errorf("DOUBLON DÉTECTÉ: hash archive %s partagé entre %s et %s/%s",
						tool.ArchiveSHA256, prev, platName, toolName)
				}
			} else {
				seenHashes[tool.ArchiveSHA256] = platName + "/" + toolName + " (archive)"
			}

			// Check binary hash
			if len(tool.BinarySHA256) != 64 {
				t.Errorf("BinarySHA256 invalide pour %s/%s: %s", platName, toolName, tool.BinarySHA256)
			}
			if prev, exists := seenHashes[tool.BinarySHA256]; exists {
				if !strings.Contains(prev, "/"+toolName) {
					t.Errorf("DOUBLON DÉTECTÉ: hash binaire %s partagé entre %s et %s/%s",
						tool.BinarySHA256, prev, platName, toolName)
				}
			} else {
				seenHashes[tool.BinarySHA256] = platName + "/" + toolName + " (binary)"
			}
		}
	}

	if len(seenHashes) == 0 {
		t.Errorf("Aucun hash trouvé dans le manifeste !")
	}
	t.Logf("SUCCESS: %d hashes vérifiés, tous distincts et uniques !", len(seenHashes))
}

func TestExtractedBinaryHashesFromArchives(t *testing.T) {
	manifestPath := filepath.Join("..", "..", "..", ".config", "runtime-manifest.json")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("Lecture du manifeste impossible: %v", err)
	}

	var manifest RuntimeManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("Désérialisation échouée: %v", err)
	}

	cacheRoot := filepath.Join("..", "..", "..", ".tools", "cache")

	archiveFiles := map[string]string{
		"ruff":        filepath.Join(cacheRoot, "wheels", "ruff-0.16.10-py3-none-win_amd64.whl"),
		"gitleaks":    filepath.Join(cacheRoot, "gitleaks_8.30.1_windows_x64.zip"),
		"tflint":      filepath.Join(cacheRoot, "tflint_windows_amd64.zip"),
		"trivy":       filepath.Join(cacheRoot, "trivy_0.75.0_windows-64bit.zip"),
		"terraform":   filepath.Join(cacheRoot, "terraform_1.8.5_windows_amd64.zip"),
		"opentofu":    filepath.Join(cacheRoot, "tofu_1.8.2_windows_amd64.zip"),
		"shellcheck":  filepath.Join(cacheRoot, "shellcheck-v0.10.0.zip"),
		"terragrunt":  filepath.Join(cacheRoot, "terragrunt_windows_amd64.exe"),
		"hadolint":    filepath.Join(cacheRoot, "hadolint-windows-x86_64.exe"),
		"python":      filepath.Join(cacheRoot, "python-3.11.9-amd64.zip"),
		"bandit":      filepath.Join(cacheRoot, "wheels", "bandit-1.9.4-py3-none-any.whl"),
		"pylint":      filepath.Join(cacheRoot, "wheels", "pylint-4.1.2-py3-none-any.whl"),
		"pytest":      filepath.Join(cacheRoot, "wheels", "pytest-9.1.1-py3-none-any.whl"),
		"pip-audit":   filepath.Join(cacheRoot, "wheels", "pip_audit-2.10.1-py3-none-any.whl"),
		"checkov":     filepath.Join(cacheRoot, "wheels", "checkov-3.3.23-py3-none-any.whl"),
	}

	winPlat, ok := manifest.Platforms["windows-x64"]
	if !ok {
		t.Fatalf("Plateforme windows-x64 absente")
	}

	verifiedCount := 0
	for toolName, arcPath := range archiveFiles {
		tool, exists := winPlat.Tools[toolName]
		if !exists {
			t.Fatalf("Outil %s absent du manifeste", toolName)
		}

		arcBytes, err := os.ReadFile(arcPath)
		if err != nil {
			t.Logf("Archive locale absente pour %s (%s): %v", toolName, arcPath, err)
			continue
		}

		// 1. Vérifier le hash de l'archive
		actualArcHash := sha256Hex(arcBytes)
		if !strings.EqualFold(actualArcHash, tool.ArchiveSHA256) {
			t.Errorf("Archive SHA-256 mismatch pour %s: attendu %s, obtenu %s", toolName, tool.ArchiveSHA256, actualArcHash)
		}

		// 2. Extraire et vérifier le hash du binaire extrait
		binBytes, err := extractBinary(arcBytes, tool.BinaryInArchive, tool.ArchiveURL)
		if err != nil {
			t.Errorf("Échec d'extraction du binaire pour %s (%s): %v", toolName, tool.BinaryInArchive, err)
			continue
		}

		actualBinHash := sha256Hex(binBytes)
		if !strings.EqualFold(actualBinHash, tool.BinarySHA256) {
			t.Errorf("Binary SHA-256 mismatch pour %s extrait de l'archive: attendu %s, obtenu %s", toolName, tool.BinarySHA256, actualBinHash)
		} else {
			t.Logf("SUCCESS: Binaire extrait pour %s (%d octets) vérifié avec succès: %s", toolName, len(binBytes), actualBinHash)
			verifiedCount++
		}
	}

	if verifiedCount == 0 {
		t.Skip("Toutes les archives sont absentes du cache local (.tools/cache): test sauté pour éviter un faux succès en CI minimale")
	}
}



