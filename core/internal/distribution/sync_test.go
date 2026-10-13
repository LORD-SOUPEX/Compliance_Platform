package distribution

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRealRuntimeSyncEndToEnd(t *testing.T) {
	// 1. Lire la vraie archive wheel de ruff présente dans .tools/cache/wheels
	wheelPath := filepath.Join("..", "..", "..", ".tools", "cache", "wheels", "ruff-0.16.10-py3-none-win_amd64.whl")
	wheelBytes, err := os.ReadFile(wheelPath)
	if err != nil {
		t.Skipf("Archive ruff introuvable dans le cache local: %v", err)
	}

	actualArchiveHash := sha256Hex(wheelBytes)
	actualBinaryHash := "7663ebf1a11dfdad737f95a0952d9e893eb88bf0ab6a24e3c4e48d4c8b8156eb"

	// 2. Démarrer un serveur HTTP statique local
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(wheelBytes)
	}))
	defer ts.Close()

	// 3. Générer une paire de clés Ed25519 cryptographiquement sécurisée pour le test
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Génération de clé éphémère échouée: %v", err)
	}

	// 4. Construire un manifeste pointant sur notre serveur HTTP local
	manifest := RuntimeManifest{
		SchemaVersion:   2,
		ManifestVersion: "2.0.0",
		Platforms: map[string]PlatformManifest{
			"windows-x64": {
				Status: "qualified",
				Tools: map[string]ToolEntry{
					"ruff": {
						Name:            "ruff",
						Version:         "0.16.10",
						ArchiveURL:      ts.URL + "/ruff.whl",
						ArchiveSHA256:   actualArchiveHash,
						BinaryInArchive: "ruff.exe",
						BinarySHA256:    actualBinaryHash,
						VersionArgs:     []string{"--version"},
					},
				},
			},
		},
	}

	manifestBytes, _ := json.MarshalIndent(manifest, "", "  ")
	sigHex := SignManifest(manifestBytes, privKey)

	tempDir, err := os.MkdirTemp("", "compliance-sync-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	manifestFile := filepath.Join(tempDir, "manifest.json")
	sigFile := filepath.Join(tempDir, "manifest.sig")
	cacheDir := filepath.Join(tempDir, "cache")

	os.WriteFile(manifestFile, manifestBytes, 0644)
	os.WriteFile(sigFile, []byte(sigHex), 0644)

	// 5. Exécuter SyncRuntime réel
	res, err := SyncRuntime(SyncOptions{
		ManifestPath: manifestFile,
		SigPath:      sigFile,
		CacheDir:     cacheDir,
		Platform:     "windows-x64",
		PublicKey:    pubKey,
	})
	if err != nil {
		t.Fatalf("SyncRuntime a échoué: %v", err)
	}

	ruffPath, ok := res.SyncedTools["ruff"]
	if !ok {
		t.Fatalf("Outil ruff absent des outils synchronisés")
	}

	if _, err := os.Stat(ruffPath); err != nil {
		t.Fatalf("Binaire extrait introuvable sur le disque: %v", err)
	}

	// 6. Tester que le binaire extrait s'exécute réellement !
	cmd := exec.Command(ruffPath, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Échec d'exécution du binaire extrait %s: %v", ruffPath, err)
	}

	t.Logf("SUCCESS: Binaire synchronisé et exécuté avec succès : %s", string(out))
}

func TestSyncRepoManifestWithEmbeddedKey(t *testing.T) {
	manifestPath := filepath.Join("..", "..", "..", ".config", "runtime-manifest.json")
	sigPath := filepath.Join("..", "..", "..", ".config", "runtime-manifest.json.sig")
	cacheArchiveDir := filepath.Join("..", "..", "..", ".tools", "cache")

	if _, err := os.Stat(filepath.Join(cacheArchiveDir, "gitleaks_8.30.1_windows_x64.zip")); err != nil {
		t.Skip("Archives locales absentes dans .tools/cache: skip du test complet repo sync")
	}

	tempDir := t.TempDir()

	res, err := SyncRuntime(SyncOptions{
		ManifestPath:    manifestPath,
		SigPath:         sigPath,
		CacheDir:        tempDir,
		ArchiveCacheDir: cacheArchiveDir,
		Platform:        "windows-x64",
		// PublicKey omitted to test the embedded DefaultPhase0PublicKeyHex!
	})
	if err != nil {
		t.Fatalf("SyncRuntime sur le manifeste officiel du dépôt a échoué: %v", err)
	}

	for _, toolName := range []string{"ruff", "gitleaks", "tflint", "trivy"} {
		binPath, ok := res.SyncedTools[toolName]
		if !ok {
			t.Errorf("Outil %s manquant dans le résultat de synchronisation", toolName)
			continue
		}
		if _, err := os.Stat(binPath); err != nil {
			t.Errorf("Binaire extrait pour %s introuvable: %v", toolName, err)
		}
	}

	// Tester l'exécution réelle d'un binaire extrait du manifeste officiel
	gitleaksBin := res.SyncedTools["gitleaks"]
	cmd := exec.Command(gitleaksBin, "version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Échec exécution gitleaks extrait (%s): %v", gitleaksBin, err)
	}
	t.Logf("SUCCESS: Repo manifest synchronisé avec clé embarquée et exécuté avec succès (gitleaks version: %s)", strings.TrimSpace(string(out)))
}

