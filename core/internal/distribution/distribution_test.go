package distribution

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSignatureVerification(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	manifestData := []byte(`{"schema_version": 2, "manifest_version": "test"}`)
	sigHex := SignManifest(manifestData, priv)

	// Valid signature
	if err := VerifyManifest(manifestData, sigHex, pub); err != nil {
		t.Errorf("Valid signature failed verification: %v", err)
	}

	// Tampered manifest
	tamperedData := []byte(`{"schema_version": 2, "manifest_version": "tampered"}`)
	if err := VerifyManifest(tamperedData, sigHex, pub); err == nil {
		t.Errorf("Tampered manifest was accepted!")
	} else if err != ErrInvalidSignature {
		t.Errorf("Expected ErrInvalidSignature, got %v", err)
	}

	// Tampered signature
	tamperedSig := "00" + sigHex[2:]
	if err := VerifyManifest(manifestData, tamperedSig, pub); err == nil {
		t.Errorf("Tampered signature was accepted!")
	}
}

func TestSyncWithHashVerification(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "compliance-dist-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	// Create a dummy binary and zip archive
	fakeBinContent := []byte("FAKE_BINARY_EXECUTABLE_CONTENT")
	fakeBinHash := sha256Hex(fakeBinContent)

	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	f, _ := zw.Create("mytool.exe")
	f.Write(fakeBinContent)
	zw.Close()

	archiveBytes := zipBuf.Bytes()
	archiveHash := sha256Hex(archiveBytes)

	archivePath := filepath.Join(tempDir, "mytool.zip")
	os.WriteFile(archivePath, archiveBytes, 0644)

	platform := "test-os-x64"
	manifest := RuntimeManifest{
		SchemaVersion:   2,
		ManifestVersion: "1.0",
		Platforms: map[string]PlatformManifest{
			platform: {
				Status: "qualified",
				Tools: map[string]ToolEntry{
					"mytool": {
						Name:            "mytool",
						Version:         "1.0.0",
						ArchiveURL:      archivePath,
						ArchiveSHA256:   archiveHash,
						BinaryInArchive: "mytool.exe",
						BinarySHA256:    fakeBinHash,
					},
				},
			},
		},
	}

	manifestBytes, _ := json.Marshal(manifest)
	manifestPath := filepath.Join(tempDir, "manifest.json")
	os.WriteFile(manifestPath, manifestBytes, 0644)

	sigHex := SignManifest(manifestBytes, priv)
	sigPath := filepath.Join(tempDir, "manifest.sig")
	os.WriteFile(sigPath, []byte(sigHex), 0644)

	cacheDir := filepath.Join(tempDir, "cache")

	// 1. Success case
	res, err := SyncRuntime(SyncOptions{
		ManifestPath: manifestPath,
		SigPath:      sigPath,
		CacheDir:     cacheDir,
		Platform:     platform,
		PublicKey:    pub,
	})
	if err != nil {
		t.Fatalf("SyncRuntime failed unexpectedly: %v", err)
	}
	if _, ok := res.SyncedTools["mytool"]; !ok {
		t.Fatalf("mytool not present in SyncedTools")
	}

	// 2. Archive Hash Mismatch rejection (Criterion 3)
	badArchiveManifest := manifest
	badArchiveManifest.Platforms[platform].Tools["mytool"] = ToolEntry{
		Name:            "mytool",
		Version:         "1.0.0",
		ArchiveURL:      archivePath,
		ArchiveSHA256:   strings.Repeat("0", 64), // BAD HASH
		BinaryInArchive: "mytool.exe",
		BinarySHA256:    fakeBinHash,
	}
	badBytes, _ := json.Marshal(badArchiveManifest)
	badSig := SignManifest(badBytes, priv)
	badManifestPath := filepath.Join(tempDir, "bad_archive_manifest.json")
	badSigPath := filepath.Join(tempDir, "bad_archive_manifest.sig")
	os.WriteFile(badManifestPath, badBytes, 0644)
	os.WriteFile(badSigPath, []byte(badSig), 0644)

	_, err = SyncRuntime(SyncOptions{
		ManifestPath: badManifestPath,
		SigPath:      badSigPath,
		CacheDir:     cacheDir,
		Platform:     platform,
		PublicKey:    pub,
	})
	if err == nil {
		t.Errorf("Expected failure on archive hash mismatch, but succeeded!")
	} else if !strings.Contains(err.Error(), "somme SHA-256 de l'archive") {
		t.Errorf("Unexpected error message: %v", err)
	} else {
		t.Logf("SUCCESS: Archive hash mismatch rejected with: %v", err)
	}

	// 3. Binary Hash Mismatch rejection (Criterion 3)
	badBinManifest := manifest
	badBinManifest.Platforms[platform].Tools["mytool"] = ToolEntry{
		Name:            "mytool",
		Version:         "1.0.0",
		ArchiveURL:      archivePath,
		ArchiveSHA256:   archiveHash,
		BinaryInArchive: "mytool.exe",
		BinarySHA256:    strings.Repeat("f", 64), // BAD BINARY HASH
	}
	badBinBytes, _ := json.Marshal(badBinManifest)
	badBinSig := SignManifest(badBinBytes, priv)
	badBinManifestPath := filepath.Join(tempDir, "bad_bin_manifest.json")
	badBinSigPath := filepath.Join(tempDir, "bad_bin_manifest.sig")
	os.WriteFile(badBinManifestPath, badBinBytes, 0644)
	os.WriteFile(badBinSigPath, []byte(badBinSig), 0644)

	_, err = SyncRuntime(SyncOptions{
		ManifestPath: badBinManifestPath,
		SigPath:      badBinSigPath,
		CacheDir:     cacheDir,
		Platform:     platform,
		PublicKey:    pub,
	})
	if err == nil {
		t.Errorf("Expected failure on binary hash mismatch, but succeeded!")
	} else if !strings.Contains(err.Error(), "somme SHA-256 du binaire") {
		t.Errorf("Unexpected error message: %v", err)
	} else {
		t.Logf("SUCCESS: Binary hash mismatch rejected with: %v", err)
	}
}

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

func TestToolResolverLocalBin(t *testing.T) {
	manifestPath := filepath.Join("..", "..", "..", ".config", "runtime-manifest.json")
	sigPath := filepath.Join("..", "..", "..", ".config", "runtime-manifest.json.sig")
	localBinDir := filepath.Join("..", "..", "..", ".tools", "bin")

	targetExe := filepath.Join(localBinDir, "gitleaks.exe")
	if _, err := os.Stat(targetExe); err != nil {
		t.Skip("Binaire gitleaks.exe absent dans .tools/bin: test local bin sauté en environnement minimal")
	}

	resolver, err := NewResolver(ResolverOptions{
		ManifestPath: manifestPath,
		SigPath:      sigPath,
		CacheDir:     t.TempDir(),
		LocalBinDir:  localBinDir,
		Platform:     "windows-x64",
	})
	if err != nil {
		t.Fatalf("NewResolver failed: %v", err)
	}

	ctx := context.Background()

	res, err := resolver.ResolveTool(ctx, "gitleaks")
	if err != nil {
		t.Fatalf("ResolveTool('gitleaks') failed: %v", err)
	}

	if res.Name != "gitleaks" {
		t.Errorf("Expected name 'gitleaks', got %s", res.Name)
	}
	if res.Version != "8.30.1" {
		t.Errorf("Expected version '8.30.1', got %s", res.Version)
	}
	if res.Source != "local_bin" {
		t.Errorf("Expected source 'local_bin', got %s", res.Source)
	}

	if runtime.GOOS == "windows" {
		cmd := exec.Command(res.ExecutablePath, "version")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Execution of resolved gitleaks failed: %v", err)
		}
		if !strings.Contains(string(out), "8.30.1") {
			t.Errorf("Unexpected output: %s", string(out))
		}
		t.Logf("SUCCESS: gitleaks resolved and verified: %s", strings.TrimSpace(string(out)))
	}
}

func TestToolResolverOnDemandExtraction(t *testing.T) {
	manifestPath := filepath.Join("..", "..", "..", ".config", "runtime-manifest.json")
	sigPath := filepath.Join("..", "..", "..", ".config", "runtime-manifest.json.sig")
	archiveCacheDir := filepath.Join("..", "..", "..", ".tools", "cache")

	tflintArc := filepath.Join(archiveCacheDir, "tflint_windows_amd64.zip")
	if _, err := os.Stat(tflintArc); err != nil {
		t.Skip("Archive tflint absente dans .tools/cache: test extraction sauté en environnement minimal")
	}

	tempCache := t.TempDir()

	resolver, err := NewResolver(ResolverOptions{
		ManifestPath:    manifestPath,
		SigPath:         sigPath,
		CacheDir:        tempCache,
		ArchiveCacheDir: archiveCacheDir,
		Platform:        "windows-x64",
	})
	if err != nil {
		t.Fatalf("NewResolver failed: %v", err)
	}

	ctx := context.Background()

	res, err := resolver.ResolveTool(ctx, "tflint")
	if err != nil {
		t.Fatalf("ResolveTool('tflint') on-demand failed: %v", err)
	}

	if res.Source != "synced" {
		t.Errorf("Expected source 'synced', got %s", res.Source)
	}

	if runtime.GOOS == "windows" {
		cmd := exec.Command(res.ExecutablePath, "--version")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Execution of extracted tflint failed: %v", err)
		}
		if !strings.Contains(string(out), "0.64.0") {
			t.Errorf("Unexpected output from tflint: %s", string(out))
		}
		t.Logf("SUCCESS: tflint extracted on demand and executed: %s", strings.TrimSpace(string(out)))
	}

	// Second resolution should be instant from "cache"
	res2, err := resolver.ResolveTool(ctx, "tflint")
	if err != nil {
		t.Fatalf("Second ResolveTool('tflint') failed: %v", err)
	}
	if res2.Source != "cache" {
		t.Errorf("Expected second resolution to be 'cache', got %s", res2.Source)
	}
}

func TestToolResolverTamperedBinaryRejection(t *testing.T) {
	manifestPath := filepath.Join("..", "..", "..", ".config", "runtime-manifest.json")
	sigPath := filepath.Join("..", "..", "..", ".config", "runtime-manifest.json.sig")
	archiveCacheDir := filepath.Join("..", "..", "..", ".tools", "cache")

	gitleaksArc := filepath.Join(archiveCacheDir, "gitleaks_8.30.1_windows_x64.zip")
	if _, err := os.Stat(gitleaksArc); err != nil {
		t.Skip("Archive gitleaks absente dans .tools/cache: test falsification sauté en environnement minimal")
	}

	fakeBinDir := t.TempDir()
	corruptExe := filepath.Join(fakeBinDir, "gitleaks.exe")
	os.WriteFile(corruptExe, []byte("NOT A VALID GITLEAKS BINARY"), 0755)

	tempCache := t.TempDir()

	resolver, err := NewResolver(ResolverOptions{
		ManifestPath:    manifestPath,
		SigPath:         sigPath,
		CacheDir:        tempCache,
		LocalBinDir:     fakeBinDir,
		ArchiveCacheDir: archiveCacheDir,
		Platform:        "windows-x64",
	})
	if err != nil {
		t.Fatalf("NewResolver failed: %v", err)
	}

	ctx := context.Background()

	res, err := resolver.ResolveTool(ctx, "gitleaks")
	if err != nil {
		t.Fatalf("ResolveTool failed: %v", err)
	}

	if res.Source == "local_bin" {
		t.Errorf("Tampered binary should NOT have been accepted as local_bin!")
	}
	if res.Source != "synced" {
		t.Errorf("Expected fallback recovery to 'synced', got %s", res.Source)
	}
	t.Logf("SUCCESS: Corrupted local binary rejected and recovered via authentic extraction")
}

func TestToolResolverUnknownTool(t *testing.T) {
	manifestPath := filepath.Join("..", "..", "..", ".config", "runtime-manifest.json")
	sigPath := filepath.Join("..", "..", "..", ".config", "runtime-manifest.json.sig")

	resolver, err := NewResolver(ResolverOptions{
		ManifestPath: manifestPath,
		SigPath:      sigPath,
		CacheDir:     t.TempDir(),
		Platform:     "windows-x64",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = resolver.ResolveTool(context.Background(), "non_existent_tool")
	if err == nil {
		t.Errorf("Expected error for non_existent_tool")
	}
}

func TestToolResolverAutonomousMock(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Create a mock executable in a zip archive
	mockBinContent := []byte("#!/bin/sh\necho mock 1.0\n")
	mockBinHash := sha256Hex(mockBinContent)

	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	f, err := zw.Create("mytool")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(mockBinContent); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	zipBytes := zipBuf.Bytes()
	zipHash := sha256Hex(zipBytes)

	// 2. Start mock HTTP server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		w.Write(zipBytes)
	}))
	defer ts.Close()

	// 3. Ephemeral keypair
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	plat := DetectPlatform()
	manifest := RuntimeManifest{
		SchemaVersion:   2,
		ManifestVersion: "2.0.0",
		Platforms: map[string]PlatformManifest{
			plat: {
				Status: "qualified",
				Tools: map[string]ToolEntry{
					"mytool": {
						Name:            "mytool",
						Version:         "1.0.0",
						ArchiveURL:      ts.URL + "/mytool.zip",
						ArchiveSHA256:   zipHash,
						BinaryInArchive: "mytool",
						BinarySHA256:    mockBinHash,
						VersionArgs:     []string{"version"},
					},
				},
			},
		},
	}

	manifestBytes, _ := json.MarshalIndent(manifest, "", "  ")
	sigHex := SignManifest(manifestBytes, privKey)

	manifestPath := filepath.Join(tempDir, "manifest.json")
	sigPath := filepath.Join(tempDir, "manifest.sig")
	cacheDir := filepath.Join(tempDir, "cache")

	os.WriteFile(manifestPath, manifestBytes, 0644)
	os.WriteFile(sigPath, []byte(sigHex), 0644)

	// 4. Test on-demand resolution via mock server
	resolver, err := NewResolver(ResolverOptions{
		ManifestPath: manifestPath,
		SigPath:      sigPath,
		CacheDir:     cacheDir,
		Platform:     plat,
		PublicKey:    pubKey,
	})
	if err != nil {
		t.Fatalf("NewResolver autonomous failed: %v", err)
	}

	res, err := resolver.ResolveTool(context.Background(), "mytool")
	if err != nil {
		t.Fatalf("ResolveTool autonomous failed: %v", err)
	}

	if res.Name != "mytool" || res.Version != "1.0.0" {
		t.Errorf("Unexpected resolved tool: %+v", res)
	}
	if res.Source != "synced" {
		t.Errorf("Expected source 'synced', got %s", res.Source)
	}

	t.Logf("SUCCESS: Tool Resolver autonomous test passed in %s with source %s", plat, res.Source)
}
