package distribution

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
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


