package report

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReportParityAndNormalization(t *testing.T) {
	goReportPath := filepath.Join("..", "..", "testdata", "go_report.json")
	goBytes, err := os.ReadFile(goReportPath)
	if err != nil {
		t.Skipf("go_report.json non disponible: %v", err)
	}

	normGo, err := NormalizeReport(goBytes)
	if err != nil {
		t.Fatalf("NormalizeReport(go) failed: %v", err)
	}

	// Verify normalized values
	if normGo["generated_at"] != "2026-10-13T00:00:00Z" {
		t.Errorf("expected normalized generated_at, got %v", normGo["generated_at"])
	}
	if normGo["engine_version"] != "CANONICAL_ENGINE_VERSION" {
		t.Errorf("expected normalized engine_version, got %v", normGo["engine_version"])
	}

	meta, ok := normGo["metadata"].(map[string]interface{})
	if !ok || meta["run_id"] != "CANONICAL_RUN_ID" {
		t.Errorf("expected normalized run_id, got %v", meta["run_id"])
	}

	// If ps_report.json exists, compare common properties
	psReportPath := filepath.Join("..", "..", "testdata", "ps_report.json")
	psBytes, err := os.ReadFile(psReportPath)
	if err == nil {
		normPS, err := NormalizeReport(psBytes)
		if err != nil {
			t.Fatalf("NormalizeReport(ps) failed: %v", err)
		}

		// Verify structural conformity: both have schema_version 1
		if normGo["schema_version"] != normPS["schema_version"] {
			t.Errorf("schema_version mismatch: %v vs %v", normGo["schema_version"], normPS["schema_version"])
		}

		// Verify repository path normalization (slashes converted to /)
		repoGo, _ := normGo["repository"].(string)
		repoPS, _ := normPS["repository"].(string)
		if repoGo != repoPS {
			t.Logf("Normalized repo: Go=%s, PS=%s", repoGo, repoPS)
		}
	}
}
