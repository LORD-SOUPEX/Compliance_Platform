package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestControlLogKeepsEveryExecutedControl(t *testing.T) {
	if name := ControlLogName("javascript/linting/eslint/."); name == ".log" || !strings.HasSuffix(name, ".log") || strings.Contains(name, "/") {
		t.Fatalf("name = %q", name)
	}
	dir := t.TempDir()
	eslint, err := WriteControlLog(dir, "javascript/linting/eslint/.", "", "")
	if err != nil {
		t.Fatal(err)
	}
	gitleaks, err := WriteControlLog(dir, "javascript/security/gitleaks/.", "leaks found: 0", "")
	if err != nil {
		t.Fatal(err)
	}
	if eslint == gitleaks {
		t.Fatal("two controls wrote the same log")
	}
	info, err := os.Stat(eslint)
	if err != nil || info.Size() != 0 {
		t.Fatalf("empty stdout was not persisted: %v size=%v", err, info)
	}
	body, err := os.ReadFile(gitleaks)
	if err != nil || string(body) != "leaks found: 0" {
		t.Fatalf("gitleaks log = %q err=%v", body, err)
	}
	if filepath.Base(eslint) == ".log" {
		t.Fatal("log collapsed to .log")
	}
}

func TestHistoricalReportKeepsDurationAndLogs(t *testing.T) {
	dir := t.TempDir()
	ids := []string{"javascript/linting/eslint/.", "javascript/security/gitleaks/."}
	for _, id := range ids {
		if _, err := WriteControlLog(dir, id, "", ""); err != nil {
			t.Fatal(err)
		}
	}
	body := map[string]interface{}{
		"metrics": map[string]interface{}{"total_duration_ms": 4321},
		"execution_results": []interface{}{
			map[string]interface{}{"control_id": ids[0], "status": "success", "duration_ms": 12},
			map[string]interface{}{"control_id": ids[1], "status": "success", "duration_ms": 4},
		},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "compliance-report.json")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	reloaded, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var report map[string]interface{}
	if err := json.Unmarshal(reloaded, &report); err != nil {
		t.Fatal(err)
	}
	if ReportDurationMs(report) != 4321 {
		t.Fatalf("duration = %d", ReportDurationMs(report))
	}
	metrics := report["metrics"].(map[string]interface{})
	delete(metrics, "total_duration_ms")
	if ReportDurationMs(report) != 16 {
		t.Fatalf("sum = %d", ReportDurationMs(report))
	}
	entries, err := os.ReadDir(filepath.Join(dir, "logs"))
	if err != nil || len(entries) != 2 {
		t.Fatalf("logs = %v err=%v", entries, err)
	}
	for _, entry := range entries {
		if entry.Name() == ".log" || !strings.HasSuffix(entry.Name(), ".log") {
			t.Fatalf("log name = %s", entry.Name())
		}
	}
}
