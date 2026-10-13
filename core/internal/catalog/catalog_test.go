package catalog

import (
	"path/filepath"
	"testing"
)

func TestLoadCatalogOfficial(t *testing.T) {
	catPath := filepath.Join("..", "..", "..", ".config", "control-catalog.json")
	cat, err := LoadCatalog(catPath)
	if err != nil {
		t.Fatalf("LoadCatalog failed: %v", err)
	}

	if cat.SchemaVersion != 1 {
		t.Errorf("expected SchemaVersion 1, got %d", cat.SchemaVersion)
	}

	if len(cat.Controls) != 28 {
		t.Errorf("expected exactly 28 controls in official catalog, got %d", len(cat.Controls))
	}

	if len(cat.ContentSHA256) != 64 {
		t.Errorf("expected 64-char SHA256, got %s", cat.ContentSHA256)
	}

	// Verify Python profile
	pyProfiles := cat.GetCapabilityProfile("python")
	if len(pyProfiles) == 0 {
		t.Fatalf("expected Python capability profiles, got 0")
	}

	foundFormatting := false
	for _, p := range pyProfiles {
		if p.Name == "formatting" {
			foundFormatting = true
			if len(p.Controls) != 1 || p.Controls[0].ID != "python.format.ruff" {
				t.Errorf("unexpected formatting control: %+v", p.Controls)
			}
		}
	}
	if !foundFormatting {
		t.Errorf("expected python formatting capability profile")
	}

	// Verify total count across all technologies
	techs := make(map[string]bool)
	for _, c := range cat.Controls {
		techs[c.Technology] = true
	}
	if len(techs) != 13 {
		t.Errorf("expected 13 distinct technologies in catalog, got %d", len(techs))
	}
}
