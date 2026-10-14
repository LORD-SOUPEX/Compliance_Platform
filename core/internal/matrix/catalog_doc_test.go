package matrix

import (
	"os"
	"strings"
	"testing"
)

func TestDocumentationListsCatalogControls(t *testing.T) {
	catalog, err := LoadCatalog("../../../.config/control-catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"../../../README.md", "../../../docs/extension.md"} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(body)
		start := strings.Index(text, "<!-- catalog-controls:start -->")
		end := strings.Index(text, "<!-- catalog-controls:end -->")
		if start < 0 || end < start {
			t.Fatalf("%s n'a pas de tableau catalog-controls", path)
		}
		section := text[start:end]
		if strings.Contains(section, "pre-commit") {
			t.Fatalf("%s mentionne encore pre-commit dans le tableau", path)
		}
		seen := map[string]bool{}
		for _, line := range strings.Split(section, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "|") || strings.Contains(line, "Identifiant") || strings.Contains(line, "---") {
				continue
			}
			cells := strings.Split(line, "|")
			if len(cells) < 4 {
				continue
			}
			id := strings.TrimSpace(cells[1])
			tool := strings.TrimSpace(cells[3])
			seen[id] = true
			control := findControl(catalog, id)
			if control == nil {
				t.Errorf("%s : identifiant inconnu %s", path, id)
				continue
			}
			want := "aucun"
			if control.Tool != nil && control.Tool.Command != "" {
				want = control.Tool.Command
			}
			if tool != want {
				t.Errorf("%s : %s outil %s, catalogue %s", path, id, tool, want)
			}
		}
		if len(seen) != len(catalog.Controls) {
			t.Errorf("%s : %d lignes, catalogue %d", path, len(seen), len(catalog.Controls))
		}
		for _, control := range catalog.Controls {
			if !seen[control.ID] {
				t.Errorf("%s : contrôle absent %s", path, control.ID)
			}
		}
	}
}

func findControl(catalog *ControlCatalog, id string) *CatalogControl {
	for i := range catalog.Controls {
		if catalog.Controls[i].ID == id {
			return &catalog.Controls[i]
		}
	}
	return nil
}
