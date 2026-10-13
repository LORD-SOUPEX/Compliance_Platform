package selftest

import (
	"path/filepath"
	"testing"
)

func TestSelftestEndToEnd(t *testing.T) {
	platformRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("Calcul platformRoot échoué: %v", err)
	}

	passed, steps := Run(platformRoot)
	if !passed {
		for i, s := range steps {
			if !s.Passed {
				t.Errorf("Étape %d (%s) échouée: %s", i+1, s.Name, s.Error)
			}
		}
		t.Fatalf("Selftest global a échoué")
	}

	if len(steps) != 20 {
		t.Errorf("Attendu 20 étapes, obtenu %d", len(steps))
	}
}
