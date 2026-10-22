package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenTofuStageRenamesAndRestoresPaths(t *testing.T) {
	root := t.TempDir()
	for name, body := range map[string]string{
		"main.tofu":          "resource \"a\" \"b\" {}\n",
		"main.tf":            "# shadowed by main.tofu\n",
		"outputs.tf":         "output \"x\" { value = 1 }\n",
		"modules/db/db.tofu": "resource \"c\" \"d\" {}\n",
		".terraform/skip.tf": "ignored cache\n",
		"README.md":          "not HCL\n",
	} {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	stage, err := stageOpenTofu(root)
	if err != nil || stage == nil {
		t.Fatalf("stage = %v %v", stage, err)
	}
	defer stage.cleanup()
	main, err := os.ReadFile(filepath.Join(stage.Dir, "main.tf"))
	if err != nil || !strings.Contains(string(main), "resource") {
		t.Fatalf("main.tofu must win over main.tf: %q %v", main, err)
	}
	for _, name := range []string{"outputs.tf", "modules/db/db.tf"} {
		if _, err := os.Stat(filepath.Join(stage.Dir, filepath.FromSlash(name))); err != nil {
			t.Fatalf("%s missing from the stage", name)
		}
	}
	for _, name := range []string{".terraform/skip.tf", "README.md", "main.tofu"} {
		if _, err := os.Stat(filepath.Join(stage.Dir, filepath.FromSlash(name))); err == nil {
			t.Fatalf("%s must not be staged", name)
		}
	}
	escaped := strings.ReplaceAll(stage.Dir, `\`, `\`)
	output := `{"file_abs_path": "` + escaped + `\modules\db\db.tf", "file_path": "/main.tf", "other": "/outputs.tf", "range": {"filename": "modules/db/db.tf"}}`
	restored := stage.restore(output)
	if strings.Contains(restored, stage.Dir) || strings.Contains(restored, escaped) {
		t.Fatalf("staged directory still named: %s", restored)
	}
	for _, want := range []string{`"/main.tofu"`, `"/outputs.tf"`, `"modules/db/db.tofu"`, `db\db.tofu"`} {
		if !strings.Contains(restored, want) {
			t.Fatalf("%s absent from %s", want, restored)
		}
	}
	if none, err := stageOpenTofu(filepath.Join(root, "modules", "missing")); none != nil || err != nil {
		t.Fatalf("a root without .tofu must not be staged: %v %v", none, err)
	}
}

func TestCheckovAnalysedNothing(t *testing.T) {
	if !checkovAnalysedNothing("{\n    \"passed\": 0,\n    \"resource_count\": 0,\n    \"checkov_version\": \"3.3.23\"\n}") {
		t.Fatal("empty summary not recognised")
	}
	if checkovAnalysedNothing(`{"check_type": "terraform", "results": {"failed_checks": []}, "summary": {"resource_count": 0}}`) {
		t.Fatal("a real result was taken for an empty analysis")
	}
}
