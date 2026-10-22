package engine

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"compliance/internal/embedded"
	"compliance/internal/matrix"
)

// Every tool of the catalog must have an adapter: a control whose output is not
// read reports a failure with no file, which hides the findings.
func TestEveryCatalogToolHasAnAdapter(t *testing.T) {
	path, err := embedded.ResolveAsset("control-catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := matrix.LoadCatalog(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, control := range catalog.Controls {
		if _, ok := adapterFor(control.Tool.Command); !ok {
			t.Errorf("%s: no adapter for %s", control.ID, control.Tool.Command)
		}
	}
}

func TestSARIFFromBiomeOsvAndGolangci(t *testing.T) {
	repo := t.TempDir()
	style := filepath.ToSlash(filepath.Join(repo, "web", "style.css"))
	app := filepath.ToSlash(filepath.Join(repo, "web", "app.js"))
	biome := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Biome"}},"results":[` +
		`{"ruleId":"lint/suspicious/noEmptyBlock","level":"warning","message":{"text":"An empty block isn't allowed."},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"` + style + `"},"region":{"startLine":4,"startColumn":3}}}]},` +
		`{"ruleId":"format","level":"error","message":{"text":"Formatter would have printed the following content:"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"` + app + `"}}}]}]}]}`
	leaks := parseSARIF(biome, repo)
	if len(leaks) != 2 || leaks[0].File != "web/style.css" || leaks[0].Line != 4 || leaks[0].Severity != "medium" || leaks[1].File != "web/app.js" || leaks[1].Line != 1 || leaks[1].Severity != "high" {
		t.Fatalf("biome = %+v", leaks)
	}

	uri := "file:///" + strings.TrimPrefix(filepath.ToSlash(filepath.Join(repo, "deps", "requirements.txt")), "/")
	osv := `{"runs":[{"results":[{"ruleId":"CVE-2025-66471","level":"warning","message":{"text":"Package 'urllib3@1.23.0' is vulnerable"},"locations":[{"physicalLocation":{"artifactLocation":{"index":-1,"uri":"` + uri + `"}}}]}]}]}`
	osvLeaks := parseSARIF(osv, repo)
	if len(osvLeaks) != 1 || osvLeaks[0].File != "deps/requirements.txt" || osvLeaks[0].RuleID != "CVE-2025-66471" {
		t.Fatalf("osv-scanner = %+v (uri %s)", osvLeaks, uri)
	}

	golangci := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"golangci-lint"}},"results":[{"ruleId":"errcheck","level":"error","message":{"text":"Error return value of os.Remove is not checked"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"main.go","index":0},"region":{"startLine":9,"startColumn":11}}}]}]}]}` +
		"\n1 issues:\n* errcheck: 1\n" +
		`level=error msg="[linters_context] typechecking error: : # example.com/demo\n.\\main.go:11:6: unused declared and not used"`
	goLeaks := parseGolangci(golangci, repo)
	if len(goLeaks) != 2 || goLeaks[0].RuleID != "errcheck" || goLeaks[0].Line != 9 || goLeaks[1].RuleID != "typecheck" || goLeaks[1].Line != 11 || !strings.Contains(goLeaks[1].Description, "declared and not used") {
		t.Fatalf("golangci = %+v", goLeaks)
	}
	if toolCrashed("golangci-lint", `level=error msg="typechecking error: x"`, 0) || !toolCrashed("golangci-lint", `level=error msg="can't load config"`, 0) {
		t.Fatal("golangci crash detection")
	}
}

func TestSARIFPathForms(t *testing.T) {
	cases := map[string]string{
		"file:///C:/Users/a%20b/x.txt": "C:/Users/a b/x.txt",
		"file:///home/me/x.txt":        "/home/me/x.txt",
		"src/main.go":                  "src/main.go",
		"src/a%20b.go":                 "src/a b.go",
	}
	for uri, want := range cases {
		if got := sarifPath(uri); got != want {
			t.Fatalf("sarifPath(%q) = %q, want %q", uri, got, want)
		}
	}
	if runtime.GOOS == "windows" && sarifPath("file:///C:/x") != "C:/x" {
		t.Fatal("drive letter")
	}
}

func TestStylelintAndHTMLHintParsers(t *testing.T) {
	repo := t.TempDir()
	css := strings.ReplaceAll(filepath.Join(repo, "web", "style.css"), `\`, `\\`)
	stylelint := `[{"source":"` + css + `","warnings":[{"line":4,"column":3,"rule":"block-no-empty","severity":"error","text":"Empty block (block-no-empty)"},{"line":1,"column":18,"rule":"property-no-unknown","severity":"warning","text":"Unexpected unknown property"}]}]`
	leaks := parseStylelint("\n"+stylelint, repo)
	if len(leaks) != 2 || leaks[0].File != "web/style.css" || leaks[0].RuleID != "block-no-empty" || leaks[0].Severity != "medium" || leaks[1].Severity != "low" {
		t.Fatalf("stylelint = %+v", leaks)
	}
	html := strings.ReplaceAll(filepath.Join(repo, "web", "index.html"), `\`, `\\`)
	htmlhint := `[{"file":"` + html + `","messages":[{"type":"error","message":"The id value [ x ] must be unique.","line":1,"col":29,"rule":{"id":"id-unique"}}],"time":3}]`
	hint := parseHTMLHint(htmlhint, repo)
	if len(hint) != 1 || hint[0].File != "web/index.html" || hint[0].Column != 29 || hint[0].RuleID != "id-unique" {
		t.Fatalf("htmlhint = %+v", hint)
	}
}

func TestBiomeFilesPerTechnology(t *testing.T) {
	cases := []struct {
		technology, file string
		want             bool
	}{
		{"javascript", "a/app.js", true}, {"javascript", "a/data.json", true}, {"javascript", "a/package-lock.json", false},
		{"javascript", "a/client.ts", false}, {"typescript", "a/client.ts", true}, {"typescript", "a/app.js", false},
		{"css", "a/style.css", true}, {"css", "a/style.scss", false},
	}
	for _, c := range cases {
		if got := biomeFile(c.technology, c.file); got != c.want {
			t.Fatalf("biomeFile(%s, %s) = %v", c.technology, c.file, got)
		}
	}
}
