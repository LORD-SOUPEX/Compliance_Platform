package engine

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"compliance/internal/embedded"
	"compliance/internal/report"
)

func TestHeterogeneousRepositoryRunsPastPlan(t *testing.T) {
	repo := t.TempDir()
	for i := 0; i < 12; i++ {
		writeFixture(t, filepath.Join(repo, "mod"+strconv.Itoa(i), "main.tf"), "resource \"a\" \"b\" {}\n")
	}
	writeFixture(t, filepath.Join(repo, "scripts", "bad.sh"), "#!/bin/sh\necho $UNQUOTED\n")
	writeFixture(t, filepath.Join(repo, "app.py"), "import os\n")
	writeFixture(t, filepath.Join(repo, "requirements.txt"), "requests==2.32.3\n")
	writeFixture(t, filepath.Join(repo, "ansible.cfg"), "[defaults]\n")
	writeFixture(t, filepath.Join(repo, "playbooks", "site.yml"), "- hosts: all\n  tasks:\n    - debug: msg=ok\n")
	writeFixture(t, filepath.Join(repo, ".gitpod.Dockerfile"), "FROM scratch\n")
	writeFixture(t, filepath.Join(repo, "images", "app.Dockerfile"), "FROM scratch\n")
	writeFixture(t, filepath.Join(repo, "charts", "demo", "Chart.yaml"), "apiVersion: v2\nname: demo\nversion: 0.1.0\n")
	writeFixture(t, filepath.Join(repo, "deploy", "pod.yaml"), "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\nspec:\n  containers:\n    - name: web\n      image: nginx\n")
	writeFixture(t, filepath.Join(repo, "package.json"), "{\"name\":\"app\"}\n")
	writeFixture(t, filepath.Join(repo, "src", "app.js"), "console.log(1)\n")
	writeFixture(t, filepath.Join(repo, "tsconfig.json"), "{\"compilerOptions\":{\"strict\":true}}\n")
	writeFixture(t, filepath.Join(repo, "src", "app.ts"), "export const value = 1\n")
	writeFixture(t, filepath.Join(repo, "script.ps1"), "Write-Output 'ok'\n")
	writeFixture(t, filepath.Join(repo, "live", "terragrunt.hcl"), "terraform {\n  source = \".\"\n}\n")
	writeFixture(t, filepath.Join(repo, "tofu", "main.tofu"), "resource \"a\" \"b\" {}\n")

	catalog, err := embedded.ResolveAsset("control-catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	rep, err := RunCompliance(context.Background(), ComplianceOptions{
		RepoRoot:             repo,
		PlatformRoot:         t.TempDir(),
		CatalogPath:          catalog,
		TimeoutSeconds:       45,
		GlobalTimeoutSeconds: 180,
		AllowCodeExecution:   true,
		SourceAdapter:        "Go",
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.ExecutionStatus != "completed" && rep.ExecutionStatus != "blocked" {
		t.Fatalf("status %s", rep.ExecutionStatus)
	}
	executed := map[string]bool{}
	for _, result := range rep.ExecutionResults {
		if result.Status == "success" || result.Status == "fail" || result.Status == "error" {
			executed[result.Technology] = true
		}
		for _, diagnostic := range result.Diagnostics {
			if strings.Contains(diagnostic.Message, "filename or extension is too long") {
				t.Fatalf("command line overflow: %s", result.ControlId)
			}
			if result.Technology == "terraform" && strings.Contains(diagnostic.Message, "Aucune preuve du catalogue") {
				t.Fatalf("terraform root without proof: %s", result.ControlId)
			}
			if result.Technology == "docker" && strings.Contains(diagnostic.Message, "Aucune preuve du catalogue") {
				t.Fatalf("docker root without proof: %s", result.ControlId)
			}
		}
		if runtime.GOOS == "windows" && strings.Contains(result.ControlId, "/ansible-lint/") {
			message := diagnosticText(result)
			if result.Status != "skipped" || !strings.Contains(message, "Linux") {
				t.Fatalf("ansible-lint = %s %s", result.Status, message)
			}
		}
	}
	assertStructuredFinding(t, rep, executed, "python", "ruff", "app.py")
	assertStructuredFinding(t, rep, executed, "shell", "shellcheck", "bad.sh")
	if !executed["docker"] && !executed["shell"] && !executed["python"] && !executed["ansible"] {
		// Planning and the checks above still ran; execution needs at least one of
		// hadolint, shellcheck, ruff or yamllint on this machine.
		t.Skip("aucun outil shell, python, ansible ou docker installé : exécution non vérifiable ici")
	}
}

func assertStructuredFinding(t *testing.T, rep *report.Report, executed map[string]bool, technology, command, file string) {
	t.Helper()
	if !executed[technology] {
		return
	}
	ran := false
	for _, result := range rep.ExecutionResults {
		if result.Technology == technology && strings.Contains(result.ControlId, "/"+command+"/") && (result.Status == "success" || result.Status == "fail") {
			ran = true
		}
	}
	if !ran {
		return
	}
	for _, finding := range rep.Findings {
		if finding.Technology == technology && strings.Contains(finding.ControlId, "/"+command+"/") && strings.Contains(finding.File, file) && finding.Line > 0 && finding.Message != "" {
			return
		}
	}
	t.Fatalf("%s/%s produced no finding for %s", technology, command, file)
}

func diagnosticText(result report.ExecutionResult) string {
	if len(result.Diagnostics) == 0 {
		return ""
	}
	return result.Diagnostics[0].Message
}

func writeFixture(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
