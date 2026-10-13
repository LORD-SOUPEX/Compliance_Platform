package discovery

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoveryAllTechnologies(t *testing.T) {
	tempDir := t.TempDir()

	// Create a rich fixture project with multiple technologies
	files := map[string]string{
		// Python
		"services/api/pyproject.toml": "[tool.ruff]\nline-length = 88\n",
		"services/api/app/main.py":    "print('hello API')\n",
		// PowerShell
		"scripts/deploy.ps1": "Write-Output 'deploy'\n",
		"src/module.psm1":    "function Test-Me {}\n",
		// Shell
		"ci/build.sh": "#!/bin/bash\necho build\n",
		// Markdown
		"README.md": "# Docs\n",
		// JavaScript & TypeScript
		"frontend/package.json":  `{"name":"front","version":"1.0.0"}`,
		"frontend/src/index.js":  "console.log('js');",
		"backend/tsconfig.json":  `{"compilerOptions":{}}`,
		"backend/src/server.ts":  "const x: number = 42;",
		// Terragrunt
		"infra/terragrunt.hcl": "# terragrunt root\n",
		// Docker
		"Dockerfile":         "FROM alpine:3.18\n",
		"compose.yaml":       "version: '3.8'\n",
		// Helm
		"chart/Chart.yaml":   "apiVersion: v2\nname: test-chart\nversion: 0.1.0\n",
		// Excluded directories (should NOT be detected)
		".git/hooks/pre-commit.sh": "echo git hook\n",
		".venv/lib/site.py":        "# virtualenv\n",
		".tools/bin/tool.ps1":      "# ignored\n",
		"node_modules/pkg/lib.js":  "# ignored\n",
	}

	for path, content := range files {
		fullPath := filepath.Join(tempDir, path)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	res, err := DiscoverAll(tempDir)
	if err != nil {
		t.Fatalf("DiscoverAll failed: %v", err)
	}

	if !res.ScanComplete {
		t.Errorf("Expected ScanComplete = true")
	}

	statusMap := make(map[string]string)
	for _, tr := range res.Technologies {
		statusMap[tr.Technology] = tr.Status
	}

	expectedDetected := []string{
		"python", "powershell", "shell", "markdown",
		"javascript", "typescript", "terragrunt", "docker", "helm",
	}
	for _, tech := range expectedDetected {
		if statusMap[tech] != "detected" {
			t.Errorf("Expected %s to be detected, got %s", tech, statusMap[tech])
		}
	}

	expectedAbsent := []string{"ansible", "terraform", "opentofu", "kubernetes"}
	for _, tech := range expectedAbsent {
		if statusMap[tech] != "absent" {
			t.Errorf("Expected %s to be absent, got %s", tech, statusMap[tech])
		}
	}
}

func TestTerraformAndOpenTofuDetection(t *testing.T) {
	// Scenario 1: Pure Terraform with .terraform-version
	dir1 := t.TempDir()
	os.WriteFile(filepath.Join(dir1, "main.tf"), []byte(`resource "null_resource" "x" {}`), 0644)
	os.WriteFile(filepath.Join(dir1, ".terraform-version"), []byte("1.8.0\n"), 0644)

	res1, err := DiscoverAll(dir1)
	if err != nil {
		t.Fatal(err)
	}
	for _, tr := range res1.Technologies {
		if tr.Technology == "terraform" && tr.Status != "detected" {
			t.Errorf("Scenario 1: Expected terraform detected, got %s", tr.Status)
		}
		if tr.Technology == "opentofu" && tr.Status != "absent" {
			t.Errorf("Scenario 1: Expected opentofu absent, got %s", tr.Status)
		}
	}

	// Scenario 2: Unmarked .tf -> ambiguous
	dir2 := t.TempDir()
	os.WriteFile(filepath.Join(dir2, "main.tf"), []byte(`resource "null_resource" "x" {}`), 0644)

	res2, err := DiscoverAll(dir2)
	if err != nil {
		t.Fatal(err)
	}
	for _, tr := range res2.Technologies {
		if tr.Technology == "terraform" && tr.Status != "ambiguous" {
			t.Errorf("Scenario 2: Expected terraform ambiguous, got %s", tr.Status)
		}
	}

	// Scenario 3: Contradictory markers
	dir3 := t.TempDir()
	os.WriteFile(filepath.Join(dir3, "main.tf"), []byte(`resource "null_resource" "x" {}`), 0644)
	os.WriteFile(filepath.Join(dir3, ".terraform-version"), []byte("1.8.0\n"), 0644)
	os.WriteFile(filepath.Join(dir3, ".opentofu-version"), []byte("1.7.0\n"), 0644)

	res3, err := DiscoverAll(dir3)
	if err != nil {
		t.Fatal(err)
	}
	for _, tr := range res3.Technologies {
		if tr.Technology == "terraform" && tr.Status != "ambiguous" {
			t.Errorf("Scenario 3: Expected terraform ambiguous, got %s", tr.Status)
		}
		if tr.Technology == "opentofu" && tr.Status != "ambiguous" {
			t.Errorf("Scenario 3: Expected opentofu ambiguous, got %s", tr.Status)
		}
	}
}

func TestKubernetesAndAnsibleDetection(t *testing.T) {
	tempDir := t.TempDir()

	// Kubernetes valid resource
	k8sFile := filepath.Join(tempDir, "deploy.yaml")
	os.WriteFile(k8sFile, []byte(`
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
`), 0644)

	// Ansible playbook
	ansibleFile := filepath.Join(tempDir, "playbooks", "site.yml")
	os.MkdirAll(filepath.Dir(ansibleFile), 0755)
	os.WriteFile(ansibleFile, []byte(`
- name: Setup servers
  hosts: all
  tasks:
    - name: ping
      ansible.builtin.ping:
`), 0644)

	res, err := DiscoverAll(tempDir)
	if err != nil {
		t.Fatal(err)
	}

	statusMap := make(map[string]string)
	for _, tr := range res.Technologies {
		statusMap[tr.Technology] = tr.Status
	}

	if statusMap["kubernetes"] != "detected" {
		t.Errorf("Expected kubernetes detected, got %s", statusMap["kubernetes"])
	}
	if statusMap["ansible"] != "detected" {
		t.Errorf("Expected ansible detected, got %s", statusMap["ansible"])
	}
}
