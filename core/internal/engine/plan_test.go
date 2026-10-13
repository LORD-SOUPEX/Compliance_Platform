package engine

import (
	"path/filepath"
	"testing"

	"compliance/internal/catalog"
	"compliance/internal/discovery"
	"compliance/internal/matrix"
)

func TestBuildCompliancePlan_All28Controls(t *testing.T) {
	catPath := filepath.Join("..", "..", "..", ".config", "control-catalog.json")
	cat, err := catalog.LoadCatalog(catPath)
	if err != nil {
		t.Fatalf("LoadCatalog failed: %v", err)
	}

	// Create discoveries with all 13 technologies detected
	discoveries := []discovery.TechnologyRecord{
		{Technology: "terraform", Status: "detected", Roots: []string{"infra/tf"}, Evidence: []string{"infra/tf/main.tf"}, Ambiguities: []string{}},
		{Technology: "opentofu", Status: "detected", Roots: []string{"infra/tofu"}, Evidence: []string{"infra/tofu/main.tofu"}, Ambiguities: []string{}},
		{Technology: "terragrunt", Status: "detected", Roots: []string{"infra/tg"}, Evidence: []string{"infra/tg/terragrunt.hcl"}, Ambiguities: []string{}},
		{Technology: "ansible", Status: "detected", Roots: []string{"playbooks"}, Evidence: []string{"playbooks/site.yml"}, Ambiguities: []string{}},
		{Technology: "python", Status: "detected", Roots: []string{"src/py"}, Evidence: []string{"src/py/app.py", "src/py/requirements.txt"}, Ambiguities: []string{}},
		{Technology: "powershell", Status: "detected", Roots: []string{"scripts"}, Evidence: []string{"scripts/setup.ps1"}, Ambiguities: []string{}},
		{Technology: "docker", Status: "detected", Roots: []string{"docker"}, Evidence: []string{"docker/Dockerfile"}, Ambiguities: []string{}},
		{Technology: "kubernetes", Status: "detected", Roots: []string{"k8s"}, Evidence: []string{"k8s/deploy.yaml"}, Ambiguities: []string{}},
		{Technology: "helm", Status: "detected", Roots: []string{"charts"}, Evidence: []string{"charts/Chart.yaml"}, Ambiguities: []string{}},
		{Technology: "shell", Status: "detected", Roots: []string{"bin"}, Evidence: []string{"bin/run.sh"}, Ambiguities: []string{}},
		{Technology: "javascript", Status: "detected", Roots: []string{"web"}, Evidence: []string{"web/index.js"}, Ambiguities: []string{}},
		{Technology: "typescript", Status: "detected", Roots: []string{"app"}, Evidence: []string{"app/main.ts"}, Ambiguities: []string{}},
		{Technology: "markdown", Status: "detected", Roots: []string{"docs"}, Evidence: []string{"docs/readme.md"}, Ambiguities: []string{}},
	}

	platform := matrix.PlatformInfo{OS: "windows", Architecture: "x64", ID: "windows-x64"}

	// Mock resolver that makes tools available
	mockResolver := &mockResolverMap{
		available: map[string]bool{
			"terraform":             true,
			"tflint":                true,
			"checkov":               true,
			"tofu":                  true,
			"terragrunt":            true,
			"yamllint":              true,
			"ruff":                  true,
			"pylint":                true,
			"pytest":                true,
			"bandit":                true,
			"pip-audit":             true,
			"Invoke-ScriptAnalyzer": true,
			"hadolint":              true,
			"trivy":                 true,
			"pre-commit":            true,
		},
	}

	mat := matrix.BuildCapabilityMatrix(discoveries, cat, platform, mockResolver, ".")
	res := matrix.ResolveCapabilityTools(mat)

	plan, orderedControls, err := BuildCompliancePlan(discoveries, mat, res, ".", PlanOptions{
		TimeoutSeconds:       30,
		GlobalTimeoutSeconds: 300,
		AllowNetwork:         true,
		AllowCodeExecution:   true,
	})
	if err != nil {
		t.Fatalf("BuildCompliancePlan failed: %v", err)
	}

	if plan.SchemaVersion != 1 {
		t.Errorf("expected plan SchemaVersion 1, got %d", plan.SchemaVersion)
	}

	if len(orderedControls) != 28 {
		t.Errorf("expected exactly 28 controls planned, got %d", len(orderedControls))
	}

	// Verify topological order: execution_order must be sequential 1..28
	for i, c := range orderedControls {
		if c.ExecutionOrder != i+1 {
			t.Errorf("control %s has execution order %d, expected %d", c.ID, c.ExecutionOrder, i+1)
		}
	}
}

type mockResolverMap struct {
	available map[string]bool
}

func (m *mockResolverMap) ResolveCandidate(name, command string, platform matrix.PlatformInfo, repoRoot string) matrix.CandidateToolState {
	status := "not_installed"
	if m.available[command] {
		status = "available"
	}
	src := "/mock/bin/" + command
	ver := "1.0.0"
	return matrix.CandidateToolState{
		Name:           name,
		Command:        command,
		Status:         status,
		Source:         &src,
		Version:        &ver,
		Platform:       platform.ID,
		RuntimeManaged: true,
	}
}
