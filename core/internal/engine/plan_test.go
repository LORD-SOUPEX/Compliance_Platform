package engine

import (
	"path/filepath"
	"testing"

	"compliance/internal/discovery"
	"compliance/internal/matrix"
)

func TestBuildCompliancePlan_All28Controls(t *testing.T) {
	catPath := filepath.Join("..", "..", "..", ".config", "control-catalog.json")
	cat, err := matrix.LoadCatalog(catPath)
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

func TestLinearAndBranchingDAG(t *testing.T) {
	// Diamond DAG:
	//       init
	//      /    \
	//   lint    sec
	//      \    /
	//      build
	p := &Pipeline{
		Version:         "1",
		ID:              "test.diamond",
		Name:            "Diamond Test Pipeline",
		Technology:      "general",
		Category:        "quality",
		SideEffectLevel: "read_only",
		Steps: []PipelineStep{
			{ID: "build", Name: "Build Step", Tool: "builder", SideEffect: "read_only", TimeoutSeconds: 30, DependsOn: []string{"lint", "sec"}},
			{ID: "lint", Name: "Lint Step", Tool: "linter", SideEffect: "read_only", TimeoutSeconds: 30, DependsOn: []string{"init"}},
			{ID: "sec", Name: "Sec Step", Tool: "scanner", SideEffect: "read_only", TimeoutSeconds: 30, DependsOn: []string{"init"}},
			{ID: "init", Name: "Init Step", Tool: "initer", SideEffect: "read_only", TimeoutSeconds: 30},
		},
	}

	ordered, err := ComputeTopologicalOrder(p)
	if err != nil {
		t.Fatalf("ComputeTopologicalOrder failed: %v", err)
	}

	if len(ordered) != 4 {
		t.Fatalf("Expected 4 steps, got %d", len(ordered))
	}

	if ordered[0].ID != "init" {
		t.Errorf("Expected first step to be 'init', got %s", ordered[0].ID)
	}
	if ordered[3].ID != "build" {
		t.Errorf("Expected last step to be 'build', got %s", ordered[3].ID)
	}

	// Middle two should be 'lint' and 'sec' in deterministic alphabetical order
	if ordered[1].ID != "lint" || ordered[2].ID != "sec" {
		t.Errorf("Expected middle steps [lint, sec], got [%s, %s]", ordered[1].ID, ordered[2].ID)
	}
}

func TestCycleDetection(t *testing.T) {
	// Cycle: A -> B -> C -> A
	p := &Pipeline{
		Version:         "1",
		ID:              "test.cycle",
		Name:            "Cycle Pipeline",
		Technology:      "general",
		Category:        "quality",
		SideEffectLevel: "read_only",
		Steps: []PipelineStep{
			{ID: "a", Name: "A", Tool: "tool", SideEffect: "read_only", TimeoutSeconds: 10, DependsOn: []string{"c"}},
			{ID: "b", Name: "B", Tool: "tool", SideEffect: "read_only", TimeoutSeconds: 10, DependsOn: []string{"a"}},
			{ID: "c", Name: "C", Tool: "tool", SideEffect: "read_only", TimeoutSeconds: 10, DependsOn: []string{"b"}},
		},
	}

	err := ValidateDAG(p)
	if err == nil {
		t.Fatalf("Expected error for cyclic DAG, got nil")
	}
	t.Logf("Cycle correctly rejected: %v", err)
}

func TestSelfCycleAndMissingDep(t *testing.T) {
	// Self-cycle: A -> A
	pSelf := &Pipeline{
		Version:         "1",
		ID:              "test.self",
		Name:            "Self Cycle",
		Technology:      "general",
		Category:        "quality",
		SideEffectLevel: "read_only",
		Steps: []PipelineStep{
			{ID: "a", Name: "A", Tool: "tool", SideEffect: "read_only", TimeoutSeconds: 10, DependsOn: []string{"a"}},
		},
	}
	if err := ValidateDAG(pSelf); err == nil {
		t.Errorf("Expected error for self cycle")
	}

	// Missing dependency
	pMissing := &Pipeline{
		Version:         "1",
		ID:              "test.missing",
		Name:            "Missing Dep",
		Technology:      "general",
		Category:        "quality",
		SideEffectLevel: "read_only",
		Steps: []PipelineStep{
			{ID: "a", Name: "A", Tool: "tool", SideEffect: "read_only", TimeoutSeconds: 10, DependsOn: []string{"unknown_step"}},
		},
	}
	if err := ValidateDAG(pMissing); err == nil {
		t.Errorf("Expected error for missing dependency")
	}
}

func TestGuardrailsOnApplyDestroy(t *testing.T) {
	pipelinePath := filepath.Join("..", "..", "..", ".config", "pipelines", "terraform.dev-deployment.json")
	p, err := LoadPipelineFile(pipelinePath)
	if err != nil {
		t.Fatalf("Failed to load terraform pipeline: %v", err)
	}

	applyStep := &p.Steps[2] // step "apply"
	if applyStep.ID != "apply" {
		t.Fatalf("Expected step 'apply', got %s", applyStep.ID)
	}

	// 1. Run All protection
	err = ValidateStepGuardrails(p, applyStep, GuardrailContext{
		Environment:   "sandbox",
		IsRunAll:      true,
		UserConfirmed: true,
		PlanSucceeded: true,
	})
	if err == nil {
		t.Errorf("Expected Run All to be blocked on apply_destroy")
	}

	// 2. Forbidden environment 'prod'
	err = ValidateStepGuardrails(p, applyStep, GuardrailContext{
		Environment:   "production",
		IsRunAll:      false,
		UserConfirmed: true,
		PlanSucceeded: true,
	})
	if err == nil {
		t.Errorf("Expected 'production' environment to be blocked")
	}

	// 3. Staging forbidden
	err = ValidateStepGuardrails(p, applyStep, GuardrailContext{
		Environment:   "staging",
		IsRunAll:      false,
		UserConfirmed: true,
		PlanSucceeded: true,
	})
	if err == nil {
		t.Errorf("Expected 'staging' environment to be blocked")
	}

	// 4. Missing plan preview
	err = ValidateStepGuardrails(p, applyStep, GuardrailContext{
		Environment:   "sandbox",
		IsRunAll:      false,
		UserConfirmed: true,
		PlanSucceeded: false,
	})
	if err == nil {
		t.Errorf("Expected failure when plan preview did not succeed")
	}

	// 5. Missing explicit confirmation
	err = ValidateStepGuardrails(p, applyStep, GuardrailContext{
		Environment:   "sandbox",
		IsRunAll:      false,
		UserConfirmed: false,
		PlanSucceeded: true,
	})
	if err == nil {
		t.Errorf("Expected failure when user has not explicitly confirmed")
	}

	// 6. Valid authorization in sandbox
	err = ValidateStepGuardrails(p, applyStep, GuardrailContext{
		Environment:   "sandbox",
		IsRunAll:      false,
		UserConfirmed: true,
		PlanSucceeded: true,
	})
	if err != nil {
		t.Errorf("Expected success for valid sandbox execution, got: %v", err)
	}

	// 7. Valid authorization in wildcard ephemeral-*
	err = ValidateStepGuardrails(p, applyStep, GuardrailContext{
		Environment:   "ephemeral-feature1",
		IsRunAll:      false,
		UserConfirmed: true,
		PlanSucceeded: true,
	})
	if err != nil {
		t.Errorf("Expected success for 'ephemeral-feature1' in 'ephemeral-*' wildcard, got: %v", err)
	}

	// 8. Valid authorization for exact dev-local
	err = ValidateStepGuardrails(p, applyStep, GuardrailContext{
		Environment:   "dev-local",
		IsRunAll:      false,
		UserConfirmed: true,
		PlanSucceeded: true,
	})
	if err != nil {
		t.Errorf("Expected success for 'dev-local', got: %v", err)
	}
}

func TestLoadAllRepoPipelines(t *testing.T) {
	pipelines := []string{
		filepath.Join("..", "..", "..", ".config", "pipelines", "python.quality.json"),
		filepath.Join("..", "..", "..", ".config", "pipelines", "terraform.dev-deployment.json"),
	}

	for _, path := range pipelines {
		p, err := LoadPipelineFile(path)
		if err != nil {
			t.Fatalf("Failed to load and validate %s: %v", path, err)
		}
		ordered, err := ComputeTopologicalOrder(p)
		if err != nil {
			t.Fatalf("Failed to compute topological order for %s: %v", path, err)
		}
		t.Logf("SUCCESS: Pipeline %s ordonnancé avec %d étapes:", p.ID, len(ordered))
		for idx, s := range ordered {
			t.Logf("  [%d] %s (tool: %s, side_effect: %s, depends_on: %v)", idx+1, s.ID, s.Tool, s.SideEffect, s.DependsOn)
		}
	}
}

