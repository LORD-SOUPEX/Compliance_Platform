package engine

import (
	"path/filepath"
	"testing"
)

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
