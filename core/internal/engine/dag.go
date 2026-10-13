package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var (
	ErrDuplicateStepID       = errors.New("identifiant d'étape dupliqué dans le pipeline")
	ErrMissingDependency     = errors.New("dépendance introuvable dans le pipeline")
	ErrCycleDetected         = errors.New("cycle de dépendances détecté dans le DAG")
	ErrGuardrailViolation    = errors.New("violation des garde-fous d'exécution")
	ErrForbiddenEnvironment  = errors.New("exécution bloquée : environnement dans la liste noire interdite")
	ErrEnvironmentNotAllowed = errors.New("exécution bloquée : environnement absent de la liste blanche autorisée")
	ErrPlanRequired          = errors.New("exécution bloquée : étape de plan préalable non validée pour apply_destroy")
	ErrConfirmationRequired  = errors.New("exécution bloquée : confirmation explicite requise pour apply_destroy")
	ErrRunAllForbidden       = errors.New("exécution bloquée : les étapes apply_destroy ne peuvent pas être exécutées via Run All")
)

// Pipeline represents a declarative tool pipeline conforming to pipeline.schema.json.
type Pipeline struct {
	Version         string                `json:"version"`
	ID              string                `json:"id"`
	Name            string                `json:"name"`
	Technology      string                `json:"technology"`
	Category        string                `json:"category"`
	SideEffectLevel string                `json:"side_effect_level"`
	Guardrails      *GuardrailsDefinition `json:"guardrails,omitempty"`
	Steps           []PipelineStep        `json:"steps"`
}

// GuardrailsDefinition defines security guardrails for destructive steps.
type GuardrailsDefinition struct {
	AllowedEnvironments          []string `json:"allowed_environments,omitempty"`
	ForbiddenEnvironments        []string `json:"forbidden_environments,omitempty"`
	RequirePlanPreview           bool     `json:"require_plan_preview,omitempty"`
	RequireExplicitConfirmation  bool     `json:"require_explicit_confirmation,omitempty"`
	StateBackendRestrictions     []string `json:"state_backend_restrictions,omitempty"`
}

// PipelineStep represents a single node in the DAG.
type PipelineStep struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Tool           string            `json:"tool"`
	Args           []string          `json:"args"`
	SideEffect     string            `json:"side_effect"`
	TimeoutSeconds int               `json:"timeout_seconds"`
	DependsOn      []string          `json:"depends_on,omitempty"`
	Env            map[string]string `json:"env,omitempty"`
}

// ParsePipeline parses a pipeline from JSON bytes.
func ParsePipeline(data []byte) (*Pipeline, error) {
	var p Pipeline
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("erreur de décodage JSON du pipeline: %w", err)
	}

	if err := ValidateDAG(&p); err != nil {
		return nil, err
	}

	return &p, nil
}

// LoadPipelineFile loads and validates a declarative pipeline JSON file.
func LoadPipelineFile(path string) (*Pipeline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("lecture du fichier pipeline impossible: %w", err)
	}
	return ParsePipeline(data)
}

// ValidateDAG verifies step uniqueness, dependency existence, and cycle freedom.
func ValidateDAG(p *Pipeline) error {
	stepMap := make(map[string]PipelineStep)

	for _, step := range p.Steps {
		if _, exists := stepMap[step.ID]; exists {
			return fmt.Errorf("%w: étape %q", ErrDuplicateStepID, step.ID)
		}
		stepMap[step.ID] = step
	}

	// Verify all depends_on refer to existing steps
	for _, step := range p.Steps {
		for _, dep := range step.DependsOn {
			if _, exists := stepMap[dep]; !exists {
				return fmt.Errorf("%w: étape %q dépend de %q inexistant", ErrMissingDependency, step.ID, dep)
			}
			if dep == step.ID {
				return fmt.Errorf("%w: étape %q dépend d'elle-même", ErrCycleDetected, step.ID)
			}
		}
	}

	// Cycle detection using Kahn's algorithm
	_, err := ComputeTopologicalOrder(p)
	if err != nil {
		return err
	}

	return nil
}

// ComputeTopologicalOrder returns a deterministic execution plan of steps.
// If dependencies form a cycle, ErrCycleDetected is returned.
func ComputeTopologicalOrder(p *Pipeline) ([]PipelineStep, error) {
	stepMap := make(map[string]PipelineStep)
	inDegree := make(map[string]int)
	graph := make(map[string][]string) // dependency -> steps that depend on it

	for _, step := range p.Steps {
		stepMap[step.ID] = step
		inDegree[step.ID] = len(step.DependsOn)
		for _, dep := range step.DependsOn {
			graph[dep] = append(graph[dep], step.ID)
		}
	}

	// Collect zero in-degree nodes
	var queue []string
	for id, deg := range inDegree {
		if deg == 0 {
			queue = append(queue, id)
		}
	}

	// Deterministic sorting for initial tier
	sort.Strings(queue)

	var ordered []PipelineStep
	visitedCount := 0

	for len(queue) > 0 {
		currID := queue[0]
		queue = queue[1:]

		ordered = append(ordered, stepMap[currID])
		visitedCount++

		// Decrease in-degree for dependents
		var nextEligible []string
		for _, dependent := range graph[currID] {
			inDegree[dependent]--
			if inDegree[dependent] == 0 {
				nextEligible = append(nextEligible, dependent)
			}
		}

		// Sort next eligible deterministically before enqueuing
		sort.Strings(nextEligible)
		queue = append(queue, nextEligible...)
	}

	if visitedCount != len(p.Steps) {
		// Identify remaining steps for cycle diagnosis
		var cycleSteps []string
		for id, deg := range inDegree {
			if deg > 0 {
				cycleSteps = append(cycleSteps, id)
			}
		}
		sort.Strings(cycleSteps)
		return nil, fmt.Errorf("%w: cycle impliquant les étapes %v", ErrCycleDetected, cycleSteps)
	}

	return ordered, nil
}

// GuardrailContext encapsulates execution context for guardrail evaluation.
type GuardrailContext struct {
	Environment   string
	IsRunAll      bool
	UserConfirmed bool
	PlanSucceeded bool
}

// ValidateStepGuardrails evaluates guardrails for a specific step before execution.
func ValidateStepGuardrails(p *Pipeline, step *PipelineStep, ctx GuardrailContext) error {
	isApplyDestroy := step.SideEffect == "apply_destroy" || p.SideEffectLevel == "apply_destroy"
	if !isApplyDestroy {
		return nil // Read-only, network, filesystem steps don't trigger apply_destroy guardrails
	}

	// 1. Protection absolue Run All
	if ctx.IsRunAll {
		return fmt.Errorf("%w: étape %q", ErrRunAllForbidden, step.ID)
	}

	if p.Guardrails == nil {
		return nil
	}

	// 2. Forbidden environments check (case-insensitive substring/match)
	envClean := strings.ToLower(strings.TrimSpace(ctx.Environment))
	for _, forbidden := range p.Guardrails.ForbiddenEnvironments {
		forbClean := strings.ToLower(strings.TrimSpace(forbidden))
		if envClean == forbClean || strings.Contains(envClean, forbClean) {
			return fmt.Errorf("%w: environnement %q interdit par la règle %q pour l'étape %q",
				ErrForbiddenEnvironment, ctx.Environment, forbidden, step.ID)
		}
	}

	// 3. Allowed environments check (wildcard support)
	if len(p.Guardrails.AllowedEnvironments) > 0 {
		allowed := false
		for _, pattern := range p.Guardrails.AllowedEnvironments {
			patClean := strings.ToLower(strings.TrimSpace(pattern))
			if matchEnvPattern(patClean, envClean) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("%w: environnement %q non autorisé pour l'étape %q (autorisés: %v)",
				ErrEnvironmentNotAllowed, ctx.Environment, step.ID, p.Guardrails.AllowedEnvironments)
		}
	}

	// 4. Require plan preview
	if p.Guardrails.RequirePlanPreview && !ctx.PlanSucceeded {
		return fmt.Errorf("%w: étape %q requiert la réussite préalable du plan",
			ErrPlanRequired, step.ID)
	}

	// 5. Require explicit confirmation
	if p.Guardrails.RequireExplicitConfirmation && !ctx.UserConfirmed {
		return fmt.Errorf("%w: confirmation requise pour l'étape %q",
			ErrConfirmationRequired, step.ID)
	}

	return nil
}

func matchEnvPattern(pattern, env string) bool {
	if pattern == env {
		return true
	}
	if matched, err := filepath.Match(pattern, env); err == nil && matched {
		return true
	}
	return false
}
