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

// ParsePipeline parses a pipeline from JSON bytes with strict field checking.
func ParsePipeline(data []byte) (*Pipeline, error) {
	var p Pipeline
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("erreur de décodage JSON du pipeline: %w", err)
	}

	if p.Version != "1" {
		return nil, fmt.Errorf("%w: version %q non supportée (attendu: '1')", ErrGuardrailViolation, p.Version)
	}

	if !isValidCategory(p.Category) {
		return nil, fmt.Errorf("%w: catégorie %q invalide", ErrGuardrailViolation, p.Category)
	}

	if sideEffectRank(p.SideEffectLevel) == -1 {
		return nil, fmt.Errorf("%w: niveau d'effet de bord global %q invalide", ErrGuardrailViolation, p.SideEffectLevel)
	}

	if len(p.Steps) == 0 {
		return nil, fmt.Errorf("%w: le pipeline doit contenir au moins une étape", ErrGuardrailViolation)
	}

	if err := ValidateDAG(&p); err != nil {
		return nil, err
	}

	return &p, nil
}

func isValidCategory(cat string) bool {
	switch cat {
	case "quality", "dev_deployment", "ephemeral_sandbox", "maintenance":
		return true
	default:
		return false
	}
}

func sideEffectRank(level string) int {
	switch level {
	case "read_only":
		return 0
	case "filesystem":
		return 1
	case "network":
		return 2
	case "apply_destroy":
		return 3
	default:
		return -1
	}
}

// LoadPipelineFile loads and validates a declarative pipeline JSON file.
func LoadPipelineFile(path string) (*Pipeline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("lecture du fichier pipeline impossible: %w", err)
	}
	return ParsePipeline(data)
}

// ValidateDAG verifies step uniqueness, dependency existence, cycle freedom, and guardrail consistency.
func ValidateDAG(p *Pipeline) error {
	stepMap := make(map[string]PipelineStep)
	pipeRank := sideEffectRank(p.SideEffectLevel)

	for _, step := range p.Steps {
		if step.ID == "" {
			return fmt.Errorf("%w: identifiant d'étape vide", ErrGuardrailViolation)
		}
		if _, exists := stepMap[step.ID]; exists {
			return fmt.Errorf("%w: étape %q", ErrDuplicateStepID, step.ID)
		}
		if step.TimeoutSeconds < 1 {
			return fmt.Errorf("%w: timeout_seconds pour l'étape %q doit être >= 1", ErrGuardrailViolation, step.ID)
		}

		stepRank := sideEffectRank(step.SideEffect)
		if stepRank == -1 {
			return fmt.Errorf("%w: effet de bord %q invalide pour l'étape %q", ErrGuardrailViolation, step.SideEffect, step.ID)
		}

		// Règle de confinement : une étape ne peut pas dépasser le plafond global du pipeline
		if stepRank > pipeRank {
			return fmt.Errorf("%w: l'étape %q (%s) dépasse le niveau global du pipeline (%s)",
				ErrGuardrailViolation, step.ID, step.SideEffect, p.SideEffectLevel)
		}

		// Règle de sécurité : toute étape apply_destroy exige une section guardrails valide
		if step.SideEffect == "apply_destroy" && p.Guardrails == nil {
			return fmt.Errorf("%w: l'étape %q est en apply_destroy mais aucun guardrails n'est configuré dans le pipeline",
				ErrGuardrailViolation, step.ID)
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
	StateBackend  string
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
		return fmt.Errorf("%w: exécution bloquée : section guardrails absente pour l'étape apply_destroy %q", ErrGuardrailViolation, step.ID)
	}

	// 2. Forbidden environments check (exact or token-based: prod, prod-*, *-prod, shared-*, etc.)
	envClean := strings.ToLower(strings.TrimSpace(ctx.Environment))
	for _, forbidden := range p.Guardrails.ForbiddenEnvironments {
		forbClean := strings.ToLower(strings.TrimSpace(forbidden))
		if matchForbiddenEnv(forbClean, envClean) {
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

	// 6. State backend restrictions check
	if len(p.Guardrails.StateBackendRestrictions) > 0 && ctx.StateBackend != "" {
		backendClean := strings.ToLower(strings.TrimSpace(ctx.StateBackend))
		backendAllowed := false
		for _, pat := range p.Guardrails.StateBackendRestrictions {
			patClean := strings.ToLower(strings.TrimSpace(pat))
			if matchEnvPattern(patClean, backendClean) {
				backendAllowed = true
				break
			}
		}
		if !backendAllowed {
			return fmt.Errorf("%w: state backend %q non autorisé pour l'étape %q (autorisés: %v)",
				ErrGuardrailViolation, ctx.StateBackend, step.ID, p.Guardrails.StateBackendRestrictions)
		}
	}

	return nil
}

func matchForbiddenEnv(forbidden, env string) bool {
	if env == forbidden {
		return true
	}
	for _, sep := range []string{"-", "_", ".", "/"} {
		if strings.HasPrefix(env, forbidden+sep) || strings.HasSuffix(env, sep+forbidden) || strings.Contains(env, sep+forbidden+sep) {
			return true
		}
	}
	return false
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
