package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"compliance/internal/discovery"
	"compliance/internal/distribution"
	"compliance/internal/embedded"
	"compliance/internal/matrix"
	"compliance/internal/osutil"
	"compliance/internal/report"
)

// PlannedControl defines an individual scheduled control in an ExecutionPlan.
type PlannedControl struct {
	ID                  string                     `json:"id"`
	Name                string                     `json:"name"`
	Technology          string                     `json:"technology"`
	Capability          string                     `json:"capability"`
	Tool                *matrix.CandidateToolState `json:"tool"`
	ControlCatalogID    *string                    `json:"control_catalog_id"`
	Root                string                     `json:"root"`
	Applicability       string                     `json:"applicability"`
	ReasonCode          string                     `json:"reason_code"`
	ExecutionOrder      int                        `json:"execution_order"`
	Timeout             int                        `json:"timeout"`
	MaxOutputBytes      int64                      `json:"max_output_bytes"`
	Dependencies        []string                   `json:"dependencies"`
	CatalogDependencies []string                   `json:"catalog_dependencies"`
	SideEffectLevel     string                     `json:"side_effect_level"`
	Severity            string                     `json:"severity"`
	Cost                string                     `json:"cost"`
	Permissions         []string                   `json:"permissions"`
	PlatformSupport     []string                   `json:"platform_support"`
	Limitations         []string                   `json:"limitations"`
	Parameters          map[string]interface{}     `json:"parameters"`
	Required            bool                       `json:"required"`
	Reason              string                     `json:"reason"`
	Files               []string                   `json:"files"`
}

// PlanOptions configures plan generation.
type PlanOptions struct {
	TimeoutSeconds          int
	GlobalTimeoutSeconds    int
	MaxOutputBytesPerStream int64
	MaximumControls         int
	AllowNetwork            bool
	AllowCodeExecution      bool
	CustomDependencies      map[string][]string
	PlatformID              string
	DisabledTechnologies    []string
	DisabledControls        []string
}

func evidenceSamples(tech discovery.TechnologyRecord, root string) []string {
	if tokens := tech.RootProof[root]; len(tokens) > 0 {
		return tokens
	}
	if root == "." {
		return tech.Evidence
	}
	prefix := strings.TrimSuffix(filepath.ToSlash(root), "/") + "/"
	var samples []string
	for _, ev := range tech.Evidence {
		if strings.HasPrefix(strings.ToLower(filepath.ToSlash(ev)), strings.ToLower(prefix)) {
			samples = append(samples, ev)
		}
	}
	return samples
}

func evidenceTokenMatches(sample, wanted string) bool {
	base := filepath.Base(filepath.ToSlash(sample))
	ext := filepath.Ext(base)
	if strings.EqualFold(base, wanted) || strings.EqualFold(ext, wanted) || strings.EqualFold(sample, wanted) {
		return true
	}
	if strings.EqualFold(wanted, "Dockerfile") || strings.EqualFold(wanted, "Containerfile") {
		return discovery.IsContainerFile(base)
	}
	return false
}

// BuildCompliancePlan creates an ExecutionPlan following the exact PowerShell contract.
func BuildCompliancePlan(
	discoveries []discovery.TechnologyRecord,
	mat []matrix.CapabilityMatrixEntry,
	res []matrix.ToolResolutionEntry,
	repoRoot string,
	opts PlanOptions,
) (*report.ExecutionPlan, []*PlannedControl, error) {
	absRepo, err := osutil.CanonicalPath(repoRoot)
	if err != nil {
		return nil, nil, err
	}
	cleanRepo := filepath.Clean(absRepo)
	prefix := cleanRepo + string(filepath.Separator)

	timeout := opts.TimeoutSeconds
	if timeout <= 0 {
		timeout = 300
	}
	globalTimeout := opts.GlobalTimeoutSeconds
	if globalTimeout <= 0 {
		globalTimeout = 1800
	}
	maxOutput := opts.MaxOutputBytesPerStream
	if maxOutput <= 0 {
		maxOutput = 1048576
	}
	maxControls := opts.MaximumControls
	if maxControls <= 0 {
		maxControls = 5000
	}

	// Map matrix and resolver by technology
	matrixMap := make(map[string]matrix.CapabilityMatrixEntry)
	for _, m := range mat {
		matrixMap[m.Technology] = m
	}
	resolverMap := make(map[string]matrix.ToolResolutionEntry)
	for _, r := range res {
		resolverMap[r.Technology] = r
	}

	// Sort discoveries by technology
	sortedDisc := make([]discovery.TechnologyRecord, len(discoveries))
	copy(sortedDisc, discoveries)
	sort.Slice(sortedDisc, func(i, j int) bool {
		return sortedDisc[i].Technology < sortedDisc[j].Technology
	})

	var controls []*PlannedControl
	controlIDs := make(map[string]bool)

	for _, tech := range sortedDisc {
		matrixEntry, okM := matrixMap[tech.Technology]
		resolution, okR := resolverMap[tech.Technology]
		if !okM || !okR {
			return nil, nil, errors.New("Discovery, Matrix et Resolver doivent correspondre par technologie")
		}
		if tech.Status != matrixEntry.TechnologyStatus || tech.Status != resolution.TechnologyStatus {
			return nil, nil, errors.New("statuts de technologie incoherents entre les contrats")
		}

		roots := tech.Roots
		if len(roots) == 0 {
			roots = []string{"."}
		} else {
			sort.Strings(roots)
		}

		// Sort capabilities by name
		caps := make([]matrix.CapabilityEntry, len(matrixEntry.Capabilities))
		copy(caps, matrixEntry.Capabilities)
		sort.Slice(caps, func(i, j int) bool {
			return caps[i].Name < caps[j].Name
		})

		for _, capability := range caps {
			alternative := (capability.SelectionPolicy == "alternative")
			hasAlternative := false
			if alternative {
				for _, st := range resolution.SelectedTools {
					for _, c := range st.Capabilities {
						if c == capability.Name {
							hasAlternative = true
							break
						}
					}
					if hasAlternative {
						break
					}
				}
			}

			candidates := capability.CandidateTools
			if len(candidates) == 0 {
				candidates = []matrix.CandidateToolState{{Name: "", Command: "none"}}
			}

			for _, root := range roots {
				if filepath.IsAbs(root) {
					return nil, nil, errors.New("une racine de controle doit etre relative au depot")
				}
				absRoot := filepath.Clean(filepath.Join(cleanRepo, filepath.FromSlash(root)))
				if absRoot != cleanRepo && !strings.HasPrefix(strings.ToLower(absRoot), strings.ToLower(prefix)) {
					return nil, nil, errors.New("une racine de controle sort du depot")
				}

				for _, cand := range candidates {
					var candidate *matrix.CandidateToolState
					if cand.Command != "none" {
						cCopy := cand
						candidate = &cCopy
					}

					var selected []matrix.SelectedTool
					if candidate != nil {
						for _, st := range resolution.SelectedTools {
							if st.Command == candidate.Command {
								for _, capName := range st.Capabilities {
									if capName == capability.Name {
										selected = append(selected, st)
										break
									}
								}
							}
						}
					}

					applicability := "applicable"
					reason := ""
					if tech.Status == "absent" {
						applicability = "technology_absent"
					} else if tech.Status == "ambiguous" {
						applicability = "ambiguous"
					} else if !capability.Required {
						applicability = "not_applicable"
					} else if hasAlternative && len(selected) == 0 {
						applicability = "not_applicable"
					} else if candidate != nil && candidate.Command != "" && candidate.Command != "none" && candidate.Status != "available" {
						applicability = "tool_unavailable"
					} else if candidate == nil || capability.Availability == "unavailable" || capability.Availability == "unconfigured" {
						applicability = "capability_unavailable"
					} else if candidate.Status != "available" {
						applicability = "tool_unavailable"
					} else if len(selected) == 0 {
						applicability = "not_applicable"
					} else {
						applicability = "applicable"
					}

					if candidate != nil && candidate.Reason != "" {
						reason = candidate.Reason
					}
					if applicability == "not_applicable" && hasAlternative && len(selected) == 0 {
						var chosen []string
						for _, st := range resolution.SelectedTools {
							for _, capName := range st.Capabilities {
								if capName == capability.Name {
									chosen = append(chosen, st.Command)
									break
								}
							}
						}
						if len(chosen) > 0 {
							reason = fmt.Sprintf("Alternative non retenue : %s couvre déjà %s.", strings.Join(chosen, ", "), capability.Name)
						} else {
							reason = "Capacite non requise ou candidat non retenu par le resolver."
						}
					} else if applicability == "not_applicable" {
						reason = "Capacite non requise ou candidat non retenu par le resolver."
					}
					if applicability == "ambiguous" {
						reason = strings.Join(tech.Ambiguities, "; ")
					}
					if applicability == "capability_unavailable" {
						reason = strings.Join(capability.Reasons, "; ")
					}
					if applicability == "technology_absent" {
						reason = "Technologie absente selon Discovery."
					}

					reasonCode := applicability
					if hasAlternative && len(selected) == 0 && applicability == "not_applicable" {
						reasonCode = "alternative_not_selected"
					}

					command := "none"
					if candidate != nil {
						command = candidate.Command
					}

					var catalogCtrl *matrix.CatalogControl
					if len(capability.CatalogControls) > 0 {
						if candidate != nil && candidate.CatalogID != "" {
							for i := range capability.CatalogControls {
								if capability.CatalogControls[i].ID == candidate.CatalogID {
									catalogCtrl = &capability.CatalogControls[i]
									break
								}
							}
						}
						if catalogCtrl == nil && candidate == nil && len(capability.CatalogControls) == 1 {
							catalogCtrl = &capability.CatalogControls[0]
						}
					}

					// Evidence checking. The displayed sample is capped; root_proof keeps
					// every accepted root's extensions and file names.
					rootEvidence := evidenceSamples(tech, root)

					var evidenceExtensions []string
					if catalogCtrl != nil {
						evidenceExtensions = catalogCtrl.Applicability.EvidenceExtensions
					}

					evidenceMatches := len(evidenceExtensions) == 0
					if !evidenceMatches {
						for _, rev := range rootEvidence {
							for _, ee := range evidenceExtensions {
								if evidenceTokenMatches(rev, ee) {
									evidenceMatches = true
									break
								}
							}
							if evidenceMatches {
								break
							}
						}
					}

					if !evidenceMatches && catalogCtrl != nil {
						for _, marker := range evidenceExtensions {
							if !strings.HasPrefix(marker, ".") {
								markerPath := filepath.Join(absRoot, marker)
								if fi, err := os.Stat(markerPath); err == nil && !fi.IsDir() {
									evidenceMatches = true
									break
								}
							}
						}
					}

					if applicability == "applicable" && !evidenceMatches {
						applicability = "not_applicable"
						reasonCode = "not_applicable"
						reason = "Aucune preuve du catalogue ne correspond a cette racine."
					}

					sideEffect := "read_only"
					controlTimeout := timeout
					var catalogDeps []string
					var perms []string
					var catalogLimits []string
					var platSupport []string
					severity := "medium"
					cost := "low"
					parameters := make(map[string]interface{})

					if candidate != nil && candidate.SideEffectLevel != "" {
						sideEffect = candidate.SideEffectLevel
						if candidate.TimeoutSeconds > 0 && candidate.TimeoutSeconds < controlTimeout {
							controlTimeout = candidate.TimeoutSeconds
						}
						catalogDeps = candidate.Dependencies
						perms = candidate.Permissions
						catalogLimits = candidate.Limitations
						platSupport = candidate.PlatformSupport
						severity = candidate.Severity
						cost = candidate.Cost
						parameters = candidate.Parameters
					} else if catalogCtrl != nil {
						sideEffect = catalogCtrl.SideEffectLevel
						if catalogCtrl.TimeoutSeconds > 0 && catalogCtrl.TimeoutSeconds < controlTimeout {
							controlTimeout = catalogCtrl.TimeoutSeconds
						}
						catalogDeps = catalogCtrl.Dependencies
						perms = catalogCtrl.Permissions
						catalogLimits = catalogCtrl.Limitations
						platSupport = catalogCtrl.PlatformSupport
						severity = catalogCtrl.Severity
						cost = catalogCtrl.Cost
						parameters = catalogCtrl.Parameters
					}

					if applicability == "applicable" && !platformSupported(platSupport, opts.PlatformID) {
						applicability = "not_applicable"
						reasonCode = "platform_unsupported"
						reason = fmt.Sprintf("Controle non qualifie pour la plateforme %s.", opts.PlatformID)
					}

					// Permissions check
					if applicability == "applicable" {
						needsNetwork := (sideEffect == "network" || sideEffect == "network_code_execution")
						needsCode := (sideEffect == "code_execution" || sideEffect == "network_code_execution")
						if (needsNetwork && !opts.AllowNetwork) || (needsCode && !opts.AllowCodeExecution) {
							applicability = "not_applicable"
							reasonCode = "permission_denied"
							reason = fmt.Sprintf("Effet %s non autorise pour cette execution.", sideEffect)
						}
					}

					if listed(opts.DisabledTechnologies, tech.Technology) || (catalogCtrl != nil && listed(opts.DisabledControls, catalogCtrl.ID)) {
						applicability = "user_disabled"
						reasonCode = "user_disabled"
						reason = "Ignoré par un réglage local de l'extension, pas par le dépôt."
					}

					if (command == "eslint" || command == "tsc") && applicability != "technology_absent" && applicability != "ambiguous" && applicability != "platform_unsupported" && applicability != "permission_denied" && applicability != "user_disabled" {
						localBin := nodeToolBin(cleanRepo, command)
						switch {
						case localBin == "":
							applicability = "tool_unavailable"
							reasonCode = "tool_unavailable"
							reason = fmt.Sprintf("Outil du dépôt introuvable : node_modules/.bin/%s. Installez les dépendances (npm install) dans la cible, ou la chaîne locale avec compliance runtime node.", command)
						case command == "eslint" && !eslintConfigured(cleanRepo):
							applicability = "repository_unconfigured"
							reasonCode = "repository_unconfigured"
							reason = "Configuration ESLint absente du dépôt. Ajoutez eslint.config.js ou .eslintrc, puis relancez."
						case command == "tsc" && len(tsconfigProjects(cleanRepo)) == 0:
							applicability = "repository_unconfigured"
							reasonCode = "repository_unconfigured"
							reason = "Aucun tsconfig.json dans le dépôt. La vérification de types ne peut pas s'exécuter."
						default:
							if candidate == nil {
								copy := matrix.CandidateToolState{Name: command, Command: command}
								candidate = &copy
							}
							candidate.Status = "available"
							candidate.Source = &localBin
							candidate.RuntimeManaged = false
							if applicability != "applicable" {
								applicability = "applicable"
								reasonCode = "applicable"
								reason = ""
							}
						}
					}

					if applicability == "tool_unavailable" && candidate != nil && candidate.Status == "incompatible" {
						applicability = "platform_unsupported"
						reasonCode = "platform_unsupported"
						if command == "ansible-lint" {
							reason = "ansible-lint est réservé à Linux et macOS. Sur Windows, yamllint couvre les playbooks Ansible."
						} else if candidate.Reason != "" {
							reason = candidate.Reason
						} else {
							reason = fmt.Sprintf("Outil non pris en charge sur cette plateforme : %s.", command)
						}
					} else if applicability == "tool_unavailable" && command != "eslint" && command != "tsc" && command != "none" {
						if candidate != nil && candidate.Status == "runtime_error" && candidate.Reason != "" {
							reason = candidate.Reason
							reasonCode = "tool_unavailable"
						} else if manifestPath, err := embedded.ResolveAsset("runtime-manifest.json", ".config/runtime-manifest.json"); err == nil && distribution.ToolListed(manifestPath, opts.PlatformID, command) {
							reason = fmt.Sprintf("Outil installable depuis le manifeste : %s.", command)
							reasonCode = "tool_unavailable"
						} else if command == "Invoke-ScriptAnalyzer" {
							reason = "Module PowerShell PSScriptAnalyzer absent. Installez-le pour l'utilisateur courant, puis relancez."
							reasonCode = "tool_unavailable"
						} else {
							applicability = "platform_unavailable"
							reasonCode = "platform_unavailable"
							reason = fmt.Sprintf("Outil non disponible sur cette plateforme : %s.", command)
						}
					}

					controlID := fmt.Sprintf("%s/%s/%s/%s", tech.Technology, capability.Name, command, root)
					if controlIDs[controlID] {
						return nil, nil, fmt.Errorf("identifiant de controle duplique: %s", controlID)
					}
					controlIDs[controlID] = true

					var catalogID *string
					if catalogCtrl != nil {
						id := catalogCtrl.ID
						catalogID = &id
					} else if candidate != nil && candidate.CatalogID != "" {
						id := candidate.CatalogID
						catalogID = &id
					}

					required := capability.Required && !(hasAlternative && len(selected) == 0)
					if tech.Technology == "powershell" && applicability == "capability_unavailable" {
						required = false
					}

					ctrl := &PlannedControl{
						ID:                  controlID,
						Name:                fmt.Sprintf("%s: %s (%s)", tech.Technology, capability.Name, command),
						Technology:          tech.Technology,
						Capability:          capability.Name,
						Tool:                candidate,
						ControlCatalogID:    catalogID,
						Root:                root,
						Applicability:       applicability,
						ReasonCode:          reasonCode,
						ExecutionOrder:      len(controls) + 1,
						Timeout:             controlTimeout,
						MaxOutputBytes:      maxOutput,
						Dependencies:        make([]string, 0),
						CatalogDependencies: catalogDeps,
						SideEffectLevel:     sideEffect,
						Severity:            severity,
						Cost:                cost,
						Permissions:         perms,
						PlatformSupport:     platSupport,
						Limitations:         catalogLimits,
						Parameters:          parameters,
						Required:            required,
						Reason:              reason,
						Files:               tech.Evidence,
					}
					controls = append(controls, ctrl)
				}
			}
		}
	}

	controls = collapseRepoWideTools(controls)

	if len(controls) > maxControls {
		return nil, nil, fmt.Errorf("limite du plan depassee: %d controles maximum", maxControls)
	}

	// Resolve catalog dependencies
	controlsByID := make(map[string]*PlannedControl)
	for _, c := range controls {
		controlsByID[c.ID] = c
	}

	for _, c := range controls {
		for _, depCatID := range c.CatalogDependencies {
			var matching []*PlannedControl
			for _, other := range controls {
				if other.Technology == c.Technology && other.Root == c.Root && other.ControlCatalogID != nil && *other.ControlCatalogID == depCatID {
					matching = append(matching, other)
				}
			}
			if len(matching) != 1 {
				return nil, nil, fmt.Errorf("prerequis catalogue absent ou ambigu: %s pour %s", depCatID, c.ID)
			}
			c.Dependencies = append(c.Dependencies, matching[0].ID)
		}
		sort.Strings(c.Dependencies)
	}

	// Apply custom dependencies if any
	for ctrlID, deps := range opts.CustomDependencies {
		c, ok := controlsByID[ctrlID]
		if !ok {
			return nil, nil, fmt.Errorf("dependance configuree sur un controle absent: %s", ctrlID)
		}
		for _, dep := range deps {
			if _, exists := controlsByID[dep]; !exists {
				return nil, nil, fmt.Errorf("prerequis absent du plan: %s", dep)
			}
			if dep == ctrlID {
				return nil, nil, fmt.Errorf("dependance cyclique sur le controle: %s", ctrlID)
			}
		}
		c.Dependencies = deps
		sort.Strings(c.Dependencies)
	}

	// Topological Sort (Kahn)
	indegree := make(map[string]int)
	dependents := make(map[string][]string)
	for _, c := range controls {
		indegree[c.ID] = len(c.Dependencies)
		for _, dep := range c.Dependencies {
			dependents[dep] = append(dependents[dep], c.ID)
		}
	}

	var ready []*PlannedControl
	for _, c := range controls {
		if indegree[c.ID] == 0 {
			ready = append(ready, c)
		}
	}

	var ordered []*PlannedControl
	for len(ready) > 0 {
		// Pick lowest execution order
		sort.Slice(ready, func(i, j int) bool {
			return ready[i].ExecutionOrder < ready[j].ExecutionOrder
		})
		next := ready[0]
		ready = ready[1:]
		ordered = append(ordered, next)

		for _, depID := range dependents[next.ID] {
			indegree[depID]--
			if indegree[depID] == 0 {
				ready = append(ready, controlsByID[depID])
			}
		}
	}

	if len(ordered) != len(controls) {
		return nil, nil, errors.New("le plan contient un cycle de dependances")
	}

	for i := range ordered {
		ordered[i].ExecutionOrder = i + 1
	}

	// Build generic plan interface for report
	planControls := make([]interface{}, len(ordered))
	for i, c := range ordered {
		planControls[i] = c
	}

	execPlan := &report.ExecutionPlan{
		SchemaVersion: 1,
		Repository:    cleanRepo,
		Budgets: report.Budgets{
			TimeoutSeconds:          globalTimeout,
			MaxOutputBytesPerStream: maxOutput,
			MaxControls:             maxControls,
		},
		Permissions: report.Permissions{
			Network:       opts.AllowNetwork,
			CodeExecution: opts.AllowCodeExecution,
		},
		Controls: planControls,
	}

	return execPlan, ordered, nil
}

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
	AllowedEnvironments         []string `json:"allowed_environments,omitempty"`
	ForbiddenEnvironments       []string `json:"forbidden_environments,omitempty"`
	RequirePlanPreview          bool     `json:"require_plan_preview,omitempty"`
	RequireExplicitConfirmation bool     `json:"require_explicit_confirmation,omitempty"`
	StateBackendRestrictions    []string `json:"state_backend_restrictions,omitempty"`
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
		return nil
	}

	if ctx.IsRunAll {
		return fmt.Errorf("%w: étape %q", ErrRunAllForbidden, step.ID)
	}

	if p.Guardrails == nil {
		return fmt.Errorf("%w: exécution bloquée : section guardrails absente pour l'étape apply_destroy %q", ErrGuardrailViolation, step.ID)
	}

	envClean := strings.ToLower(strings.TrimSpace(ctx.Environment))
	for _, forbidden := range p.Guardrails.ForbiddenEnvironments {
		forbClean := strings.ToLower(strings.TrimSpace(forbidden))
		if matchForbiddenEnv(forbClean, envClean) {
			return fmt.Errorf("%w: environnement %q interdit par la règle %q pour l'étape %q",
				ErrForbiddenEnvironment, ctx.Environment, forbidden, step.ID)
		}
	}

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

	if p.Guardrails.RequirePlanPreview && !ctx.PlanSucceeded {
		return fmt.Errorf("%w: étape %q requiert la réussite préalable du plan",
			ErrPlanRequired, step.ID)
	}

	if p.Guardrails.RequireExplicitConfirmation && !ctx.UserConfirmed {
		return fmt.Errorf("%w: confirmation requise pour l'étape %q",
			ErrConfirmationRequired, step.ID)
	}

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

func collapseRepoWideTools(controls []*PlannedControl) []*PlannedControl {
	kept := make([]*PlannedControl, 0, len(controls))
	index := make(map[string]int)
	for _, ctrl := range controls {
		command := "none"
		if ctrl.Tool != nil && ctrl.Tool.Command != "" {
			command = ctrl.Tool.Command
		}
		if !repoWideCommand(command) {
			kept = append(kept, ctrl)
			continue
		}
		key := ctrl.Technology + "\x00" + ctrl.Capability + "\x00" + command
		if pos, ok := index[key]; ok {
			current := kept[pos]
			if preferRoot(ctrl.Root, current.Root) {
				ctrl.Files = unionStrings(ctrl.Files, current.Files)
				kept[pos] = ctrl
			} else {
				current.Files = unionStrings(current.Files, ctrl.Files)
			}
			continue
		}
		index[key] = len(kept)
		kept = append(kept, ctrl)
	}
	for i := range kept {
		kept[i].ExecutionOrder = i + 1
	}
	return kept
}

func listed(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), want) {
			return true
		}
	}
	return false
}

func nodeToolBin(repo, command string) string {
	if local := repositoryNodeBin(repo, command); local != "" {
		return local
	}
	return managedNodeBin(command)
}

func repositoryNodeBin(repo, command string) string {
	return nodeExecutable(filepath.Join(repo, "node_modules", ".bin"), command)
}

func managedNodeBin(command string) string {
	root := os.Getenv("COMPLIANCE_NODE_TOOLS")
	if root == "" {
		root = filepath.Join(osutil.DefaultToolCacheDir(), "node")
	}
	return nodeExecutable(filepath.Join(root, "node_modules", ".bin"), command)
}

func nodeExecutable(binDir, command string) string {
	for _, name := range []string{command, command + ".cmd", command + ".exe", command + ".ps1"} {
		candidate := filepath.Join(binDir, name)
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

func eslintConfigured(repo string) bool {
	names := []string{
		"eslint.config.js", "eslint.config.mjs", "eslint.config.cjs", "eslint.config.ts",
		".eslintrc", ".eslintrc.js", ".eslintrc.cjs", ".eslintrc.yaml", ".eslintrc.yml", ".eslintrc.json",
	}
	for _, name := range names {
		info, err := os.Stat(filepath.Join(repo, name))
		if err == nil && !info.IsDir() {
			return true
		}
	}
	body, err := os.ReadFile(filepath.Join(repo, "package.json"))
	if err != nil {
		return false
	}
	var pkg map[string]interface{}
	if json.Unmarshal(body, &pkg) != nil {
		return false
	}
	_, ok := pkg["eslintConfig"]
	return ok
}

func repoWideCommand(command string) bool {
	switch command {
	case "", "none", "eslint", "tsc", "gitleaks":
		return true
	default:
		return false
	}
}

func preferRoot(candidate, current string) bool {
	if candidate == "." && current != "." {
		return true
	}
	if current == "." {
		return false
	}
	return len(candidate) < len(current)
}

func unionStrings(left, right []string) []string {
	seen := make(map[string]bool, len(left)+len(right))
	out := make([]string, 0, len(left)+len(right))
	for _, value := range append(append([]string{}, left...), right...) {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func platformSupported(support []string, platformID string) bool {
	if len(support) == 0 || platformID == "" {
		return true
	}
	for _, id := range support {
		if id == platformID {
			return true
		}
	}
	return false
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
