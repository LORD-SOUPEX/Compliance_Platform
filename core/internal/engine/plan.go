package engine

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"compliance/internal/catalog"
	"compliance/internal/discovery"
	"compliance/internal/matrix"
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
}

// BuildCompliancePlan creates an ExecutionPlan following the exact PowerShell contract.
func BuildCompliancePlan(
	discoveries []discovery.TechnologyRecord,
	mat []matrix.CapabilityMatrixEntry,
	res []matrix.ToolResolutionEntry,
	repoRoot string,
	opts PlanOptions,
) (*report.ExecutionPlan, []*PlannedControl, error) {
	absRepo, err := filepath.Abs(repoRoot)
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
					if applicability == "not_applicable" {
						reason = "Capacite non requise ou candidat non retenu par le resolver."
					}
					if applicability == "ambiguous" {
						reason = strings.Join(tech.Ambiguities, "; ")
					}
					if applicability == "capability_unavailable" {
						reason = strings.Join(capability.Reasons, "; ")
					}

					reasonCode := applicability
					if hasAlternative && len(selected) == 0 && applicability == "not_applicable" {
						reasonCode = "alternative_not_selected"
					}

					command := "none"
					if candidate != nil {
						command = candidate.Command
					}

					var catalogCtrl *catalog.CatalogControl
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

					// Evidence checking
					evidence := tech.Evidence
					var rootEvidence []string
					if root == "." {
						rootEvidence = evidence
					} else {
						rootPrefix := strings.TrimSuffix(filepath.ToSlash(root), "/") + "/"
						for _, ev := range evidence {
							if strings.HasPrefix(strings.ToLower(ev), strings.ToLower(rootPrefix)) {
								rootEvidence = append(rootEvidence, ev)
							}
						}
					}

					var evidenceExtensions []string
					if catalogCtrl != nil {
						evidenceExtensions = catalogCtrl.Applicability.EvidenceExtensions
					}

					evidenceMatches := len(evidenceExtensions) == 0
					if !evidenceMatches {
						for _, rev := range rootEvidence {
							name := filepath.Base(rev)
							ext := filepath.Ext(rev)
							for _, ee := range evidenceExtensions {
								if strings.EqualFold(ee, name) || strings.EqualFold(ee, ext) {
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
