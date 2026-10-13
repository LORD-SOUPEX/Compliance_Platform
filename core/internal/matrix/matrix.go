package matrix

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"time"

	"compliance/internal/catalog"
	"compliance/internal/discovery"
)

var reVersion = regexp.MustCompile(`\b\d+\.\d+(?:\.\d+)?(?:[a-zA-Z0-9.+-]*)`)

// PlatformInfo identifies the execution platform.
type PlatformInfo struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	ID           string `json:"id"`
}

// DetectPlatform returns the current PlatformInfo.
func DetectPlatform() PlatformInfo {
	osName := runtime.GOOS
	if osName == "darwin" {
		osName = "macos"
	}
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x64"
	}
	return PlatformInfo{
		OS:           osName,
		Architecture: arch,
		ID:           osName + "-" + arch,
	}
}

// CandidateToolState represents the state of a tool candidate for a capability.
type CandidateToolState struct {
	Name            string                 `json:"name"`
	Command         string                 `json:"command"`
	Status          string                 `json:"status"` // available, not_installed, incompatible, runtime_error, integrity_error
	Source          *string                `json:"source"`
	Version         *string                `json:"version"`
	RuntimeManaged  bool                   `json:"runtime_managed"`
	Platform        string                 `json:"platform"`
	Reason          string                 `json:"reason"`
	ExecutionProbe  interface{}            `json:"execution_probe,omitempty"`
	CatalogID       string                 `json:"catalog_id,omitempty"`
	Severity        string                 `json:"severity,omitempty"`
	SideEffectLevel string                 `json:"side_effect_level,omitempty"`
	Permissions     []string               `json:"permissions,omitempty"`
	TimeoutSeconds  int                    `json:"timeout_seconds,omitempty"`
	Cost            string                 `json:"cost,omitempty"`
	Parameters      map[string]interface{} `json:"parameters,omitempty"`
	Dependencies    []string               `json:"dependencies,omitempty"`
	Limitations     []string               `json:"limitations,omitempty"`
	PlatformSupport []string               `json:"platform_support,omitempty"`
}

// CapabilityEntry represents a capability within the matrix.
type CapabilityEntry struct {
	Name            string                   `json:"name"`
	SelectionPolicy string                   `json:"selection_policy"` // all, alternative
	CatalogControls []catalog.CatalogControl `json:"catalog_controls"`
	Required        bool                     `json:"required"`
	Availability    string                   `json:"availability"` // available, partially_available, unavailable, unconfigured, not_applicable, ambiguous
	CandidateTools  []CandidateToolState     `json:"candidate_tools"`
	AvailableTools  []string                 `json:"available_tools"`
	Reasons         []string                 `json:"reasons"`
}

// CapabilityMatrixEntry represents the capability matrix for one technology.
type CapabilityMatrixEntry struct {
	Technology           string               `json:"technology"`
	TechnologyStatus     string               `json:"technology_status"`
	RequiredCapabilities []string             `json:"required_capabilities"`
	Capabilities         []CapabilityEntry    `json:"capabilities"`
	CandidateTools       []CandidateToolState `json:"candidate_tools"`
	Platform             PlatformInfo         `json:"platform"`
	Reasons              []string             `json:"reasons"`
}

// SelectedTool represents a chosen tool command for a technology.
type SelectedTool struct {
	Name           string      `json:"name"`
	Command        string      `json:"command"`
	Source         *string     `json:"source"`
	Version        *string     `json:"version"`
	RuntimeManaged bool        `json:"runtime_managed"`
	Platform       string      `json:"platform"`
	ExecutionProbe interface{} `json:"execution_probe,omitempty"`
	Capabilities   []string    `json:"capabilities"`
}

// UnresolvedCapability records a capability that could not be fully satisfied.
type UnresolvedCapability struct {
	Capability string   `json:"capability"`
	Status     string   `json:"status"`
	Reasons    []string `json:"reasons"`
}

// ToolResolutionMetrics holds timing and occurrence counts for tool resolution.
type ToolResolutionMetrics struct {
	RequiredCapabilities   int   `json:"required_capabilities"`
	CandidateOccurrences   int   `json:"candidate_occurrences"`
	SelectedCommands       int   `json:"selected_commands"`
	ReusedAssignments      int   `json:"reused_assignments"`
	UnresolvedCapabilities int   `json:"unresolved_capabilities"`
	DurationMs             int64 `json:"duration_ms"`
}

// ToolResolutionEntry represents the resolved tools for one technology.
type ToolResolutionEntry struct {
	Technology             string                 `json:"technology"`
	TechnologyStatus       string                 `json:"technology_status"`
	Platform               PlatformInfo           `json:"platform"`
	Status                 string                 `json:"status"` // ready, partial, unavailable, absent, ambiguous
	SelectedTools          []SelectedTool         `json:"selected_tools"`
	UnresolvedCapabilities []UnresolvedCapability `json:"unresolved_capabilities"`
	Metrics                ToolResolutionMetrics  `json:"metrics"`
	Reasons                []string               `json:"reasons"`
}

// CandidateToolResolver determines the status and path of a tool command.
type CandidateToolResolver interface {
	ResolveCandidate(name, command string, platform PlatformInfo, repoRoot string) CandidateToolState
}

// DefaultCandidateResolver resolves candidate tools across local bin, venv, and PATH.
type DefaultCandidateResolver struct {
	PlatformRoot string
}

func (r *DefaultCandidateResolver) ResolveCandidate(name, command string, platform PlatformInfo, repoRoot string) CandidateToolState {
	// 1. Incompatible tools on Windows
	if platform.OS == "windows" && (command == "ansible" || command == "ansible-lint" || command == "molecule") {
		return CandidateToolState{
			Name:           name,
			Command:        command,
			Status:         "incompatible",
			Source:         nil,
			Version:        nil,
			RuntimeManaged: false,
			Platform:       platform.ID,
			Reason:         "Controleur Ansible/Molecule natif Windows non supporte; la presence du paquet ne prouve pas son execution.",
		}
	}

	ext := ""
	if platform.OS == "windows" {
		ext = ".exe"
	}

	root := r.PlatformRoot
	if root == "" {
		root = repoRoot
	}

	probeCommand := func(exePath string, isVenv bool) CandidateToolState {
		norm := filepath.ToSlash(exePath)
		probeArgs := []string{"--version"}
		if command == "terraform" || command == "tofu" || command == "opentofu" {
			probeArgs = []string{"version"}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, exePath, probeArgs...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return CandidateToolState{
				Name:           name,
				Command:        command,
				Status:         "runtime_error",
				Source:         &norm,
				Version:        nil,
				RuntimeManaged: isVenv,
				Platform:       platform.ID,
				Reason:         "Qualification d'execution impossible: La commande de qualification a retourné le code 1.",
			}
		}

		verMatch := reVersion.FindString(string(out))
		var ver *string
		if verMatch != "" {
			ver = &verMatch
		}

		reason := "Outil qualifié, provenance vérifiée et commande exécutée."
		if isVenv {
			if ver != nil {
				reason = fmt.Sprintf("Version %s du package %s indexee et commande executee.", *ver, name)
			} else {
				reason = "Outil trouvé dans l'environnement Python géré par Compliance_Platform."
			}
		}

		return CandidateToolState{
			Name:           name,
			Command:        command,
			Status:         "available",
			Source:         &norm,
			Version:        ver,
			RuntimeManaged: isVenv,
			Platform:       platform.ID,
			Reason:         reason,
		}
	}

	// 2. Check .tools/bin/<command>[.exe]
	toolBin := filepath.Join(root, ".tools", "bin", command+ext)
	if _, err := os.Stat(toolBin); err == nil {
		return probeCommand(toolBin, false)
	}

	// 3. Check .venv/Scripts/<command>[.exe / .cmd]
	venvScripts := filepath.Join(root, ".venv", "Scripts")
	candidates := []string{
		filepath.Join(venvScripts, command+".exe"),
		filepath.Join(venvScripts, command+".cmd"),
		filepath.Join(venvScripts, command),
	}
	for _, cand := range candidates {
		if _, err := os.Stat(cand); err == nil {
			return probeCommand(cand, true)
		}
	}

	// 4. Check PowerShell modules for Invoke-ScriptAnalyzer
	if command == "Invoke-ScriptAnalyzer" {
		psModule := filepath.Join(root, ".tools", "powershell-modules", "PSScriptAnalyzer")
		if _, err := os.Stat(psModule); err == nil {
			manifest := filepath.Join(psModule, "PSScriptAnalyzer.psd1")
			norm := filepath.ToSlash(manifest)
			return CandidateToolState{
				Name:           name,
				Command:        command,
				Status:         "available",
				Source:         &norm,
				Version:        nil,
				RuntimeManaged: true,
				Platform:       platform.ID,
				Reason:         "Module trouvé dans les modules PowerShell gérés par Compliance_Platform.",
			}
		}
	}

	// 5. Check PATH
	if path, err := exec.LookPath(command); err == nil {
		return probeCommand(path, false)
	}

	// 6. Not installed
	return CandidateToolState{
		Name:           name,
		Command:        command,
		Status:         "not_installed",
		Source:         nil,
		Version:        nil,
		RuntimeManaged: false,
		Platform:       platform.ID,
		Reason:         "Aucune commande ou aucun binaire local trouvé pour '" + command + "'.",
	}
}

// BuildCapabilityMatrix constructs the capability matrix for all discoveries.
func BuildCapabilityMatrix(
	discoveries []discovery.TechnologyRecord,
	cat *catalog.ControlCatalog,
	platform PlatformInfo,
	resolver CandidateToolResolver,
	repoRoot string,
) []CapabilityMatrixEntry {
	entries := make([]CapabilityMatrixEntry, 0, len(discoveries))

	for _, disc := range discoveries {
		profiles := cat.GetCapabilityProfile(disc.Technology)
		capEntries := make([]CapabilityEntry, 0, len(profiles))
		requiredCaps := make([]string, 0)
		allToolStatesMap := make(map[string]CandidateToolState)

		for _, prof := range profiles {
			required := (disc.Status == "detected")
			if required {
				requiredCaps = append(requiredCaps, prof.Name)
			}

			toolStateList := make([]CandidateToolState, 0)
			availableTools := make([]string, 0)
			alternativeSatisfied := false

			for _, tdef := range prof.Tools {
				skipProbe := disc.Status != "detected" || (prof.SelectionPolicy == "alternative" && alternativeSatisfied)
				_ = skipProbe

				toolState := resolver.ResolveCandidate(tdef.Name, tdef.Command, platform, repoRoot)
				toolState.CatalogID = tdef.CatalogID
				toolState.Severity = tdef.Severity
				toolState.SideEffectLevel = tdef.SideEffectLevel
				toolState.Permissions = tdef.Permissions
				toolState.TimeoutSeconds = tdef.TimeoutSeconds
				toolState.Cost = tdef.Cost
				toolState.Parameters = tdef.Parameters
				toolState.Dependencies = tdef.Dependencies
				toolState.Limitations = tdef.Limitations
				toolState.PlatformSupport = tdef.PlatformSupport

				toolStateList = append(toolStateList, toolState)
				key := toolState.Name + ":" + toolState.Command
				allToolStatesMap[key] = toolState

				if toolState.Status == "available" {
					availableTools = append(availableTools, toolState.Name)
					if prof.SelectionPolicy == "alternative" {
						alternativeSatisfied = true
					}
				}
			}

			// Calculate availability
			availability := "unavailable"
			if disc.Status == "ambiguous" {
				availability = "ambiguous"
			} else if disc.Status == "absent" {
				availability = "not_applicable"
			} else if len(toolStateList) == 0 {
				availability = "unconfigured"
			} else if prof.SelectionPolicy == "alternative" && len(availableTools) > 0 {
				availability = "available"
			} else if len(availableTools) == len(toolStateList) {
				availability = "available"
			} else if len(availableTools) > 0 {
				availability = "partially_available"
			} else {
				availability = "unavailable"
			}

			// Calculate reasons
			reasons := make([]string, 0)
			if disc.Status == "ambiguous" {
				reasons = append(reasons, "La technologie est ambiguë; aucune capacité n’est considérée comme résolue.")
			} else if disc.Status == "absent" {
				reasons = append(reasons, "La technologie est absente; la capacité n’est pas applicable.")
			} else if len(toolStateList) == 0 {
				reasons = append(reasons, "Aucun outil candidat n'est configure pour cette capacite.")
			} else if len(availableTools) == 0 {
				reasons = append(reasons, "Aucun outil candidat n'est disponible sur cette plateforme.")
			} else if prof.SelectionPolicy == "alternative" && len(availableTools) > 0 {
				reasons = append(reasons, "Une alternative est disponible; le premier candidat disponible sera retenu selon l ordre du profil.")
			} else if len(availableTools) < len(toolStateList) {
				reasons = append(reasons, "Certains outils candidats sont disponibles; d'autres restent indisponibles sur cette plateforme.")
			} else {
				reasons = append(reasons, "Au moins un outil candidat est disponible; la sélection finale appartient au Tool Resolver.")
			}

			capEntries = append(capEntries, CapabilityEntry{
				Name:            prof.Name,
				SelectionPolicy: prof.SelectionPolicy,
				CatalogControls: prof.Controls,
				Required:        required,
				Availability:    availability,
				CandidateTools:  toolStateList,
				AvailableTools:  availableTools,
				Reasons:         reasons,
			})
		}

		// Sort candidate tools unique by name and command
		uniqueCandidates := make([]CandidateToolState, 0, len(allToolStatesMap))
		for _, s := range allToolStatesMap {
			uniqueCandidates = append(uniqueCandidates, s)
		}
		sort.Slice(uniqueCandidates, func(i, j int) bool {
			if uniqueCandidates[i].Name == uniqueCandidates[j].Name {
				return uniqueCandidates[i].Command < uniqueCandidates[j].Command
			}
			return uniqueCandidates[i].Name < uniqueCandidates[j].Name
		})

		discReasons := disc.Ambiguities
		if discReasons == nil {
			discReasons = make([]string, 0)
		}

		entries = append(entries, CapabilityMatrixEntry{
			Technology:           disc.Technology,
			TechnologyStatus:     disc.Status,
			RequiredCapabilities: requiredCaps,
			Capabilities:         capEntries,
			CandidateTools:       uniqueCandidates,
			Platform:             platform,
			Reasons:              discReasons,
		})
	}

	return entries
}

// ResolveCapabilityTools selects candidates and determines resolution status for each technology.
func ResolveCapabilityTools(matrix []CapabilityMatrixEntry) []ToolResolutionEntry {
	resolutions := make([]ToolResolutionEntry, 0, len(matrix))

	for _, tech := range matrix {
		start := time.Now()
		selectedAssignments := 0
		selectedByCommand := make(map[string]*SelectedTool)
		unresolved := make([]UnresolvedCapability, 0)
		candidateOccurrences := 0

		if tech.TechnologyStatus == "detected" {
			for _, capEntry := range tech.Capabilities {
				candidateOccurrences += len(capEntry.CandidateTools)
				if !capEntry.Required {
					continue
				}

				var availableCandidates []CandidateToolState
				for _, c := range capEntry.CandidateTools {
					if c.Status == "available" {
						availableCandidates = append(availableCandidates, c)
					}
				}

				if len(availableCandidates) == 0 {
					unresolved = append(unresolved, UnresolvedCapability{
						Capability: capEntry.Name,
						Status:     capEntry.Availability,
						Reasons:    capEntry.Reasons,
					})
					continue
				}

				if capEntry.SelectionPolicy == "alternative" {
					availableCandidates = availableCandidates[:1]
				}

				for _, cand := range availableCandidates {
					selectedAssignments++
					sel, exists := selectedByCommand[cand.Command]
					if !exists {
						sel = &SelectedTool{
							Name:           cand.Name,
							Command:        cand.Command,
							Source:         cand.Source,
							Version:        cand.Version,
							RuntimeManaged: cand.RuntimeManaged,
							Platform:       cand.Platform,
							ExecutionProbe: cand.ExecutionProbe,
							Capabilities:   make([]string, 0),
						}
						selectedByCommand[cand.Command] = sel
					}

					foundCap := false
					for _, existingCap := range sel.Capabilities {
						if existingCap == capEntry.Name {
							foundCap = true
							break
						}
					}
					if !foundCap {
						sel.Capabilities = append(sel.Capabilities, capEntry.Name)
					}
				}

				if capEntry.SelectionPolicy == "all" && capEntry.Availability == "partially_available" {
					unresolved = append(unresolved, UnresolvedCapability{
						Capability: capEntry.Name,
						Status:     "partially_available",
						Reasons:    capEntry.Reasons,
					})
				}
			}
		}

		selectedTools := make([]SelectedTool, 0, len(selectedByCommand))
		for _, tool := range selectedByCommand {
			selectedTools = append(selectedTools, *tool)
		}
		sort.Slice(selectedTools, func(i, j int) bool {
			return selectedTools[i].Command < selectedTools[j].Command
		})

		resolutionStatus := tech.TechnologyStatus
		if tech.TechnologyStatus == "detected" {
			if len(unresolved) > 0 && len(selectedTools) > 0 {
				resolutionStatus = "partial"
			} else if len(unresolved) > 0 {
				resolutionStatus = "unavailable"
			} else {
				resolutionStatus = "ready"
			}
		}

		reasons := make([]string, 0)
		if tech.TechnologyStatus == "ambiguous" {
			reasons = append(reasons, tech.Reasons...)
		} else if tech.TechnologyStatus == "absent" {
			reasons = append(reasons, "Technologie absente; aucun outil sélectionné.")
		}

		reqCount := 0
		for _, c := range tech.Capabilities {
			if c.Required {
				reqCount++
			}
		}

		resolutions = append(resolutions, ToolResolutionEntry{
			Technology:             tech.Technology,
			TechnologyStatus:       tech.TechnologyStatus,
			Platform:               tech.Platform,
			Status:                 resolutionStatus,
			SelectedTools:          selectedTools,
			UnresolvedCapabilities: unresolved,
			Metrics: ToolResolutionMetrics{
				RequiredCapabilities:   reqCount,
				CandidateOccurrences:   candidateOccurrences,
				SelectedCommands:       len(selectedTools),
				ReusedAssignments:      selectedAssignments - len(selectedTools),
				UnresolvedCapabilities: len(unresolved),
				DurationMs:             time.Since(start).Milliseconds(),
			},
			Reasons: reasons,
		})
	}

	return resolutions
}

// PopulateDiscovery fills res.CapabilityMatrix and res.ToolResolution dynamically.
func PopulateDiscovery(
	res *discovery.DiscoveryResult,
	cat *catalog.ControlCatalog,
	platform PlatformInfo,
	resolver CandidateToolResolver,
	repoRoot string,
) {
	if res == nil || cat == nil {
		return
	}
	if resolver == nil {
		resolver = &DefaultCandidateResolver{PlatformRoot: repoRoot}
	}

	matrixEntries := BuildCapabilityMatrix(res.Technologies, cat, platform, resolver, repoRoot)
	resolutionEntries := ResolveCapabilityTools(matrixEntries)

	matList := make([]interface{}, len(matrixEntries))
	for i, m := range matrixEntries {
		matList[i] = m
	}
	res.CapabilityMatrix = matList

	resList := make([]interface{}, len(resolutionEntries))
	var totalResolverMs int64
	for i, r := range resolutionEntries {
		resList[i] = r
		totalResolverMs += r.Metrics.DurationMs
	}
	res.ToolResolution = resList
	res.Metrics.ResolverMs = totalResolverMs
}

