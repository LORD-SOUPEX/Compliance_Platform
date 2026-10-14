package matrix

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"compliance/internal/discovery"
	"compliance/internal/osutil"
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
	Name            string               `json:"name"`
	SelectionPolicy string               `json:"selection_policy"` // all, alternative
	CatalogControls []CatalogControl     `json:"catalog_controls"`
	Required        bool                 `json:"required"`
	Availability    string               `json:"availability"` // available, partially_available, unavailable, unconfigured, not_applicable, ambiguous
	CandidateTools  []CandidateToolState `json:"candidate_tools"`
	AvailableTools  []string             `json:"available_tools"`
	Reasons         []string             `json:"reasons"`
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
	cache        sync.Map
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
		cacheKey := norm + ":" + command
		if val, ok := r.cache.Load(cacheKey); ok {
			st := val.(CandidateToolState)
			st.Name = name
			st.Command = command
			return st
		}

		probeArgs := []string{"--version"}
		if command == "terraform" || command == "tofu" || command == "opentofu" {
			probeArgs = []string{"version"}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		exe, args := osutil.ScriptCommand(exePath, probeArgs)
		var cmd *exec.Cmd
		if strings.EqualFold(filepath.Ext(exe), ".cmd") || strings.EqualFold(filepath.Ext(exe), ".bat") {
			cmd = exec.CommandContext(ctx, "cmd.exe", append([]string{"/c", exe}, args...)...)
		} else {
			cmd = exec.CommandContext(ctx, exe, args...)
		}
		osutil.SetHideWindow(cmd)
		out, err := cmd.CombinedOutput()
		if err != nil {
			st := CandidateToolState{
				Name:           name,
				Command:        command,
				Status:         "runtime_error",
				Source:         &norm,
				Version:        nil,
				RuntimeManaged: isVenv,
				Platform:       platform.ID,
				Reason:         fmt.Sprintf("Qualification d'execution impossible: %v (sortie: %s)", err, string(out)),
			}
			r.cache.Store(cacheKey, st)
			return st
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

		st := CandidateToolState{
			Name:           name,
			Command:        command,
			Status:         "available",
			Source:         &norm,
			Version:        ver,
			RuntimeManaged: isVenv,
			Platform:       platform.ID,
			Reason:         reason,
		}
		r.cache.Store(cacheKey, st)
		return st
	}

	// 2. Check .tools/bin/<command>[.exe]
	toolBin := filepath.Join(root, ".tools", "bin", command+ext)
	if _, err := os.Stat(toolBin); err == nil {
		return probeCommand(toolBin, false)
	}

	// 3. Check standalone python runtime (.tools/python/Scripts or .tools/python/bin)
	pyScriptsDir := filepath.Join(root, ".tools", "python", "Scripts")
	if platform.OS != "windows" {
		pyScriptsDir = filepath.Join(root, ".tools", "python", "bin")
	}
	pyCandidates := []string{
		filepath.Join(pyScriptsDir, command+".exe"),
		filepath.Join(pyScriptsDir, command+".cmd"),
		filepath.Join(pyScriptsDir, command),
	}
	for _, cand := range pyCandidates {
		if _, err := os.Stat(cand); err == nil {
			return probeCommand(cand, true)
		}
	}

	// 4. Check .tools/runtime/<platform>/<command>/...
	runtimeDir := filepath.Join(root, ".tools", "runtime", platform.ID, command)
	if entries, err := os.ReadDir(runtimeDir); err == nil {
		for _, e := range entries {
			cand := filepath.Join(runtimeDir, e.Name(), command+ext)
			if _, err := os.Stat(cand); err == nil {
				return probeCommand(cand, true)
			}
		}
	}

	// 5. Distribution cache produced by compliance runtime sync.
	cacheRoot := osutil.DefaultToolCacheDir()
	venvDir := filepath.Join(cacheRoot, "venv", "bin")
	if platform.OS == "windows" {
		venvDir = filepath.Join(cacheRoot, "venv", "Scripts")
	}
	for _, cand := range []string{
		filepath.Join(venvDir, command+ext),
		filepath.Join(venvDir, command+".cmd"),
		filepath.Join(venvDir, command+".bat"),
		filepath.Join(venvDir, command),
	} {
		if info, err := os.Stat(cand); err == nil && !info.IsDir() {
			return probeCommand(cand, true)
		}
	}
	cached := filepath.Join(cacheRoot, "bin", platform.ID, command+ext)
	if info, err := os.Stat(cached); err == nil && !info.IsDir() {
		return probeCommand(cached, true)
	}

	// 6. Check PowerShell modules for Invoke-ScriptAnalyzer
	if command == "Invoke-ScriptAnalyzer" {
		psModule := filepath.Join(root, ".tools", "powershell-modules", "PSScriptAnalyzer")
		if _, err := os.Stat(psModule); err == nil {
			manifest := filepath.Join(psModule, "PSScriptAnalyzer.psd1")
			if _, err := os.Stat(manifest); os.IsNotExist(err) {
				// Check versioned subdirectories like 1.25.0
				entries, _ := os.ReadDir(psModule)
				for _, e := range entries {
					if e.IsDir() {
						subManifest := filepath.Join(psModule, e.Name(), "PSScriptAnalyzer.psd1")
						if _, err := os.Stat(subManifest); err == nil {
							manifest = subManifest
							break
						}
					}
				}
			}
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

		// Check system PSModulePath and standard locations for PSScriptAnalyzer
		psModPathEnv := os.Getenv("PSModulePath")
		var candidateDirs []string
		if psModPathEnv != "" {
			candidateDirs = filepath.SplitList(psModPathEnv)
		} else if platform.OS == "windows" {
			candidateDirs = []string{
				filepath.Join(os.Getenv("ProgramFiles"), "WindowsPowerShell", "Modules"),
				filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "Modules"),
			}
			if userProfile := os.Getenv("USERPROFILE"); userProfile != "" {
				candidateDirs = append(candidateDirs,
					filepath.Join(userProfile, "Documents", "WindowsPowerShell", "Modules"),
					filepath.Join(userProfile, "Documents", "PowerShell", "Modules"),
				)
			}
		} else {
			home, _ := os.UserHomeDir()
			candidateDirs = append(candidateDirs, osutil.PowerShellModuleDirs(runtime.GOOS, home)...)
		}

		for _, baseDir := range candidateDirs {
			if baseDir == "" {
				continue
			}
			modDir := filepath.Join(baseDir, "PSScriptAnalyzer")
			if fi, err := os.Stat(modDir); err == nil && fi.IsDir() {
				manifest := filepath.Join(modDir, "PSScriptAnalyzer.psd1")
				if _, err := os.Stat(manifest); os.IsNotExist(err) {
					entries, _ := os.ReadDir(modDir)
					for _, e := range entries {
						if e.IsDir() {
							subManifest := filepath.Join(modDir, e.Name(), "PSScriptAnalyzer.psd1")
							if _, err := os.Stat(subManifest); err == nil {
								manifest = subManifest
								break
							}
						}
					}
				}
				if _, err := os.Stat(manifest); err == nil {
					norm := filepath.ToSlash(manifest)
					return CandidateToolState{
						Name:           name,
						Command:        command,
						Status:         "available",
						Source:         &norm,
						Version:        nil,
						RuntimeManaged: false,
						Platform:       platform.ID,
						Reason:         "Module PSScriptAnalyzer système disponible.",
					}
				}
			}
		}

		return CandidateToolState{
			Name:           name,
			Command:        command,
			Status:         "not_installed",
			Source:         nil,
			Version:        nil,
			RuntimeManaged: false,
			Platform:       platform.ID,
			Reason:         "Module PSScriptAnalyzer introuvable sur le système hôte.",
		}
	}

	// 7. Node package scripts live next to the target, not in the platform cache.
	if repoRoot != "" {
		binDir := filepath.Join(repoRoot, "node_modules", ".bin")
		for _, candidateName := range []string{command, command + ".cmd", command + ".exe", command + ".ps1"} {
			candidate := filepath.Join(binDir, candidateName)
			if info, statErr := os.Stat(candidate); statErr == nil && !info.IsDir() {
				return probeCommand(candidate, false)
			}
		}
	}

	// 8. Darwin tool directories (Homebrew, pip user, pyenv), then PATH.
	if found := osutil.LookupExecutable(command); found != "" {
		return probeCommand(found, false)
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
	cat *ControlCatalog,
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

			for _, tdef := range prof.Tools {
				var toolState CandidateToolState
				if disc.Status != "detected" {
					toolState = CandidateToolState{
						Name:     tdef.Name,
						Command:  tdef.Command,
						Status:   "not_installed",
						Platform: platform.ID,
						Reason:   "Technologie non détectée ; sonde d'outil omise.",
					}
				} else {
					toolState = resolver.ResolveCandidate(tdef.Name, tdef.Command, platform, repoRoot)
				}
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
	cat *ControlCatalog,
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

// ControlApplicability specifies which technology status and evidence extensions match a control.
type ControlApplicability struct {
	TechnologyStatus   []string `json:"technology_status"`
	EvidenceExtensions []string `json:"evidence_extensions"`
}

// CatalogTool defines the tool identity for a control.
type CatalogTool struct {
	Name    string `json:"name"`
	Command string `json:"command"`
}

// CatalogControl represents a single control definition from .config/control-catalog.json.
type CatalogControl struct {
	ID              string                 `json:"id"`
	Name            string                 `json:"name"`
	Objective       string                 `json:"objective"`
	Technology      string                 `json:"technology"`
	Capability      string                 `json:"capability"`
	Tool            *CatalogTool           `json:"tool"`
	Severity        string                 `json:"severity"`         // low, medium, high, critical
	SelectionPolicy string                 `json:"selection_policy"` // all, alternative
	Applicability   ControlApplicability   `json:"applicability"`
	Parameters      map[string]interface{} `json:"parameters"`
	Dependencies    []string               `json:"dependencies"`
	TimeoutSeconds  int                    `json:"timeout_seconds"`
	Cost            string                 `json:"cost"`              // low, medium, high
	SideEffectLevel string                 `json:"side_effect_level"` // read_only, code_execution, network, network_code_execution
	Permissions     []string               `json:"permissions"`
	PlatformSupport []string               `json:"platform_support"`
	Limitations     []string               `json:"limitations"`
}

// ControlCatalog contains all controls and the catalog checksum.
type ControlCatalog struct {
	SchemaVersion int              `json:"schema_version"`
	Controls      []CatalogControl `json:"controls"`
	ContentSHA256 string           `json:"content_sha256,omitempty"`
}

// CandidateToolDefinition provides tool metadata for capability profiles.
type CandidateToolDefinition struct {
	Name            string                 `json:"name"`
	Command         string                 `json:"command"`
	CatalogID       string                 `json:"catalog_id"`
	Severity        string                 `json:"severity"`
	SideEffectLevel string                 `json:"side_effect_level"`
	Permissions     []string               `json:"permissions"`
	TimeoutSeconds  int                    `json:"timeout_seconds"`
	Cost            string                 `json:"cost"`
	Parameters      map[string]interface{} `json:"parameters"`
	Dependencies    []string               `json:"dependencies"`
	Limitations     []string               `json:"limitations"`
	PlatformSupport []string               `json:"platform_support"`
}

// CapabilityProfile groups controls by capability for a technology.
type CapabilityProfile struct {
	Name            string                    `json:"name"`
	SelectionPolicy string                    `json:"selection_policy"`
	Controls        []CatalogControl          `json:"controls"`
	Tools           []CandidateToolDefinition `json:"tools"`
}

// LoadCatalog reads, validates, and hashes .config/control-catalog.json.
func LoadCatalog(path string) (*ControlCatalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("lecture du catalogue de contrôles impossible (%s): %w", path, err)
	}

	// Strip potential UTF-8 BOM
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		data = data[3:]
	}

	h := sha256.Sum256(data)
	contentSHA256 := hex.EncodeToString(h[:])

	var cat ControlCatalog
	if err := json.Unmarshal(data, &cat); err != nil {
		return nil, fmt.Errorf("désérialisation du catalogue de contrôles: %w", err)
	}

	if cat.SchemaVersion != 1 || len(cat.Controls) == 0 {
		return nil, errors.New("schéma Control Catalog invalide (schema_version != 1 ou controls vide)")
	}

	cat.ContentSHA256 = contentSHA256

	// Validate IDs and cycles
	ids := make(map[string]*CatalogControl)
	for i := range cat.Controls {
		c := &cat.Controls[i]
		if c.ID == "" || c.Name == "" || c.Technology == "" || c.Capability == "" {
			return nil, fmt.Errorf("contrôle avec identité incomplète: %+v", c)
		}
		if _, exists := ids[c.ID]; exists {
			return nil, fmt.Errorf("identifiant de contrôle en doublon: %s", c.ID)
		}
		ids[c.ID] = c
	}

	// Check dependencies exist
	for _, c := range cat.Controls {
		for _, dep := range c.Dependencies {
			if _, exists := ids[dep]; !exists {
				return nil, fmt.Errorf("dépendance de contrôle introuvable: %s pour %s", dep, c.ID)
			}
		}
	}

	// Check for dependency cycles
	for _, c := range cat.Controls {
		visited := make(map[string]bool)
		var checkCycle func(curr string) error
		checkCycle = func(curr string) error {
			if visited[curr] {
				return fmt.Errorf("cycle détecté dans les dépendances du catalogue: %s", curr)
			}
			visited[curr] = true
			if ctrl, ok := ids[curr]; ok {
				for _, dep := range ctrl.Dependencies {
					if err := checkCycle(dep); err != nil {
						return err
					}
				}
			}
			delete(visited, curr)
			return nil
		}
		if err := checkCycle(c.ID); err != nil {
			return nil, err
		}
	}

	return &cat, nil
}

// GetCapabilityProfile groups controls by capability for a given technology.
func (c *ControlCatalog) GetCapabilityProfile(technology string) []CapabilityProfile {
	var techControls []CatalogControl
	for _, ctrl := range c.Controls {
		if ctrl.Technology == technology {
			techControls = append(techControls, ctrl)
		}
	}

	// Group by capability
	groups := make(map[string][]CatalogControl)
	for _, ctrl := range techControls {
		groups[ctrl.Capability] = append(groups[ctrl.Capability], ctrl)
	}

	// Sort capability names
	var capNames []string
	for name := range groups {
		capNames = append(capNames, name)
	}
	sort.Strings(capNames)

	var profiles []CapabilityProfile
	for _, name := range capNames {
		ctrls := groups[name]
		// Sort controls by ID
		sort.Slice(ctrls, func(i, j int) bool {
			return ctrls[i].ID < ctrls[j].ID
		})

		policy := "all"
		if len(ctrls) > 0 && ctrls[0].SelectionPolicy != "" {
			policy = ctrls[0].SelectionPolicy
		}

		var tools []CandidateToolDefinition
		for _, ctrl := range ctrls {
			if ctrl.Tool != nil {
				tools = append(tools, CandidateToolDefinition{
					Name:            ctrl.Tool.Name,
					Command:         ctrl.Tool.Command,
					CatalogID:       ctrl.ID,
					Severity:        ctrl.Severity,
					SideEffectLevel: ctrl.SideEffectLevel,
					Permissions:     ctrl.Permissions,
					TimeoutSeconds:  ctrl.TimeoutSeconds,
					Cost:            ctrl.Cost,
					Parameters:      ctrl.Parameters,
					Dependencies:    ctrl.Dependencies,
					Limitations:     ctrl.Limitations,
					PlatformSupport: ctrl.PlatformSupport,
				})
			}
		}

		profiles = append(profiles, CapabilityProfile{
			Name:            name,
			SelectionPolicy: policy,
			Controls:        ctrls,
			Tools:           tools,
		})
	}

	return profiles
}
