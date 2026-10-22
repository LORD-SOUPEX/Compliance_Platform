package matrix

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"compliance/internal/discovery"
	"compliance/internal/distribution"
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
	CacheRoot    string
	cache        sync.Map
}

// negativeProbeTTL bounds how long a failed probe is trusted. A first probe that
// failed while an antivirus scanned a fresh binary is retried a minute later
// instead of staying wrong for the daemon's whole lifetime.
const negativeProbeTTL = 60 * time.Second

type cachedProbe struct {
	state      CandidateToolState
	size       int64
	modTime    time.Time
	generation string
	storedAt   time.Time
}

// cached returns a probe result only while the executable is the same file
// (size, mtime), no installation happened since (tools generation), and, for a
// failure, the result is younger than negativeProbeTTL.
func (r *DefaultCandidateResolver) cached(key, exe string) (CandidateToolState, bool) {
	value, ok := r.cache.Load(key)
	if !ok {
		return CandidateToolState{}, false
	}
	entry := value.(cachedProbe)
	info, err := os.Stat(exe)
	stale := err != nil || info.Size() != entry.size || !info.ModTime().Equal(entry.modTime) ||
		distribution.ToolsGeneration(r.cacheDir()) != entry.generation ||
		(entry.state.Status != "available" && time.Since(entry.storedAt) > negativeProbeTTL)
	if stale {
		r.cache.Delete(key)
		return CandidateToolState{}, false
	}
	return entry.state, true
}

func (r *DefaultCandidateResolver) remember(key, exe string, st CandidateToolState) {
	entry := cachedProbe{state: st, generation: distribution.ToolsGeneration(r.cacheDir()), storedAt: time.Now()}
	if info, err := os.Stat(exe); err == nil {
		entry.size, entry.modTime = info.Size(), info.ModTime()
	}
	r.cache.Store(key, entry)
}

// Invalidate forgets every probe result.
func (r *DefaultCandidateResolver) Invalidate() int {
	count := 0
	r.cache.Range(func(key, _ interface{}) bool {
		r.cache.Delete(key)
		count++
		return true
	})
	return count
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
		if st, ok := r.cached(cacheKey, exePath); ok {
			st.Name = name
			st.Command = command
			slog.Debug("tool_probe", "command", command, "path", norm, "cache", "hit", "status", st.Status)
			return st
		}

		probeArgs := distribution.VersionArgs(platform.ID, command)
		if len(probeArgs) == 0 {
			probeArgs = []string{"--version"}
			if command == "terraform" || command == "tofu" || command == "opentofu" {
				probeArgs = []string{"version"}
			}
			if command == "kubeconform" {
				probeArgs = []string{"-v"}
			}
		}

		timeout := osutil.ProbeTimeoutFor(command)
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		started := time.Now()
		stdout, stderr, err := osutil.ProbeQuiet(ctx, command, exePath, probeArgs)
		if err != nil {
			if ctx.Err() != nil {
				err = fmt.Errorf("délai de sonde dépassé (%s)", timeout)
			}
			st := CandidateToolState{
				Name:           name,
				Command:        command,
				Status:         "runtime_error",
				Source:         &norm,
				Version:        nil,
				RuntimeManaged: isVenv,
				Platform:       platform.ID,
				Reason:         osutil.FormatProbeFailure(exePath, err, stdout, stderr, time.Since(started)),
			}
			cached := !transientProbeError(ctx, err)
			if cached {
				r.remember(cacheKey, exePath, st)
			}
			slog.Warn("tool_probe", "command", command, "path", norm, "cache", "miss", "status", st.Status,
				"cached", cached, "duration_ms", time.Since(started).Milliseconds(), "reason", st.Reason)
			return st
		}

		verMatch := reVersion.FindString(stdout + " " + stderr)
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
		r.remember(cacheKey, exePath, st)
		slog.Debug("tool_probe", "command", command, "path", norm, "cache", "miss", "status", st.Status,
			"version", st.Version, "duration_ms", time.Since(started).Milliseconds())
		return st
	}

	probePythonTool := func(pyExe string) CandidateToolState {
		norm := filepath.ToSlash(pyExe)
		cacheKey := norm + ":" + command
		if st, ok := r.cached(cacheKey, pyExe); ok {
			st.Name = name
			st.Command = command
			slog.Debug("tool_probe", "command", command, "path", norm, "cache", "hit", "status", st.Status)
			return st
		}

		modName, versionArgs := distribution.PythonProbeSpec(platform.ID, command)
		if modName == "" {
			modName = pythonModuleName(command)
		}
		probeArgs := osutil.PythonModuleArgs(modName, versionArgs)
		if command == "checkov" {
			probeArgs = osutil.CheckovProbeArgs()
		}

		timeout := osutil.ProbeTimeoutFor(command)
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		started := time.Now()
		stdout, stderr, err := osutil.ProbeQuiet(ctx, command, pyExe, probeArgs)
		if err != nil {
			if ctx.Err() != nil {
				err = fmt.Errorf("délai de sonde dépassé (%s)", timeout)
			}
			st := CandidateToolState{
				Name:           name,
				Command:        command,
				Status:         "runtime_error",
				Source:         &norm,
				Version:        nil,
				RuntimeManaged: true,
				Platform:       platform.ID,
				Reason:         osutil.FormatProbeFailure(pyExe, err, stdout, stderr, time.Since(started)),
			}
			cached := !transientProbeError(ctx, err)
			if cached {
				r.remember(cacheKey, pyExe, st)
			}
			slog.Warn("tool_probe", "command", command, "path", norm, "cache", "miss", "status", st.Status,
				"cached", cached, "duration_ms", time.Since(started).Milliseconds(), "reason", st.Reason)
			return st
		}

		verMatch := reVersion.FindString(stdout + " " + stderr)
		var ver *string
		if verMatch != "" {
			ver = &verMatch
		}

		reason := fmt.Sprintf("Module %s qualifié et exécutable dans l'environnement Python autonome.", modName)
		if ver != nil {
			reason = fmt.Sprintf("Version %s du package %s indexée et exécutable dans l'environnement Python autonome.", *ver, name)
		}

		st := CandidateToolState{
			Name:           name,
			Command:        command,
			Status:         "available",
			Source:         &norm,
			Version:        ver,
			RuntimeManaged: true,
			Platform:       platform.ID,
			Reason:         reason,
		}
		r.remember(cacheKey, pyExe, st)
		slog.Debug("tool_probe", "command", command, "path", norm, "cache", "miss", "status", st.Status,
			"version", st.Version, "duration_ms", time.Since(started).Milliseconds())
		return st
	}

	// 2. Strict order for Node tools (eslint, tsc):
	// Priority 1: Target node_modules/.bin
	// Priority 2: Bundle ~/.compliance/tools/node (or .tools/node)
	// Priority 3: System PATH
	if command == "eslint" || command == "tsc" {
		cmdNames := []string{command, command + ".cmd", command + ".exe", command + ".ps1"}
		if repoRoot != "" {
			targetBin := filepath.Join(repoRoot, "node_modules", ".bin")
			for _, cName := range cmdNames {
				cand := filepath.Join(targetBin, cName)
				if info, err := os.Stat(cand); err == nil && !info.IsDir() {
					return probeCommand(cand, false)
				}
			}
		}

		// Bundle candidate directories
		cacheRoot := osutil.DefaultToolCacheDir()
		bundleDirs := []string{
			filepath.Join(root, ".tools", "node", "node_modules", ".bin"),
			filepath.Join(cacheRoot, "node", "node_modules", ".bin"),
		}
		if env := os.Getenv("COMPLIANCE_NODE_TOOLS"); env != "" {
			bundleDirs = append([]string{filepath.Join(env, "node_modules", ".bin")}, bundleDirs...)
		}
		for _, bDir := range bundleDirs {
			for _, cName := range cmdNames {
				cand := filepath.Join(bDir, cName)
				if info, err := os.Stat(cand); err == nil && !info.IsDir() {
					return probeCommand(cand, true)
				}
			}
		}

		if found := osutil.LookupExecutable(command); found != "" {
			return probeCommand(found, false)
		}

		return CandidateToolState{
			Name:           name,
			Command:        command,
			Status:         "not_installed",
			Source:         nil,
			Version:        nil,
			RuntimeManaged: false,
			Platform:       platform.ID,
			Reason:         "Outil JavaScript/TypeScript introuvable dans node_modules/.bin ni dans le bundle Node.",
		}
	}

	// 3. Strict order for PowerShell module (Invoke-ScriptAnalyzer):
	// Priority 1: .tools/powershell-modules/PSScriptAnalyzer (local dev)
	// Priority 2: ~/.compliance/tools/powershell-modules/PSScriptAnalyzer (registry installed)
	// Priority 3: System PSModulePath
	if command == "Invoke-ScriptAnalyzer" {
		cacheRoot := osutil.DefaultToolCacheDir()
		candidates := []struct {
			dir     string
			managed bool
			reason  string
		}{
			{filepath.Join(root, ".tools", "powershell-modules", "PSScriptAnalyzer"), true, "Module trouvé dans les modules PowerShell locaux (.tools)."},
			{filepath.Join(cacheRoot, "powershell-modules", "PSScriptAnalyzer"), true, "Module trouvé dans le registre d'outils Compliance_Platform."},
		}
		for _, c := range candidates {
			if manifest := findPSScriptAnalyzerManifest(c.dir); manifest != "" {
				norm := filepath.ToSlash(manifest)
				return CandidateToolState{
					Name:           name,
					Command:        command,
					Status:         "available",
					Source:         &norm,
					Version:        nil,
					RuntimeManaged: c.managed,
					Platform:       platform.ID,
					Reason:         c.reason,
				}
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
			if manifest := findPSScriptAnalyzerManifest(filepath.Join(baseDir, "PSScriptAnalyzer")); manifest != "" {
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

	// 4. All other tools:
	// Order: .tools/bin (dev local) ➔ ~/.compliance/tools/{bin,python} ➔ PATH
	toolBin := filepath.Join(root, ".tools", "bin", command+ext)
	if _, err := os.Stat(toolBin); err == nil {
		return probeCommand(toolBin, false)
	}

	cacheRoot := r.cacheDir()

	// If Python tool: check relocatable Python bundle (.tools/python ➔ ~/.compliance/tools/python)
	if isPythonTool(command) {
		pyDirs := []string{
			filepath.Join(root, ".tools", "python"),
			filepath.Join(cacheRoot, "python"),
		}
		var pythonFailure *CandidateToolState
		for _, pDir := range pyDirs {
			if pyExe := findBundlePython(pDir); pyExe != "" {
				st := probePythonTool(pyExe)
				if st.Status == "available" {
					return st
				}
				if st.Status == "runtime_error" {
					copy := st
					pythonFailure = &copy
				}
			}
		}
		if pythonFailure != nil {
			return *pythonFailure
		}
	}

	// Native binary in registry cache (~/.compliance/tools/bin/<platform>/<command>[.exe])
	for _, candidate := range distribution.PlatformCandidates(platform.ID) {
		cached := filepath.Join(cacheRoot, "bin", candidate, command+ext)
		if info, err := os.Stat(cached); err == nil && !info.IsDir() {
			return probeCommand(cached, true)
		}
	}

	// Darwin tool directories, then system PATH
	if found := osutil.LookupExecutable(command); found != "" {
		return probeCommand(found, false)
	}

	// Not installed
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
			var availability string
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
	SchemaVersion   int              `json:"schema_version"`
	CatalogRevision int              `json:"catalog_revision,omitempty"`
	Controls        []CatalogControl `json:"controls"`
	ContentSHA256   string           `json:"content_sha256,omitempty"`
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

func (r *DefaultCandidateResolver) cacheDir() string {
	if r != nil && r.CacheRoot != "" {
		return r.CacheRoot
	}
	return osutil.DefaultToolCacheDir()
}

func transientProbeError(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	if ctx.Err() != nil {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "used by another process") ||
		strings.Contains(msg, "sharing violation") ||
		strings.Contains(msg, "être utilisé par un autre processus") ||
		strings.Contains(msg, "processus ne peut pas accéder")
}

func isPythonTool(command string) bool {
	switch command {
	case "checkov", "bandit", "pylint", "pytest", "pip-audit", "yamllint", "ansible-lint":
		return true
	default:
		return false
	}
}

func pythonModuleName(command string) string {
	switch command {
	case "pip-audit":
		return "pip_audit"
	case "ansible-lint":
		return "ansiblelint"
	default:
		return command
	}
}

func findBundlePython(dir string) string {
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return ""
	}
	if runtime.GOOS == "windows" {
		exe := filepath.Join(dir, "python.exe")
		if fi, err := os.Stat(exe); err == nil && !fi.IsDir() && fi.Size() > 0 {
			return exe
		}
	} else {
		for _, name := range []string{"bin/python3", "bin/python", "python3", "python"} {
			exe := filepath.Join(dir, filepath.FromSlash(name))
			if fi, err := os.Stat(exe); err == nil && !fi.IsDir() && fi.Size() > 0 {
				return exe
			}
		}
	}
	sub := filepath.Join(dir, "python")
	if fi, err := os.Stat(sub); err == nil && fi.IsDir() {
		return findBundlePython(sub)
	}
	return ""
}

func findPSScriptAnalyzerManifest(baseDir string) string {
	if fi, err := os.Stat(baseDir); err != nil || !fi.IsDir() {
		return ""
	}
	direct := filepath.Join(baseDir, "PSScriptAnalyzer.psd1")
	if fi, err := os.Stat(direct); err == nil && !fi.IsDir() {
		return direct
	}
	entries, _ := os.ReadDir(baseDir)
	for _, e := range entries {
		if e.IsDir() {
			sub := filepath.Join(baseDir, e.Name(), "PSScriptAnalyzer.psd1")
			if fi, err := os.Stat(sub); err == nil && !fi.IsDir() {
				return sub
			}
		}
	}
	return ""
}
