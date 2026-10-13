package discovery

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// TechnologyRecord represents a detected technology.
type TechnologyRecord struct {
	Technology  string   `json:"technology"`
	Status      string   `json:"status"` // detected, absent, ambiguous
	Evidence    []string `json:"evidence"`
	Roots       []string `json:"roots"`
	Ambiguities []string `json:"ambiguities"`
}

// AmbiguityDetail represents an ambiguity with context.
type AmbiguityDetail struct {
	Technology string   `json:"technology"`
	Evidence   []string `json:"evidence"`
	Roots      []string `json:"roots"`
	Reasons    []string `json:"reasons"`
}

// ProjectRootEntry represents a technology root mapping.
type ProjectRootEntry struct {
	Technology string `json:"technology"`
	Path       string `json:"path"`
}

// ScanError records an error encountered during directory walk or file inspection.
type ScanError struct {
	Path      string `json:"path"`
	Operation string `json:"operation"`
	Error     string `json:"error"`
}

// DiscoveryResult represents the full output of discovery.
type DiscoveryResult struct {
	SchemaVersion    int                `json:"schema_version"`
	Repository       string             `json:"repository"`
	Technologies     []TechnologyRecord `json:"technologies"`
	ProjectRoots     interface{}        `json:"project_roots"`
	Ambiguities      interface{}        `json:"ambiguities"`
	CapabilityMatrix []interface{}      `json:"capability_matrix"`
	ToolResolution   []interface{}      `json:"tool_resolution"`
	ScanComplete     bool               `json:"scan_complete"`
	ScanErrors       []ScanError        `json:"scan_errors"`
	Metrics          DiscoveryMetrics   `json:"metrics"`
}

// DiscoveryMetrics captures timing.
type DiscoveryMetrics struct {
	DiscoveryMs int64 `json:"discovery_ms"`
	ResolverMs  int64 `json:"resolver_ms"`
}

// Exactly matches Get-ProjectFile in scripts/quality-gate.ps1
var excludedDirs = map[string]bool{
	".git":              true,
	".venv":             true,
	".tools":            true,
	".extension-build":  true,
	"reports":           true,
	"__pycache__":       true,
	".pytest_cache":     true,
	".mypy_cache":       true,
	".ruff_cache":       true,
	".cache":            true,
	".terraform":        true,
	".terragrunt-cache": true,
}

var allKnownTechnologies = []string{
	"ansible",
	"docker",
	"helm",
	"javascript",
	"kubernetes",
	"markdown",
	"opentofu",
	"powershell",
	"python",
	"shell",
	"terraform",
	"terragrunt",
	"typescript",
}

var pythonMarkers = []string{
	"pyproject.toml",
	"setup.py",
	"setup.cfg",
	"requirements.txt",
}

var jsMarkers = []string{
	"package.json",
}

var tsMarkers = []string{
	"tsconfig.json",
	"package.json",
}

var (
	reDockerFile      = regexp.MustCompile(`^(?i)(Dockerfile|Containerfile)(\..+)?$`)
	reDockerCompose   = regexp.MustCompile(`^(?i)(docker-compose|compose)\.(ya?ml)$`)
	reTerragrunt      = regexp.MustCompile(`^(?i)terragrunt(\.stack)?\.hcl$`)
	reTsConfig        = regexp.MustCompile(`^(?i)tsconfig(\..+)?\.json$`)
	reAnsibleHosts    = regexp.MustCompile(`(?i)(?m)^\s*(?:-\s*)?hosts\s*:`)
	reAnsibleEvidence = regexp.MustCompile(`(?i)(^|/)(ansible\.cfg|galaxy\.yml|requirements\.yml)$|(^|/)meta/runtime\.yml$|(^|/)(roles|playbooks)/`)
	reKubeKind        = regexp.MustCompile(`(?i)(?m)^\s*kind\s*:\s*(Pod|Deployment|StatefulSet|DaemonSet|ReplicaSet|Job|CronJob|Service|ConfigMap|Secret|Ingress|PersistentVolume|PersistentVolumeClaim|Namespace|ServiceAccount|Role|RoleBinding|ClusterRole|ClusterRoleBinding|CustomResourceDefinition)\s*(?:#.*)?$`)
	reKubeApi         = regexp.MustCompile(`(?i)(?m)^\s*apiVersion\s*:\s*\S+`)
)

type techAccumulator struct {
	technology  string
	status      string
	evidence    map[string]bool
	roots       map[string]bool
	ambiguities map[string]bool
}

func newAccumulator(tech string) *techAccumulator {
	return &techAccumulator{
		technology:  tech,
		status:      "absent",
		evidence:    make(map[string]bool),
		roots:       make(map[string]bool),
		ambiguities: make(map[string]bool),
	}
}

func (acc *techAccumulator) addEvidence(relFile, relRoot, status, ambiguity string) {
	acc.evidence[relFile] = true
	if relRoot == "" {
		relRoot = "."
	}
	acc.roots[relRoot] = true
	if status == "detected" {
		acc.status = "detected"
	} else if acc.status == "absent" {
		acc.status = "ambiguous"
	}
	if ambiguity != "" {
		acc.ambiguities[ambiguity] = true
	}
}

func (acc *techAccumulator) toRecord() TechnologyRecord {
	evidenceList := make([]string, 0)
	for e := range acc.evidence {
		evidenceList = append(evidenceList, e)
	}
	sort.Strings(evidenceList)

	rootsList := make([]string, 0)
	for r := range acc.roots {
		rootsList = append(rootsList, r)
	}
	sort.Strings(rootsList)

	ambList := make([]string, 0)
	for a := range acc.ambiguities {
		ambList = append(ambList, a)
	}
	sort.Strings(ambList)

	finalStatus := acc.status
	if len(ambList) > 0 {
		finalStatus = "ambiguous"
	} else if len(evidenceList) > 0 && finalStatus == "absent" {
		finalStatus = "detected"
	}

	return TechnologyRecord{
		Technology:  acc.technology,
		Status:      finalStatus,
		Evidence:    evidenceList,
		Roots:       rootsList,
		Ambiguities: ambList,
	}
}

// DiscoverAll scans repoRoot and discovers all 13 technologies supported by the Compliance Platform.
func DiscoverAll(repoRoot string) (*DiscoveryResult, error) {
	start := time.Now()
	absRepo, err := filepath.Abs(repoRoot)
	if err != nil {
		return nil, err
	}

	accumulators := make(map[string]*techAccumulator)
	for _, tech := range allKnownTechnologies {
		accumulators[tech] = newAccumulator(tech)
	}

	type fileInfo struct {
		absPath string
		relPath string
		name    string
		ext     string
		dir     string
	}

	var discoveredFiles []fileInfo
	var yamlFiles []fileInfo
	scanErrors := make([]ScanError, 0)

	err = filepath.WalkDir(absRepo, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			rel, _ := filepath.Rel(absRepo, path)
			scanErrors = append(scanErrors, ScanError{
				Path:      filepath.ToSlash(rel),
				Operation: "enumerate",
				Error:     walkErr.Error(),
			})
			return nil
		}
		if d.IsDir() {
			if excludedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		relPath, relErr := filepath.Rel(absRepo, path)
		if relErr != nil {
			return nil
		}
		normRel := filepath.ToSlash(relPath)
		name := d.Name()
		ext := strings.ToLower(filepath.Ext(name))

		fi := fileInfo{
			absPath: path,
			relPath: normRel,
			name:    name,
			ext:     ext,
			dir:     filepath.Dir(path),
		}
		discoveredFiles = append(discoveredFiles, fi)

		if ext == ".yml" || ext == ".yaml" {
			yamlFiles = append(yamlFiles, fi)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	// 1. Python
	for _, f := range discoveredFiles {
		if f.ext == ".py" {
			projRoot := findNearestProjectRoot(f.dir, absRepo, pythonMarkers)
			relRoot := toRelRoot(absRepo, projRoot)
			accumulators["python"].addEvidence(f.relPath, relRoot, "detected", "")
		}
	}

	// 2. PowerShell
	for _, f := range discoveredFiles {
		if f.ext == ".ps1" || f.ext == ".psm1" || f.ext == ".psd1" {
			relRoot := toRelRoot(absRepo, f.dir)
			accumulators["powershell"].addEvidence(f.relPath, relRoot, "detected", "")
		}
	}

	// 3. Shell
	for _, f := range discoveredFiles {
		if f.ext == ".sh" {
			relRoot := toRelRoot(absRepo, f.dir)
			accumulators["shell"].addEvidence(f.relPath, relRoot, "detected", "")
		}
	}

	// 4. Markdown
	for _, f := range discoveredFiles {
		if f.ext == ".md" {
			accumulators["markdown"].addEvidence(f.relPath, ".", "detected", "")
		}
	}

	// 5. JavaScript
	for _, f := range discoveredFiles {
		if f.ext == ".js" || f.ext == ".jsx" || f.ext == ".mjs" || f.ext == ".cjs" {
			projRoot := findNearestProjectRoot(f.dir, absRepo, jsMarkers)
			relRoot := toRelRoot(absRepo, projRoot)
			accumulators["javascript"].addEvidence(f.relPath, relRoot, "detected", "")
		} else if strings.EqualFold(f.name, "package.json") {
			relRoot := toRelRoot(absRepo, f.dir)
			accumulators["javascript"].addEvidence(f.relPath, relRoot, "detected", "")
		}
	}

	// 6. TypeScript
	for _, f := range discoveredFiles {
		if f.ext == ".ts" || f.ext == ".tsx" || f.ext == ".mts" || f.ext == ".cts" {
			projRoot := findNearestProjectRoot(f.dir, absRepo, tsMarkers)
			relRoot := toRelRoot(absRepo, projRoot)
			accumulators["typescript"].addEvidence(f.relPath, relRoot, "detected", "")
		} else if reTsConfig.MatchString(f.name) {
			relRoot := toRelRoot(absRepo, f.dir)
			accumulators["typescript"].addEvidence(f.relPath, relRoot, "detected", "")
		}
	}

	// 7. Terraform & OpenTofu
	var tfFiles []fileInfo
	var tofuFiles []fileInfo
	var tfMarkers []fileInfo
	var tofuMarkers []fileInfo

	for _, f := range discoveredFiles {
		if f.ext == ".tf" {
			tfFiles = append(tfFiles, f)
		} else if f.ext == ".tofu" {
			tofuFiles = append(tofuFiles, f)
		} else if f.name == ".terraform-version" {
			tfMarkers = append(tfMarkers, f)
		} else if f.name == ".opentofu-version" || f.name == ".tofurc" {
			tofuMarkers = append(tofuMarkers, f)
		}
	}

	for _, f := range tofuFiles {
		relRoot := toRelRoot(absRepo, f.dir)
		accumulators["opentofu"].addEvidence(f.relPath, relRoot, "detected", "")
	}
	for _, f := range tofuMarkers {
		relRoot := toRelRoot(absRepo, f.dir)
		accumulators["opentofu"].addEvidence(f.relPath, relRoot, "detected", "")
	}

	for _, f := range tfFiles {
		projRoot := findNearestProjectRoot(f.dir, absRepo, []string{".terraform-version", ".opentofu-version", ".tofurc"})
		relRoot := toRelRoot(absRepo, projRoot)

		hasTf := fileExists(filepath.Join(projRoot, ".terraform-version"))
		hasTofu := fileExists(filepath.Join(projRoot, ".opentofu-version")) || fileExists(filepath.Join(projRoot, ".tofurc"))

		if hasTf && !hasTofu {
			accumulators["terraform"].addEvidence(f.relPath, relRoot, "detected", "")
			for _, m := range tfMarkers {
				if m.dir == projRoot {
					accumulators["terraform"].addEvidence(m.relPath, relRoot, "detected", "")
				}
			}
		} else if hasTofu && !hasTf {
			accumulators["opentofu"].addEvidence(f.relPath, relRoot, "detected", "")
		} else {
			amb := "Fichiers .tf sans marqueur de selection dans leur racine."
			if hasTf && hasTofu {
				amb = "Marqueurs Terraform et OpenTofu contradictoires dans la meme racine."
			}
			accumulators["terraform"].addEvidence(f.relPath, relRoot, "ambiguous", amb)
			accumulators["opentofu"].addEvidence(f.relPath, relRoot, "ambiguous", amb)
		}
	}

	// 8. Terragrunt
	for _, f := range discoveredFiles {
		if reTerragrunt.MatchString(f.name) {
			relRoot := toRelRoot(absRepo, f.dir)
			accumulators["terragrunt"].addEvidence(f.relPath, relRoot, "detected", "")
		}
	}

	// 9. Docker / Containers
	for _, f := range discoveredFiles {
		if reDockerFile.MatchString(f.name) || reDockerCompose.MatchString(f.name) {
			relRoot := toRelRoot(absRepo, f.dir)
			accumulators["docker"].addEvidence(f.relPath, relRoot, "detected", "")
		}
	}

	// 10. Helm
	for _, f := range discoveredFiles {
		if strings.EqualFold(f.name, "Chart.yaml") {
			relRoot := toRelRoot(absRepo, f.dir)
			accumulators["helm"].addEvidence(f.relPath, relRoot, "detected", "")
		}
	}

	// 11. Ansible
	for _, f := range discoveredFiles {
		rel := f.relPath
		if !reAnsibleEvidence.MatchString(rel) {
			continue
		}

		ansibleRoot := f.dir
		if strings.EqualFold(f.name, "ansible.cfg") || strings.EqualFold(f.name, "galaxy.yml") || strings.EqualFold(f.name, "requirements.yml") {
			ansibleRoot = f.dir
		} else if idx := strings.Index(rel, "roles/"); idx != -1 {
			prefix := rel[:idx]
			if prefix == "" {
				sub := rel[len("roles/"):]
				if slashIdx := strings.Index(sub, "/"); slashIdx != -1 {
					roleName := sub[:slashIdx]
					ansibleRoot = filepath.Join(absRepo, "roles", roleName)
				} else {
					ansibleRoot = absRepo
				}
			} else {
				rootRel := strings.TrimSuffix(prefix, "/")
				ansibleRoot = filepath.Join(absRepo, filepath.FromSlash(rootRel))
			}
		} else if idx := strings.Index(rel, "playbooks/"); idx != -1 {
			prefix := rel[:idx]
			rootRel := strings.TrimSuffix(prefix, "/")
			if rootRel != "" {
				ansibleRoot = filepath.Join(absRepo, filepath.FromSlash(rootRel))
			} else {
				ansibleRoot = absRepo
			}
		} else if strings.HasSuffix(rel, "meta/runtime.yml") {
			ansibleRoot = filepath.Dir(filepath.Dir(f.absPath))
		}

		relRoot := toRelRoot(absRepo, ansibleRoot)
		accumulators["ansible"].addEvidence(f.relPath, relRoot, "detected", "")
	}

	// Ansible fallback on YAML files if absent
	if accumulators["ansible"].status == "absent" {
		for _, f := range yamlFiles {
			content, readErr := os.ReadFile(f.absPath)
			if readErr != nil {
				scanErrors = append(scanErrors, ScanError{
					Path:      f.relPath,
					Operation: "read",
					Error:     readErr.Error(),
				})
				continue
			}
			if reAnsibleHosts.Match(content) {
				relRoot := toRelRoot(absRepo, f.dir)
				amb := "La clé hosts: dans un YAML est un signal faible; le fichier peut être un playbook Ansible ou un YAML générique."
				accumulators["ansible"].addEvidence(f.relPath, relRoot, "ambiguous", amb)
			}
		}
	}

	// 12. Kubernetes
	for _, f := range yamlFiles {
		content, readErr := os.ReadFile(f.absPath)
		if readErr != nil {
			scanErrors = append(scanErrors, ScanError{
				Path:      f.relPath,
				Operation: "read",
				Error:     readErr.Error(),
			})
			continue
		}
		if reKubeApi.Match(content) && reKubeKind.Match(content) {
			relRoot := toRelRoot(absRepo, f.dir)
			status := "detected"
			amb := ""
			if strings.Contains(string(content), "{{") {
				status = "ambiguous"
				amb = "Le YAML contient des marqueurs de template Helm; la ressource rendue n'est pas confirmée."
			}
			accumulators["kubernetes"].addEvidence(f.relPath, relRoot, status, amb)
		}
	}

	// Build sorted Technologies list
	techRecords := make([]TechnologyRecord, 0, len(allKnownTechnologies))
	projectRoots := make([]ProjectRootEntry, 0)
	ambiguities := make([]AmbiguityDetail, 0)

	for _, techName := range allKnownTechnologies {
		rec := accumulators[techName].toRecord()
		techRecords = append(techRecords, rec)

		if rec.Status == "detected" || rec.Status == "ambiguous" {
			for _, r := range rec.Roots {
				projectRoots = append(projectRoots, ProjectRootEntry{
					Technology: rec.Technology,
					Path:       r,
				})
			}
		}

		if len(rec.Ambiguities) > 0 {
			ambiguities = append(ambiguities, AmbiguityDetail{
				Technology: rec.Technology,
				Evidence:   rec.Evidence,
				Roots:      rec.Roots,
				Reasons:    rec.Ambiguities,
			})
		}
	}

	res := &DiscoveryResult{
		SchemaVersion:    1,
		Repository:       absRepo,
		Technologies:     techRecords,
		ProjectRoots:     projectRoots,
		Ambiguities:      ambiguities,
		CapabilityMatrix: make([]interface{}, 0),
		ToolResolution:   make([]interface{}, 0),
		ScanComplete:     (len(scanErrors) == 0),
		ScanErrors:       scanErrors,
		Metrics: DiscoveryMetrics{
			DiscoveryMs: time.Since(start).Milliseconds(),
			ResolverMs:  0,
		},
	}

	return res, nil
}

// DiscoverPython scans repoRoot and discovers Python evidence and roots.
// Maintained for strict backward compatibility with Phase 0 contracts.
func DiscoverPython(repoRoot string) (*DiscoveryResult, error) {
	full, err := DiscoverAll(repoRoot)
	if err != nil {
		return nil, err
	}

	var pyRecord TechnologyRecord
	for _, t := range full.Technologies {
		if t.Technology == "python" {
			pyRecord = t
			break
		}
	}

	// Return only Python project roots as string slice for Phase 0 parity
	pyRoots := make([]string, 0, len(pyRecord.Roots))
	pyRoots = append(pyRoots, pyRecord.Roots...)

	pyAmbiguities := make([]string, 0, len(pyRecord.Ambiguities))
	pyAmbiguities = append(pyAmbiguities, pyRecord.Ambiguities...)

	return &DiscoveryResult{
		SchemaVersion:    full.SchemaVersion,
		Repository:       full.Repository,
		Technologies:     []TechnologyRecord{pyRecord},
		ProjectRoots:     pyRoots,
		Ambiguities:      pyAmbiguities,
		CapabilityMatrix: make([]interface{}, 0),
		ToolResolution:   make([]interface{}, 0),
		ScanComplete:     full.ScanComplete,
		ScanErrors:       full.ScanErrors,
		Metrics:          full.Metrics,
	}, nil
}

func findNearestProjectRoot(dir, repoRoot string, markers []string) string {
	curr := dir
	for {
		for _, m := range markers {
			if _, err := os.Stat(filepath.Join(curr, m)); err == nil {
				return curr
			}
		}
		if curr == repoRoot || curr == filepath.Dir(curr) {
			break
		}
		curr = filepath.Dir(curr)
	}
	return dir
}

func toRelRoot(repoRoot, dir string) string {
	rel, err := filepath.Rel(repoRoot, dir)
	if err != nil || rel == "." || rel == "" {
		return "."
	}
	return filepath.ToSlash(rel)
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// ToJSON serializes the DiscoveryResult to JSON.
func (d *DiscoveryResult) ToJSON(indent bool) ([]byte, error) {
	if indent {
		return json.MarshalIndent(d, "", "  ")
	}
	return json.Marshal(d)
}
