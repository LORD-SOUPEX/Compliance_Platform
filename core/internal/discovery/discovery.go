package discovery

import (
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"compliance/internal/osutil"
)

// TechnologyRecord represents a detected technology.
type TechnologyRecord struct {
	Technology    string              `json:"technology"`
	Status        string              `json:"status"` // detected, absent, ambiguous
	Evidence      []string            `json:"evidence"`
	EvidenceTotal int                 `json:"evidence_total"`
	Roots         []string            `json:"roots"`
	Ambiguities   []string            `json:"ambiguities"`
	RootProof     map[string][]string `json:"root_proof,omitempty"`
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

// excludedDirs remains for callers that only need the built-in directory names.
var excludedDirs = map[string]bool{}

func init() {
	for _, name := range defaultSkipDirs {
		excludedDirs[name] = true
	}
}

var allKnownTechnologies = []string{
	"ansible",
	"css",
	"dependencies",
	"docker",
	"go",
	"helm",
	"html",
	"javascript",
	"kubernetes",
	"markdown",
	"opentofu",
	"powershell",
	"python",
	"secrets",
	"shell",
	"terraform",
	"terragrunt",
	"typescript",
	"yaml",
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

// dependencyManifests are the lockfiles and manifests osv-scanner and Trivy read.
var dependencyManifests = map[string]bool{
	"package-lock.json": true, "npm-shrinkwrap.json": true, "yarn.lock": true, "pnpm-lock.yaml": true, "bun.lock": true,
	"requirements.txt": true, "poetry.lock": true, "pipfile.lock": true, "uv.lock": true, "pdm.lock": true,
	"go.mod": true, "cargo.lock": true, "composer.lock": true, "gemfile.lock": true,
	"pom.xml": true, "gradle.lockfile": true, "packages.lock.json": true, "pubspec.lock": true, "mix.lock": true,
}

var (
	reDockerFile      = regexp.MustCompile(`(?i)(^|[.])(dockerfile|containerfile)([.]|$)`)
	reDockerCompose   = regexp.MustCompile(`^(?i)(docker-compose|compose)\.(ya?ml)$`)
	reTerragrunt      = regexp.MustCompile(`^(?i)terragrunt(\.stack)?\.hcl$`)
	reTsConfig        = regexp.MustCompile(`^(?i)tsconfig(\..+)?\.json$`)
	reAnsibleHosts    = regexp.MustCompile(`(?i)(?m)^\s*(?:-\s*)?hosts\s*:`)
	reAnsibleTasks    = regexp.MustCompile(`(?i)(?m)^\s*(?:-\s*)?tasks\s*:`)
	reAnsibleRole     = regexp.MustCompile(`(?i)(^|/)roles/[^/]+/tasks/main\.ya?ml$`)
	reAnsiblePlaybook = regexp.MustCompile(`(?i)(^|/)(playbooks?/)?[^/]+\.ya?ml$`)
	reKubeKind        = regexp.MustCompile(`(?i)(?m)^\s*kind\s*:\s*(Pod|Deployment|StatefulSet|DaemonSet|ReplicaSet|Job|CronJob|Service|ConfigMap|Secret|Ingress|PersistentVolume|PersistentVolumeClaim|Namespace|ServiceAccount|Role|RoleBinding|ClusterRole|ClusterRoleBinding|CustomResourceDefinition)\s*(?:#.*)?$`)
	reKubeApi         = regexp.MustCompile(`(?i)(?m)^\s*apiVersion\s*:\s*\S+`)
)

type techAccumulator struct {
	technology    string
	status        string
	evidence      map[string]bool
	markers       map[string]bool
	evidenceTotal int
	roots         map[string]bool
	ambiguities   map[string]bool
	proof         map[string]map[string]struct{}
}

func newAccumulator(tech string) *techAccumulator {
	return &techAccumulator{
		technology:  tech,
		status:      "absent",
		evidence:    make(map[string]bool),
		markers:     make(map[string]bool),
		roots:       make(map[string]bool),
		ambiguities: make(map[string]bool),
	}
}

func (acc *techAccumulator) addEvidence(relFile, relRoot, status, ambiguity string) {
	acc.evidenceTotal++
	if relRoot == "" {
		relRoot = "."
	}
	if !acc.roots[relRoot] && len(acc.roots) >= maxEvidence {
		return
	}
	firstRoot := !acc.roots[relRoot]
	acc.roots[relRoot] = true
	acc.noteProof(relRoot, relFile)
	if firstRoot || len(acc.evidence) < maxEvidence {
		acc.evidence[relFile] = true
	}
	if status == "detected" {
		acc.status = "detected"
	} else if acc.status == "absent" {
		acc.status = "ambiguous"
	}
	if ambiguity != "" {
		acc.ambiguities[ambiguity] = true
	}
}

func (acc *techAccumulator) addMarker(relFile, relRoot, status, ambiguity string) {
	acc.markers[relFile] = true
	acc.addEvidence(relFile, relRoot, status, ambiguity)
}

func (acc *techAccumulator) toRecord() TechnologyRecord {
	evidenceList := make([]string, 0)
	for e := range acc.markers {
		evidenceList = append(evidenceList, e)
	}
	sort.Strings(evidenceList)
	rest := make([]string, 0)
	for e := range acc.evidence {
		if !acc.markers[e] {
			rest = append(rest, e)
		}
	}
	sort.Strings(rest)
	evidenceList = append(evidenceList, rest...)
	if len(evidenceList) > maxEvidence {
		evidenceList = evidenceList[:maxEvidence]
	}

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

	proof := map[string][]string{}
	for root, tokens := range acc.proof {
		list := make([]string, 0, len(tokens))
		for token := range tokens {
			list = append(list, token)
		}
		sort.Strings(list)
		proof[root] = list
	}

	finalStatus := acc.status
	if len(ambList) > 0 {
		finalStatus = "ambiguous"
	} else if len(evidenceList) > 0 && finalStatus == "absent" {
		finalStatus = "detected"
	}

	return TechnologyRecord{
		Technology:    acc.technology,
		Status:        finalStatus,
		Evidence:      evidenceList,
		EvidenceTotal: acc.evidenceTotal,
		Roots:         rootsList,
		Ambiguities:   ambList,
		RootProof:     proof,
	}
}

func (acc *techAccumulator) noteProof(relRoot, relFile string) {
	if acc.proof == nil {
		acc.proof = map[string]map[string]struct{}{}
	}
	tokens := acc.proof[relRoot]
	if tokens == nil {
		tokens = map[string]struct{}{}
		acc.proof[relRoot] = tokens
	}
	base := filepath.Base(relFile)
	if base != "" && base != "." {
		tokens[base] = struct{}{}
	}
	if ext := strings.ToLower(filepath.Ext(base)); ext != "" {
		tokens[ext] = struct{}{}
	}
}

// DiscoverAll scans repoRoot and discovers all 13 technologies supported by the Compliance Platform.
func DiscoverAll(repoRoot string) (*DiscoveryResult, error) {
	start := time.Now()
	absRepo, err := osutil.CanonicalPath(repoRoot)
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
	rules := newIgnoreRules(absRepo)

	err = filepath.WalkDir(absRepo, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			rel, _ := filepath.Rel(absRepo, path)
			scanErrors = append(scanErrors, ScanError{
				Path:      filepath.ToSlash(rel),
				Operation: "enumerate",
				Error:     walkErr.Error(),
			})
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		relPath, relErr := filepath.Rel(absRepo, path)
		if relErr != nil {
			return nil
		}
		normRel := filepath.ToSlash(relPath)
		if d.IsDir() {
			if path != absRepo && rules.skipDir(d.Name(), normRel) {
				return filepath.SkipDir
			}
			rules.observeDir(path, normRel)
			return nil
		}
		if rules.skipFile(normRel) {
			return nil
		}

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

	// 5. JavaScript — package.json is the marker. Source files are counted, not all stored.
	for _, f := range discoveredFiles {
		if strings.EqualFold(f.name, "package.json") || strings.HasPrefix(strings.ToLower(f.name), "vite.config.") || strings.HasPrefix(strings.ToLower(f.name), "eslint.config.") {
			relRoot := toRelRoot(absRepo, f.dir)
			accumulators["javascript"].addMarker(f.relPath, relRoot, "detected", "")
		} else if f.ext == ".js" || f.ext == ".jsx" || f.ext == ".mjs" || f.ext == ".cjs" || f.ext == ".vue" {
			projRoot := findNearestProjectRoot(f.dir, absRepo, jsMarkers)
			relRoot := toRelRoot(absRepo, projRoot)
			accumulators["javascript"].addEvidence(f.relPath, relRoot, "detected", "")
		}
	}

	// 6. TypeScript — tsconfig is the marker.
	for _, f := range discoveredFiles {
		if reTsConfig.MatchString(f.name) {
			relRoot := toRelRoot(absRepo, f.dir)
			accumulators["typescript"].addMarker(f.relPath, relRoot, "detected", "")
		} else if f.ext == ".ts" || f.ext == ".tsx" || f.ext == ".mts" || f.ext == ".cts" {
			projRoot := findNearestProjectRoot(f.dir, absRepo, tsMarkers)
			relRoot := toRelRoot(absRepo, projRoot)
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

		useTofu := false
		switch {
		case hasTofu && !hasTf:
			useTofu = true
		case hasTf && !hasTofu:
			useTofu = false
		default:
			useTofu = preferOpenTofu()
		}
		if useTofu {
			accumulators["opentofu"].addEvidence(f.relPath, relRoot, "detected", "")
			continue
		}
		accumulators["terraform"].addEvidence(f.relPath, relRoot, "detected", "")
		for _, m := range tfMarkers {
			if m.dir == projRoot {
				accumulators["terraform"].addEvidence(m.relPath, relRoot, "detected", "")
			}
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

	// 11. Ansible — precise markers only. A directory named roles/ is not enough.
	for _, f := range discoveredFiles {
		if strings.EqualFold(f.name, "ansible.cfg") || strings.EqualFold(f.name, "galaxy.yml") || reAnsibleRole.MatchString(f.relPath) {
			relRoot := toRelRoot(absRepo, f.dir)
			accumulators["ansible"].addMarker(f.relPath, relRoot, "detected", "")
			continue
		}
		if !reAnsiblePlaybook.MatchString(f.relPath) || (f.ext != ".yml" && f.ext != ".yaml") {
			continue
		}
		info, statErr := os.Stat(f.absPath)
		if statErr != nil || info.Size() > 1024*1024 {
			continue
		}
		content, readErr := os.ReadFile(f.absPath)
		if readErr != nil {
			continue
		}
		if reAnsibleHosts.Match(content) && reAnsibleTasks.Match(content) {
			relRoot := toRelRoot(absRepo, f.dir)
			accumulators["ansible"].addMarker(f.relPath, relRoot, "detected", "")
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

	// 13a. CSS and HTML belong to the nearest package (package.json), else to their folder.
	for _, f := range discoveredFiles {
		switch f.ext {
		case ".css", ".scss", ".less":
			accumulators["css"].addEvidence(f.relPath, toRelRoot(absRepo, findNearestProjectRoot(f.dir, absRepo, jsMarkers)), "detected", "")
		case ".html", ".htm":
			accumulators["html"].addEvidence(f.relPath, toRelRoot(absRepo, findNearestProjectRoot(f.dir, absRepo, jsMarkers)), "detected", "")
		}
	}

	// 13b. Go modules: one root per go.mod.
	for _, f := range discoveredFiles {
		if f.name == "go.mod" {
			accumulators["go"].addMarker(f.relPath, toRelRoot(absRepo, f.dir), "detected", "")
		} else if f.ext == ".go" {
			accumulators["go"].addEvidence(f.relPath, toRelRoot(absRepo, findNearestProjectRoot(f.dir, absRepo, []string{"go.mod"})), "detected", "")
		}
	}

	// 13c. Third-party dependencies: one root per folder holding a lockfile or a manifest.
	for _, f := range discoveredFiles {
		name := strings.ToLower(f.name)
		if dependencyManifests[name] || (strings.HasPrefix(name, "requirements") && f.ext == ".txt") {
			accumulators["dependencies"].addEvidence(f.relPath, toRelRoot(absRepo, f.dir), "detected", "")
		}
	}

	// 13. Secrets: any repository can leak one. Gitleaks scans the whole tree once.
	for _, f := range discoveredFiles {
		accumulators["secrets"].addEvidence(f.relPath, ".", "detected", "")
	}

	// 14. YAML outside Ansible roots (their own yamllint control covers them) and
	// outside templates, which are not YAML until rendered.
	ansibleRoots := accumulators["ansible"].roots
	for _, f := range yamlFiles {
		if underRoot(f.relPath, ansibleRoots) {
			continue
		}
		content, readErr := os.ReadFile(f.absPath)
		if readErr != nil || strings.Contains(string(content), "{{") {
			continue
		}
		accumulators["yaml"].addEvidence(f.relPath, toRelRoot(absRepo, f.dir), "detected", "")
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

// CollectSources lists files under relRoot, honoring the same exclusions as DiscoverAll.
// underRoot reports whether relPath sits in one of roots ("." holds everything).
func underRoot(relPath string, roots map[string]bool) bool {
	for root := range roots {
		if root == "." || relPath == root || strings.HasPrefix(relPath, root+"/") {
			return true
		}
	}
	return false
}

// IsContainerFile reports Dockerfiles and Containerfiles, including
// Dockerfile.*, *.Dockerfile and files nested in a subdirectory.
func IsContainerFile(name string) bool {
	return reDockerFile.MatchString(filepath.Base(name))
}

func CollectSources(repoRoot, relRoot string, match func(name, rel string) bool) ([]string, error) {
	absRepo, err := osutil.CanonicalPath(repoRoot)
	if err != nil {
		return nil, err
	}
	start := absRepo
	if relRoot != "" && relRoot != "." {
		start = filepath.Join(absRepo, filepath.FromSlash(relRoot))
	}
	rules := newIgnoreRules(absRepo)
	var out []string
	err = filepath.WalkDir(start, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d == nil {
			return nil
		}
		rel, relErr := filepath.Rel(absRepo, path)
		if relErr != nil {
			return nil
		}
		norm := filepath.ToSlash(rel)
		if d.IsDir() {
			if path != start && path != absRepo && rules.skipDir(d.Name(), norm) {
				return filepath.SkipDir
			}
			rules.observeDir(path, norm)
			return nil
		}
		if rules.skipFile(norm) {
			return nil
		}
		if match == nil || match(d.Name(), norm) {
			out = append(out, path)
		}
		return nil
	})
	return out, err
}

// preferOpenTofu is true only when tofu is installed and terraform is not.
// COMPLIANCE_IAC_DEFAULT forces the choice in tests.
func preferOpenTofu() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("COMPLIANCE_IAC_DEFAULT"))) {
	case "terraform":
		return false
	case "opentofu", "tofu":
		return true
	}
	return commandExists("tofu") && !commandExists("terraform")
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
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
