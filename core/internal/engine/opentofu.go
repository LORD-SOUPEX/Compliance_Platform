package engine

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"compliance/internal/discovery"
)

// tofuStage is a temporary copy of an OpenTofu root where *.tofu files are
// named *.tf. TFLint and Checkov only read *.tf: without it they analyse
// nothing in an OpenTofu module and report a success.
type tofuStage struct {
	Dir     string
	root    string
	renames map[string]string // staged relative path (x.tf) -> original (x.tofu), slash form
}

// stageOpenTofu copies the HCL files of root. Returns nil when root has no
// *.tofu file. As in OpenTofu, x.tofu takes precedence over x.tf.
func stageOpenTofu(root string) (*tofuStage, error) {
	var files []string
	hasTofu := false
	skip := map[string]bool{}
	for _, name := range discovery.SkipDirNames() {
		skip[name] = true
	}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			if path != root && skip[entry.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		lower := strings.ToLower(entry.Name())
		switch {
		case strings.HasSuffix(lower, ".tofu"):
			hasTofu = true
			files = append(files, path)
		case strings.HasSuffix(lower, ".tf"), strings.HasSuffix(lower, ".tfvars"), strings.HasSuffix(lower, ".tofu.json"),
			strings.HasSuffix(lower, ".tf.json"), lower == ".tflint.hcl":
			files = append(files, path)
		}
		return nil
	})
	if err != nil || !hasTofu {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "compliance-tofu-")
	if err != nil {
		return nil, err
	}
	stage := &tofuStage{Dir: dir, root: root, renames: map[string]string{}}
	present := map[string]bool{}
	for _, file := range files {
		rel, _ := filepath.Rel(root, file)
		present[filepath.ToSlash(rel)] = true
	}
	for _, file := range files {
		rel, _ := filepath.Rel(root, file)
		slash := filepath.ToSlash(rel)
		target := slash
		if strings.HasSuffix(strings.ToLower(slash), ".tofu") {
			target = slash[:len(slash)-len(".tofu")] + ".tf"
			stage.renames[target] = slash
		} else if strings.HasSuffix(strings.ToLower(slash), ".tf") && present[slash[:len(slash)-len(".tf")]+".tofu"] {
			continue
		}
		body, err := os.ReadFile(file)
		if err != nil {
			_ = os.RemoveAll(dir)
			return nil, err
		}
		dest := filepath.Join(dir, filepath.FromSlash(target))
		if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
			_ = os.RemoveAll(dir)
			return nil, err
		}
		if err := os.WriteFile(dest, body, 0o600); err != nil {
			_ = os.RemoveAll(dir)
			return nil, err
		}
	}
	return stage, nil
}

// restore rewrites a tool output so that it names the real root and the real
// *.tofu files, in plain, slash and JSON-escaped path forms.
func (s *tofuStage) restore(text string) string {
	if s == nil || text == "" {
		return text
	}
	for _, staged := range []string{s.Dir, resolvedDir(s.Dir)} {
		if staged == "" {
			continue
		}
		text = strings.ReplaceAll(text, strings.ReplaceAll(staged, `\`, `\\`), strings.ReplaceAll(s.root, `\`, `\\`))
		text = strings.ReplaceAll(text, staged, s.root)
		text = strings.ReplaceAll(text, filepath.ToSlash(staged), filepath.ToSlash(s.root))
	}
	for staged, original := range s.renames {
		for _, sep := range []string{"/", `\`, `\\`} {
			from := strings.ReplaceAll(staged, "/", sep)
			to := strings.ReplaceAll(original, "/", sep)
			pattern := regexp.MustCompile(`(^|[^\w.-])` + regexp.QuoteMeta(from) + `($|[^\w.])`)
			text = pattern.ReplaceAllString(text, "${1}"+strings.ReplaceAll(to, "$", "$$")+"${2}")
		}
	}
	return text
}

func (s *tofuStage) cleanup() {
	if s != nil {
		_ = os.RemoveAll(s.Dir)
	}
}

// resolvedDir follows links (macOS /var -> /private/var) that tools print resolved.
func resolvedDir(dir string) string {
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil || resolved == dir {
		return ""
	}
	return resolved
}

// checkovAnalysedNothing reports the summary Checkov prints when it parsed no resource.
func checkovAnalysedNothing(stdout string) bool {
	return !strings.Contains(stdout, `"results"`) && regexp.MustCompile(`"resource_count":\s*0\b`).MatchString(stdout)
}
