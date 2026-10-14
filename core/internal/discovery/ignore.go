package discovery

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const maxEvidence = 8

// Default directory names skipped even when they are absent from .gitignore.
var defaultSkipDirs = []string{
	".git",
	".vscode",
	".vscode-test",
	".rumdl_cache",
	".venv",
	".tools",
	".extension-build",
	"reports",
	"__pycache__",
	".pytest_cache",
	".mypy_cache",
	".ruff_cache",
	".cache",
	".terraform",
	".terragrunt-cache",
	"node_modules",
	"venv",
	"dist",
	"build",
	"vendor",
	"testdata",
	"fixtures",
	"__snapshots__",
}

type gitPattern struct {
	negate   bool
	dirOnly  bool
	anchored bool
	re       *regexp.Regexp
}

type ignoreRules struct {
	names    map[string]struct{}
	patterns []scopedPattern
}

type scopedPattern struct {
	base string
	gitPattern
}

func newIgnoreRules(repoRoot string) *ignoreRules {
	rules := &ignoreRules{names: map[string]struct{}{}}
	rootName := strings.ToLower(filepath.Base(repoRoot))
	for _, name := range defaultSkipDirs {
		lower := strings.ToLower(name)
		if rootName == lower && (lower == "testdata" || lower == "fixtures" || lower == "__snapshots__") {
			continue
		}
		rules.names[lower] = struct{}{}
	}
	if extra := os.Getenv("COMPLIANCE_DISCOVERY_EXCLUDE"); extra != "" {
		for _, name := range strings.Split(extra, ",") {
			name = strings.TrimSpace(name)
			if name != "" {
				rules.names[strings.ToLower(name)] = struct{}{}
			}
		}
	}
	rules.readFile(repoRoot, ".", filepath.Join(repoRoot, ".gitignore"))
	rules.readFile(repoRoot, ".", filepath.Join(repoRoot, ".complianceignore"))
	return rules
}

func (r *ignoreRules) readFile(repoRoot, baseRel, path string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if pat, ok := compileGitPattern(line); ok {
			r.patterns = append(r.patterns, scopedPattern{base: baseRel, gitPattern: pat})
		}
	}
}

func (r *ignoreRules) observeDir(absDir, rel string) {
	r.readFile("", rel, filepath.Join(absDir, ".gitignore"))
}

func (r *ignoreRules) skipDir(name, rel string) bool {
	if _, ok := r.names[strings.ToLower(name)]; ok {
		return true
	}
	return r.ignored(rel, true)
}

func (r *ignoreRules) skipFile(rel string) bool {
	return r.ignored(rel, false)
}

// SkipDirNames lists directory names the discovery walk never enters.
func SkipDirNames() []string {
	names := make([]string, len(defaultSkipDirs))
	copy(names, defaultSkipDirs)
	return names
}

// PathHasSkippedDir reports whether a relative path walks through a directory
// the discovery ignores, such as testdata or node_modules.
func PathHasSkippedDir(path string) bool {
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if part == "" || part == "." {
			continue
		}
		if _, ok := skippedDirNames[strings.ToLower(part)]; ok {
			return true
		}
	}
	return false
}

// ToolExcludeGlobs is the rumdl --exclude value matching SkipDirNames.
func ToolExcludeGlobs() string {
	globs := make([]string, 0, len(defaultSkipDirs))
	for _, name := range defaultSkipDirs {
		globs = append(globs, "**/"+name+"/**")
	}
	return strings.Join(globs, ",")
}

var skippedDirNames = func() map[string]struct{} {
	names := make(map[string]struct{}, len(defaultSkipDirs))
	for _, name := range defaultSkipDirs {
		names[strings.ToLower(name)] = struct{}{}
	}
	return names
}()

func (r *ignoreRules) ignored(rel string, isDir bool) bool {
	rel = strings.TrimPrefix(filepath.ToSlash(rel), "./")
	if rel == "" || rel == "." {
		return false
	}
	ignored := false
	for _, pat := range r.patterns {
		candidate := rel
		if pat.base != "" && pat.base != "." {
			prefix := strings.TrimSuffix(pat.base, "/") + "/"
			if !strings.HasPrefix(rel, prefix) {
				continue
			}
			candidate = strings.TrimPrefix(rel, prefix)
		}
		if pat.matches(candidate, isDir) {
			ignored = !pat.negate
		}
	}
	return ignored
}

func compileGitPattern(line string) (gitPattern, bool) {
	pat := gitPattern{}
	if strings.HasPrefix(line, "!") {
		pat.negate = true
		line = strings.TrimSpace(line[1:])
	}
	if line == "" {
		return pat, false
	}
	if strings.HasSuffix(line, "/") {
		pat.dirOnly = true
		line = strings.TrimSuffix(line, "/")
	}
	if strings.HasPrefix(line, "/") {
		pat.anchored = true
		line = strings.TrimPrefix(line, "/")
	}
	expr := gitPatternToRegexp(line, pat.anchored)
	re, err := regexp.Compile(expr)
	if err != nil {
		return pat, false
	}
	pat.re = re
	return pat, true
}

func gitPatternToRegexp(pattern string, anchored bool) string {
	var b strings.Builder
	b.WriteString("^")
	if !anchored && !strings.Contains(pattern, "/") {
		b.WriteString("(?:.*/)?")
	}
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				if i+2 < len(pattern) && pattern[i+2] == '/' {
					b.WriteString("(?:.*/)?")
					i += 2
					continue
				}
				b.WriteString(".*")
				i++
				continue
			}
			b.WriteString("[^/]*")
		case '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(pattern[i])))
		}
	}
	b.WriteString("(?:/.*)?$")
	return b.String()
}

func (p gitPattern) matches(rel string, isDir bool) bool {
	if p.dirOnly && !isDir {
		return false
	}
	if p.re == nil {
		return false
	}
	return p.re.MatchString(rel)
}
