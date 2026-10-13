package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"compliance/internal/osutil"
)

var (
	reVersionFinder = regexp.MustCompile(`\b\d+\.\d+(?:\.\d+)?(?:[a-zA-Z0-9.+-]*)`)

	// Default sensitive patterns to redact if enabled
	defaultRedactionPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:ghp|glpat)_[a-zA-Z0-9]{20,}`),
		regexp.MustCompile(`(?i)(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}`),
		regexp.MustCompile(`-----BEGIN [A-Z ]+PRIVATE KEY-----`),
	}
)

// Redactor handles string sanitization.
type Redactor struct {
	Patterns    []*regexp.Regexp
	Replacement string
}

// NewRedactor creates a Redactor from pattern strings.
func NewRedactor(patterns []string, replacement string) (*Redactor, error) {
	if replacement == "" {
		replacement = "[REDACTED]"
	}
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pat := range patterns {
		if strings.TrimSpace(pat) == "" {
			continue
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("motif de masquage regex invalide: %s: %w", pat, err)
		}
		compiled = append(compiled, re)
	}
	return &Redactor{
		Patterns:    compiled,
		Replacement: replacement,
	}, nil
}

// Redact sanitizes text by replacing matches of all configured patterns.
func (r *Redactor) Redact(text string) string {
	if r == nil || len(r.Patterns) == 0 {
		return text
	}
	res := text
	for _, re := range r.Patterns {
		res = re.ReplaceAllString(res, r.Replacement)
	}
	return res
}

// Invocation represents the command line execution details for a control.
type Invocation struct {
	Executable string   `json:"executable"`
	Arguments  []string `json:"arguments"`
}

// BuildInvocation constructs the executable and arguments for a planned control.
func BuildInvocation(
	ctrl *PlannedControl,
	root string,
	platformRoot string,
	repoRoot string,
) (*Invocation, error) {
	if ctrl.Tool == nil || ctrl.Tool.Source == nil || *ctrl.Tool.Source == "" {
		return nil, errors.New("source executable absente du plan")
	}

	executable := *ctrl.Tool.Source
	command := ctrl.Tool.Command

	var catalogArgs []string
	if ctrl.Parameters != nil {
		if rawArgs, ok := ctrl.Parameters["arguments"]; ok {
			if argsSlice, ok := rawArgs.([]interface{}); ok {
				for _, a := range argsSlice {
					catalogArgs = append(catalogArgs, fmt.Sprintf("%v", a))
				}
			} else if argsStrSlice, ok := rawArgs.([]string); ok {
				catalogArgs = append(catalogArgs, argsStrSlice...)
			}
		}
	}

	// Filter files belonging to this root
	var filesInRoot []string
	prefix := filepath.Clean(root) + string(filepath.Separator)
	for _, rel := range ctrl.Files {
		full := filepath.Join(repoRoot, filepath.FromSlash(rel))
		if strings.EqualFold(filepath.Clean(root), repoRoot) || strings.HasPrefix(strings.ToLower(full), strings.ToLower(prefix)) {
			filesInRoot = append(filesInRoot, full)
		}
	}

	var arguments []string

	switch command {
	case "ruff":
		var pyFiles []string
		for _, f := range filesInRoot {
			if strings.EqualFold(filepath.Ext(f), ".py") {
				pyFiles = append(pyFiles, f)
			}
		}
		if len(pyFiles) == 0 {
			return nil, errors.New("aucune source Python pour Ruff")
		}
		if len(catalogArgs) == 0 {
			return nil, errors.New("arguments Ruff absents du catalogue")
		}
		arguments = append(arguments, catalogArgs...)
		arguments = append(arguments, pyFiles...)

	case "pylint", "bandit":
		var pyFiles []string
		for _, f := range filesInRoot {
			if strings.EqualFold(filepath.Ext(f), ".py") {
				pyFiles = append(pyFiles, f)
			}
		}
		if len(pyFiles) == 0 {
			return nil, fmt.Errorf("aucune source Python pour %s", command)
		}
		arguments = append(arguments, catalogArgs...)
		arguments = append(arguments, pyFiles...)

	case "pytest":
		arguments = append(arguments, catalogArgs...)
		arguments = append(arguments, root)

	case "pip-audit":
		reqPath := filepath.Join(root, "requirements.txt")
		if _, err := os.Stat(reqPath); err != nil {
			return nil, errors.New("audit consommateur: requirements.txt requis; le runtime de la plateforme n est pas audite a sa place")
		}
		arguments = append(arguments, catalogArgs...)
		arguments = append(arguments, "-r", reqPath)

	case "terraform", "tofu", "terragrunt", "tflint":
		arguments = append(arguments, catalogArgs...)

	case "shellcheck":
		var shFiles []string
		for _, f := range filesInRoot {
			if strings.EqualFold(filepath.Ext(f), ".sh") {
				shFiles = append(shFiles, f)
			}
		}
		if len(shFiles) == 0 {
			return nil, errors.New("aucun script Shell pour ShellCheck")
		}
		arguments = append(arguments, catalogArgs...)
		arguments = append(arguments, shFiles...)

	case "hadolint":
		var containerFiles []string
		for _, f := range filesInRoot {
			base := filepath.Base(f)
			if strings.HasPrefix(strings.ToLower(base), "dockerfile") || strings.HasPrefix(strings.ToLower(base), "containerfile") {
				containerFiles = append(containerFiles, f)
			}
		}
		if len(containerFiles) == 0 {
			return nil, errors.New("validation Compose non implementee par Hadolint")
		}
		arguments = containerFiles

	case "ansible-lint":
		arguments = append(arguments, catalogArgs...)
		arguments = append(arguments, root)

	case "yamllint":
		cfg, _ := ctrl.Parameters["configuration"].(string)
		if cfg == "" {
			cfg = ".yamllint.yml"
		}
		arguments = []string{"-c", filepath.Join(platformRoot, cfg), root}

	case "pre-commit":
		hook, _ := ctrl.Parameters["hook"].(string)
		var mdFiles []string
		for _, f := range filesInRoot {
			if strings.EqualFold(filepath.Ext(f), ".md") {
				mdFiles = append(mdFiles, f)
			}
		}
		if len(mdFiles) == 0 {
			return nil, errors.New("aucun fichier Markdown pour le controle")
		}
		arguments = append([]string{"run", hook, "--config", filepath.Join(platformRoot, ".pre-commit-config.yaml"), "--files"}, mdFiles...)

	case "checkov":
		framework, _ := ctrl.Parameters["framework"].(string)
		if framework == "" {
			return nil, errors.New("framework Checkov absent du catalogue")
		}
		arguments = []string{"-d", root, "--framework", framework, "--quiet"}
		if strings.EqualFold(filepath.Ext(executable), ".cmd") {
			arguments = append([]string{"-x", executable}, arguments...)
			executable = filepath.Join(platformRoot, ".venv", "Scripts", "python.exe")
		}

	case "trivy":
		var scanners []string
		if rawScanners, ok := ctrl.Parameters["scanners"].([]interface{}); ok {
			for _, s := range rawScanners {
				scanners = append(scanners, fmt.Sprintf("%v", s))
			}
		} else if strScanners, ok := ctrl.Parameters["scanners"].([]string); ok {
			scanners = strScanners
		}
		arguments = []string{
			"fs",
			"--scanners", strings.Join(scanners, ","),
			"--exit-code", "1",
			"--no-progress",
			"--skip-dirs", ".git",
			"--skip-dirs", ".venv",
			"--skip-dirs", ".tools",
			"--skip-dirs", "reports",
			root,
		}

	case "Invoke-ScriptAnalyzer":
		if len(filesInRoot) == 0 {
			return nil, errors.New("aucun fichier PowerShell pour le controle")
		}
		filesJSON, _ := json.Marshal(filesInRoot)
		settings, _ := ctrl.Parameters["settings"].(string)
		arguments = []string{
			"-NoProfile",
			"-ExecutionPolicy", "Bypass",
			"-File", filepath.Join(platformRoot, "scripts", "invoke-compliance-powershell.ps1"),
			"-ModulePath", executable,
			"-SettingsPath", filepath.Join(platformRoot, settings),
			"-FilesJson", string(filesJSON),
		}
		executable = "powershell.exe"

	default:
		return nil, fmt.Errorf("adaptateur de controle non implemente: %s", command)
	}

	return &Invocation{
		Executable: executable,
		Arguments:  arguments,
	}, nil
}

// ProbeToolVersion runs the version command of a tool and returns the parsed version string.
func ProbeToolVersion(
	ctx context.Context,
	executable string,
	command string,
	dir string,
	timeout time.Duration,
) (string, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	args := []string{"--version"}
	if command == "terraform" || command == "tofu" || command == "opentofu" {
		args = []string{"version"}
	}

	res, err := osutil.RunBounded(ctx, osutil.CommandSpec{
		Executable:       executable,
		Args:             args,
		WorkingDirectory: dir,
		Limits: osutil.ProcessLimits{
			Timeout:        timeout,
			MaxOutputBytes: 64 * 1024,
		},
	})
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("probe exit code %d: %s", res.ExitCode, res.Stderr)
	}

	out := res.Stdout + " " + res.Stderr
	match := reVersionFinder.FindString(out)
	if match == "" {
		return "", errors.New("version de l outil non identifiable")
	}
	return match, nil
}
