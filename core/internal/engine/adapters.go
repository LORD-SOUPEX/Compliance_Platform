package engine

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"

	"compliance/internal/report"
)

// ToolAdapter is how the engine reads one tool once it has run. Adding a tool
// means one entry here, one invocation in BuildInvocation and one catalog entry.
type ToolAdapter struct {
	// Parse turns the captured output into located findings.
	Parse func(output, repo string) []report.LocatedLeak
	// ReadsStderr parses stdout followed by stderr (tools that report on stderr).
	ReadsStderr bool
	// Crashed tells a tool that stopped on its own error, with no finding, from a
	// compliance failure: both exit non-zero.
	Crashed func(stderr string) bool
}

var adapters = map[string]ToolAdapter{
	"checkov":               {Parse: parseCheckov},
	"tflint":                {Parse: parseTFLint},
	"shellcheck":            {Parse: parseShellcheck},
	"trivy":                 {Parse: parseTrivy, Crashed: func(stderr string) bool { return strings.Contains(stderr, "FATAL") }},
	"terraform":             {Parse: parseFmtFiles},
	"tofu":                  {Parse: parseFmtFiles},
	"terragrunt":            {Parse: parseTerragruntFmt, ReadsStderr: true, Crashed: terragruntCrashed},
	"shfmt":                 {Parse: parseShfmt},
	"kubeconform":           {Parse: parseKubeconform},
	"Invoke-ScriptAnalyzer": {Parse: parsePSScriptAnalyzer},
	"ruff":                  {Parse: parseRuff},
	"pylint":                {Parse: parsePylint},
	"bandit":                {Parse: parseBandit, ReadsStderr: true},
	"pytest":                {Parse: parsePytest},
	"pip-audit":             {Parse: parsePipAudit, ReadsStderr: true},
	"yamllint":              {Parse: parseYamllint, ReadsStderr: true},
	"hadolint":              {Parse: parseHadolint},
	"eslint":                {Parse: parseESLint},
	"tsc":                   {Parse: parseTSC},
	"biome":                 {Parse: parseSARIF},
	"osv-scanner":           {Parse: parseSARIF, Crashed: func(stderr string) bool { return strings.Contains(stderr, "No package sources found") }},
	"golangci-lint":         {Parse: parseGolangci, ReadsStderr: true, Crashed: golangciCrashed},
	"stylelint":             {Parse: parseStylelint, ReadsStderr: true},
	"htmlhint":              {Parse: parseHTMLHint},
	"rumdl":                 {Parse: parseRumdlOutput},
	"ansible-lint":          {Parse: parseSARIF},
	// Gitleaks writes its findings to --report-path; readGitleaksFindings reads them.
	"gitleaks": {Parse: func(string, string) []report.LocatedLeak { return nil }},
}

// adapterFor returns the adapter of a command, if the engine knows how to read it.
func adapterFor(command string) (ToolAdapter, bool) {
	adapter, ok := adapters[command]
	return adapter, ok && adapter.Parse != nil
}

// parseToolFindings reads a tool output through its adapter.
func parseToolFindings(command, output, repo string) []report.LocatedLeak {
	adapter, ok := adapterFor(command)
	if !ok {
		return nil
	}
	return filterSkipped(adapter.Parse(output, repo))
}

// toolCrashed tells a tool that stopped on its own error from a tool that
// reported findings: both exit non-zero, only the second is a compliance failure.
func toolCrashed(command, stderr string, leaks int) bool {
	if leaks > 0 {
		return false
	}
	adapter, ok := adapters[command]
	return ok && adapter.Crashed != nil && adapter.Crashed(stderr)
}

func terragruntCrashed(stderr string) bool {
	return !strings.Contains(stderr, "needs formatting") && strings.Contains(stderr, "ERROR")
}

func golangciCrashed(stderr string) bool {
	return strings.Contains(stderr, "level=error") && !strings.Contains(stderr, "typechecking error")
}

// parseSARIF reads SARIF 2.1 (Biome, osv-scanner, golangci-lint, Trivy...). It
// decodes every JSON document of the output: a summary may follow the report.
func parseSARIF(output, repo string) []report.LocatedLeak {
	var leaks []report.LocatedLeak
	decodeJSONDocuments(output, func(raw json.RawMessage) {
		var doc struct {
			Runs []struct {
				Results []struct {
					RuleID  string `json:"ruleId"`
					Level   string `json:"level"`
					Message struct {
						Text string `json:"text"`
					} `json:"message"`
					Locations []struct {
						PhysicalLocation struct {
							ArtifactLocation struct {
								URI string `json:"uri"`
							} `json:"artifactLocation"`
							Region struct {
								StartLine   int `json:"startLine"`
								StartColumn int `json:"startColumn"`
							} `json:"region"`
						} `json:"physicalLocation"`
					} `json:"locations"`
				} `json:"results"`
			} `json:"runs"`
		}
		if json.Unmarshal(raw, &doc) != nil {
			return
		}
		for _, run := range doc.Runs {
			for _, result := range run.Results {
				file, line, column := "", 1, 1
				if len(result.Locations) > 0 {
					location := result.Locations[0].PhysicalLocation
					file = sarifPath(location.ArtifactLocation.URI)
					if location.Region.StartLine > 0 {
						line = location.Region.StartLine
					}
					if location.Region.StartColumn > 0 {
						column = location.Region.StartColumn
					}
				}
				if file == "" {
					continue
				}
				leaks = append(leaks, report.LocatedLeak{
					File: relativeToRepo(repo, file), Line: line, Column: column,
					RuleID: result.RuleID, Description: strings.TrimSpace(result.Message.Text), Severity: sarifSeverity(result.Level),
				})
			}
		}
	})
	return leaks
}

// sarifPath turns a SARIF URI into a path: file:///C:/x and file:///home/x on
// every OS, percent-encoded characters decoded, relative URIs kept relative.
func sarifPath(uri string) string {
	uri = strings.TrimSpace(uri)
	if !strings.HasPrefix(strings.ToLower(uri), "file:") {
		if decoded, err := url.PathUnescape(uri); err == nil {
			return decoded
		}
		return uri
	}
	parsed, err := url.Parse(uri)
	if err != nil {
		return strings.TrimPrefix(uri, "file://")
	}
	path := parsed.Path
	if len(path) >= 3 && path[0] == '/' && path[2] == ':' {
		path = path[1:] // /C:/x on Windows
	}
	return path
}

func sarifSeverity(level string) string {
	switch strings.ToLower(level) {
	case "error":
		return "high"
	case "warning":
		return "medium"
	default:
		return "low"
	}
}

var reGoCompileError = regexp.MustCompile(`([^\s"\\]+\.go):(\d+):(\d+): ([^"\\]+)`)

// parseGolangci reads the SARIF report, plus the compile errors golangci-lint
// only logs (typechecking errors stop the analysis of a package).
func parseGolangci(output, repo string) []report.LocatedLeak {
	leaks := parseSARIF(output, repo)
	for _, line := range strings.Split(output, "\n") {
		if !strings.Contains(line, "typechecking error") {
			continue
		}
		for _, match := range reGoCompileError.FindAllStringSubmatch(line, -1) {
			leaks = append(leaks, report.LocatedLeak{
				File: relativeToRepo(repo, match[1]), Line: atoiOr(match[2], 1), Column: atoiOr(match[3], 1),
				RuleID: "typecheck", Description: strings.TrimSpace(match[4]), Severity: "high",
			})
		}
	}
	return dedupeLeaks(leaks)
}

// parseStylelint reads --formatter json (Stylelint 16+ writes it on stderr).
func parseStylelint(output, repo string) []report.LocatedLeak {
	var leaks []report.LocatedLeak
	decodeJSONDocuments(output, func(raw json.RawMessage) {
		var files []struct {
			Source   string `json:"source"`
			Warnings []struct {
				Line     int    `json:"line"`
				Column   int    `json:"column"`
				Rule     string `json:"rule"`
				Severity string `json:"severity"`
				Text     string `json:"text"`
			} `json:"warnings"`
		}
		if json.Unmarshal(raw, &files) != nil {
			return
		}
		for _, file := range files {
			for _, warning := range file.Warnings {
				severity := "low"
				if warning.Severity == "error" {
					severity = "medium"
				}
				leaks = append(leaks, report.LocatedLeak{
					File: relativeToRepo(repo, file.Source), Line: max(warning.Line, 1), Column: max(warning.Column, 1),
					RuleID: warning.Rule, Description: warning.Text, Severity: severity,
				})
			}
		}
	})
	return leaks
}

// parseHTMLHint reads htmlhint --format json.
func parseHTMLHint(output, repo string) []report.LocatedLeak {
	var leaks []report.LocatedLeak
	decodeJSONDocuments(output, func(raw json.RawMessage) {
		var files []struct {
			File     string `json:"file"`
			Messages []struct {
				Type    string `json:"type"`
				Message string `json:"message"`
				Line    int    `json:"line"`
				Col     int    `json:"col"`
				Rule    struct {
					ID string `json:"id"`
				} `json:"rule"`
			} `json:"messages"`
		}
		if json.Unmarshal(raw, &files) != nil {
			return
		}
		for _, file := range files {
			for _, message := range file.Messages {
				severity := "low"
				if message.Type == "error" {
					severity = "medium"
				}
				leaks = append(leaks, report.LocatedLeak{
					File: relativeToRepo(repo, file.File), Line: max(message.Line, 1), Column: max(message.Col, 1),
					RuleID: message.Rule.ID, Description: message.Message, Severity: severity,
				})
			}
		}
	})
	return leaks
}

func atoiOr(value string, fallback int) int {
	number := 0
	for _, r := range value {
		if r < '0' || r > '9' {
			return fallback
		}
		number = number*10 + int(r-'0')
	}
	if number == 0 {
		return fallback
	}
	return number
}
