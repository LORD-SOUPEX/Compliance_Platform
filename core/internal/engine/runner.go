package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"compliance/internal/discovery"
	"compliance/internal/report"
)

// rumdlLine matches "fichier:ligne:colonne: [MD032] message", including a Windows drive letter.
var rumdlLine = regexp.MustCompile(`^(.+):(\d+):(\d+):\s*\[([A-Z0-9]+)\]\s*(.*)$`)

func parseRumdlOutput(stdout, repo string) []report.LocatedLeak {
	var leaks []report.LocatedLeak
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		match := rumdlLine.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		lineNo, errLine := strconv.Atoi(match[2])
		column, errColumn := strconv.Atoi(match[3])
		if errLine != nil || errColumn != nil || lineNo < 1 {
			continue
		}
		file := relativeToRepo(repo, match[1])
		if discovery.PathHasSkippedDir(file) {
			continue
		}
		leaks = append(leaks, report.LocatedLeak{
			File:        file,
			Line:        lineNo,
			Column:      column,
			RuleID:      match[4],
			Description: match[5],
			Severity:    "low",
		})
	}
	return leaks
}

func markdownConfigPresent(repo string) bool {
	names := []string{".rumdl.toml", "rumdl.toml", ".markdownlint.json", ".markdownlint.jsonc", ".markdownlint.yaml", ".markdownlint.yml", ".markdownlintrc"}
	for _, name := range names {
		if info, err := os.Stat(filepath.Join(repo, name)); err == nil && !info.IsDir() {
			return true
		}
	}
	body, err := os.ReadFile(filepath.Join(repo, "pyproject.toml"))
	return err == nil && strings.Contains(strings.ToLower(string(body)), "rumdl")
}

func parseToolFindings(command, stdout, repo string) []report.LocatedLeak {
	var leaks []report.LocatedLeak
	switch command {
	case "checkov":
		leaks = parseCheckov(stdout, repo)
	case "tflint":
		leaks = parseTFLint(stdout, repo)
	case "shellcheck":
		leaks = parseShellcheck(stdout, repo)
	case "trivy":
		leaks = parseTrivy(stdout, repo)
	case "terraform", "tofu":
		leaks = parseFmtFiles(stdout, repo)
	case "ruff":
		leaks = parseRuff(stdout, repo)
	case "pylint":
		leaks = parsePylint(stdout, repo)
	case "bandit":
		leaks = parseBandit(stdout, repo)
	case "pytest":
		leaks = parsePytest(stdout, repo)
	case "pip-audit":
		leaks = parsePipAudit(stdout, repo)
	case "yamllint":
		leaks = parseYamllint(stdout, repo)
	default:
		return nil
	}
	return filterSkipped(leaks)
}

func filterSkipped(leaks []report.LocatedLeak) []report.LocatedLeak {
	kept := leaks[:0]
	for _, leak := range leaks {
		if leak.File != "" && discovery.PathHasSkippedDir(leak.File) {
			continue
		}
		kept = append(kept, leak)
	}
	return kept
}

func parseCheckov(stdout, repo string) []report.LocatedLeak {
	var payload interface{}
	if json.Unmarshal([]byte(strings.TrimSpace(stdout)), &payload) == nil {
		var leaks []report.LocatedLeak
		collectCheckov(payload, repo, &leaks)
		if len(leaks) > 0 {
			return leaks
		}
	}
	return parseCheckovText(stdout, repo)
}

func collectCheckov(node interface{}, repo string, leaks *[]report.LocatedLeak) {
	switch value := node.(type) {
	case map[string]interface{}:
		if raw, ok := value["failed_checks"].([]interface{}); ok {
			for _, item := range raw {
				if leak, ok := checkovCheck(item, repo); ok {
					*leaks = append(*leaks, leak)
				}
			}
		}
		for key, child := range value {
			if key == "failed_checks" {
				continue
			}
			collectCheckov(child, repo, leaks)
		}
	case []interface{}:
		for _, child := range value {
			collectCheckov(child, repo, leaks)
		}
	}
}

func checkovCheck(node interface{}, repo string) (report.LocatedLeak, bool) {
	record, ok := node.(map[string]interface{})
	if !ok {
		return report.LocatedLeak{}, false
	}
	rule := jsonString(record["check_id"])
	if rule == "" {
		return report.LocatedLeak{}, false
	}
	name := jsonString(record["check_name"])
	resource := jsonString(record["resource"])
	message := name
	if resource != "" {
		if message != "" {
			message += " — "
		}
		message += resource
	}
	file := jsonString(record["file_path"])
	if file == "" {
		file = jsonString(record["file_abs_path"])
	}
	line := 1
	if span, ok := record["file_line_range"].([]interface{}); ok && len(span) > 0 {
		if parsed := jsonInt(span[0]); parsed > 0 {
			line = parsed
		}
	}
	return report.LocatedLeak{
		File: relativeToRepo(repo, file), Line: line, Column: 1,
		RuleID: rule, Description: message, Severity: "high",
	}, true
}

var checkovText = regexp.MustCompile(`(?m)^Check: ([A-Z0-9_]+): "?([^"\r\n]*)"?`)
var checkovFile = regexp.MustCompile(`(?m)^\s*File:\s*(.+?):(\d+)`)

func parseCheckovText(stdout, repo string) []report.LocatedLeak {
	checks := checkovText.FindAllStringSubmatchIndex(stdout, -1)
	var leaks []report.LocatedLeak
	for index, match := range checks {
		end := len(stdout)
		if index+1 < len(checks) {
			end = checks[index+1][0]
		}
		block := stdout[match[0]:end]
		fileMatch := checkovFile.FindStringSubmatch(block)
		file, line := "", 1
		if fileMatch != nil {
			file = fileMatch[1]
			if parsed, err := strconv.Atoi(fileMatch[2]); err == nil && parsed > 0 {
				line = parsed
			}
		}
		leaks = append(leaks, report.LocatedLeak{
			File: relativeToRepo(repo, file), Line: line, Column: 1,
			RuleID: stdout[match[2]:match[3]], Description: strings.Trim(stdout[match[4]:match[5]], `"`), Severity: "high",
		})
	}
	return leaks
}

func parseTFLint(stdout, repo string) []report.LocatedLeak {
	var document struct {
		Issues []struct {
			Message string `json:"message"`
			Rule    struct {
				Name string `json:"name"`
			} `json:"rule"`
			Range struct {
				Filename string `json:"filename"`
				Start    struct {
					Line int `json:"line"`
				} `json:"start"`
			} `json:"range"`
		} `json:"issues"`
	}
	if json.Unmarshal([]byte(strings.TrimSpace(stdout)), &document) == nil && len(document.Issues) > 0 {
		leaks := make([]report.LocatedLeak, 0, len(document.Issues))
		for _, issue := range document.Issues {
			line := issue.Range.Start.Line
			if line < 1 {
				line = 1
			}
			leaks = append(leaks, report.LocatedLeak{
				File: relativeToRepo(repo, issue.Range.Filename), Line: line, Column: 1,
				RuleID: issue.Rule.Name, Description: issue.Message, Severity: "medium",
			})
		}
		return leaks
	}
	linePattern := regexp.MustCompile(`(?m)^(.+):(\d+):\d+:\s*(.+)`)
	var leaks []report.LocatedLeak
	for _, match := range linePattern.FindAllStringSubmatch(stdout, -1) {
		line, _ := strconv.Atoi(match[2])
		if line < 1 {
			continue
		}
		leaks = append(leaks, report.LocatedLeak{
			File: relativeToRepo(repo, match[1]), Line: line, Column: 1,
			RuleID: "tflint", Description: match[3], Severity: "medium",
		})
	}
	return leaks
}

func parseShellcheck(stdout, repo string) []report.LocatedLeak {
	type row struct {
		File    string `json:"file"`
		Line    int    `json:"line"`
		Column  int    `json:"column"`
		Code    int    `json:"code"`
		Level   string `json:"level"`
		Message string `json:"message"`
	}
	var leaks []report.LocatedLeak
	decoded := false
	dec := json.NewDecoder(strings.NewReader(stdout))
	for {
		var rows []row
		if err := dec.Decode(&rows); err != nil {
			break
		}
		decoded = true
		for _, item := range rows {
			line := item.Line
			if line < 1 {
				line = 1
			}
			leaks = append(leaks, report.LocatedLeak{
				File: relativeToRepo(repo, item.File), Line: line, Column: item.Column,
				RuleID: "SC" + strconv.Itoa(item.Code), Description: item.Message, Severity: shellcheckSeverity(item.Level),
			})
		}
	}
	if decoded {
		return leaks
	}
	linePattern := regexp.MustCompile(`(?m)^(.+):(\d+):\d+:\s*\w+:\s*(.+?)\s*\[(SC\d+)\]`)
	for _, match := range linePattern.FindAllStringSubmatch(stdout, -1) {
		line, _ := strconv.Atoi(match[2])
		leaks = append(leaks, report.LocatedLeak{
			File: relativeToRepo(repo, match[1]), Line: line, Column: 1,
			RuleID: match[4], Description: match[3], Severity: "medium",
		})
	}
	return leaks
}

func shellcheckSeverity(level string) string {
	switch strings.ToLower(level) {
	case "error":
		return "high"
	case "warning":
		return "medium"
	default:
		return "low"
	}
}

func parseTrivy(stdout, repo string) []report.LocatedLeak {
	var document struct {
		Results []struct {
			Target            string `json:"Target"`
			Misconfigurations []struct {
				ID            string `json:"ID"`
				Title         string `json:"Title"`
				Description   string `json:"Description"`
				Severity      string `json:"Severity"`
				CauseMetadata struct {
					StartLine int `json:"StartLine"`
				} `json:"CauseMetadata"`
			} `json:"Misconfigurations"`
			Vulnerabilities []struct {
				VulnerabilityID string `json:"VulnerabilityID"`
				Title           string `json:"Title"`
				PkgName         string `json:"PkgName"`
				Severity        string `json:"Severity"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &document); err != nil {
		return nil
	}
	var leaks []report.LocatedLeak
	for _, result := range document.Results {
		for _, item := range result.Misconfigurations {
			line := item.CauseMetadata.StartLine
			if line < 1 {
				line = 1
			}
			message := item.Title
			if item.Description != "" && item.Description != item.Title {
				message = strings.TrimSpace(item.Title + " — " + item.Description)
			}
			leaks = append(leaks, report.LocatedLeak{
				File: relativeToRepo(repo, result.Target), Line: line, Column: 1,
				RuleID: item.ID, Description: message, Severity: strings.ToLower(item.Severity),
			})
		}
		for _, item := range result.Vulnerabilities {
			message := item.Title
			if item.PkgName != "" {
				message = strings.TrimSpace(item.PkgName + " — " + item.Title)
			}
			leaks = append(leaks, report.LocatedLeak{
				File: relativeToRepo(repo, result.Target), Line: 1, Column: 1,
				RuleID: item.VulnerabilityID, Description: message, Severity: strings.ToLower(item.Severity),
			})
		}
	}
	return leaks
}

func parseFmtFiles(stdout, repo string) []report.LocatedLeak {
	var leaks []report.LocatedLeak
	seen := map[string]bool{}
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" || strings.HasPrefix(line, "---") || strings.HasPrefix(line, "+++") || strings.HasPrefix(line, "@@") || strings.HasPrefix(line, "+") || strings.HasPrefix(line, "-") {
			continue
		}
		if !strings.Contains(strings.ToLower(line), ".tf") {
			continue
		}
		file := relativeToRepo(repo, line)
		if seen[file] {
			continue
		}
		seen[file] = true
		leaks = append(leaks, report.LocatedLeak{
			File: file, Line: 1, Column: 1, RuleID: "fmt", Description: "Le formatage du fichier diffère de terraform fmt.", Severity: "low",
		})
	}
	return leaks
}

func jsonString(value interface{}) string {
	text, _ := value.(string)
	return strings.TrimSpace(text)
}

func jsonInt(value interface{}) int {
	switch typed := value.(type) {
	case float64:
		return int(typed)
	case json.Number:
		parsed, _ := typed.Int64()
		return int(parsed)
	case string:
		parsed, _ := strconv.Atoi(typed)
		return parsed
	default:
		return 0
	}
}

func decodeJSONDocuments(stdout string, consume func(json.RawMessage)) bool {
	dec := json.NewDecoder(strings.NewReader(stdout))
	decoded := false
	for {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return decoded
		}
		decoded = true
		consume(raw)
	}
}

func parseRuff(stdout, repo string) []report.LocatedLeak {
	var leaks []report.LocatedLeak
	if decodeJSONDocuments(stdout, func(raw json.RawMessage) {
		var rows []struct {
			Filename string `json:"filename"`
			Code     string `json:"code"`
			Message  string `json:"message"`
			Location struct {
				Row    int `json:"row"`
				Column int `json:"column"`
			} `json:"location"`
		}
		if json.Unmarshal(raw, &rows) != nil {
			return
		}
		for _, row := range rows {
			line := row.Location.Row
			if line < 1 {
				line = 1
			}
			column := row.Location.Column
			if column < 1 {
				column = 1
			}
			leaks = append(leaks, report.LocatedLeak{
				File: relativeToRepo(repo, row.Filename), Line: line, Column: column,
				RuleID: row.Code, Description: row.Message, Severity: "medium",
			})
		}
	}) {
		return leaks
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimRight(line, "\r"), "Would reformat:"))
		line = strings.TrimSpace(line)
		if !strings.Contains(strings.ToLower(line), ".py") || strings.Contains(line, " ") {
			continue
		}
		file := relativeToRepo(repo, line)
		if seen[file] {
			continue
		}
		seen[file] = true
		leaks = append(leaks, report.LocatedLeak{
			File: file, Line: 1, Column: 1, RuleID: "format", Description: "Le formatage du fichier diffère de ruff format.", Severity: "low",
		})
	}
	return leaks
}

func parsePylint(stdout, repo string) []report.LocatedLeak {
	var leaks []report.LocatedLeak
	if decodeJSONDocuments(stdout, func(raw json.RawMessage) {
		var rows []struct {
			Path      string `json:"path"`
			Line      int    `json:"line"`
			Column    int    `json:"column"`
			Message   string `json:"message"`
			MessageID string `json:"message-id"`
			Symbol    string `json:"symbol"`
			Type      string `json:"type"`
		}
		if json.Unmarshal(raw, &rows) != nil {
			return
		}
		for _, row := range rows {
			line := row.Line
			if line < 1 {
				line = 1
			}
			column := row.Column + 1
			if column < 1 {
				column = 1
			}
			rule := row.MessageID
			if rule == "" {
				rule = row.Symbol
			}
			leaks = append(leaks, report.LocatedLeak{
				File: relativeToRepo(repo, row.Path), Line: line, Column: column,
				RuleID: rule, Description: row.Message, Severity: pylintSeverity(row.Type),
			})
		}
	}) {
		return leaks
	}
	pattern := regexp.MustCompile(`(?m)^(.+):(\d+):(\d+):\s+([A-Z]\d+):\s+(.+)$`)
	for _, match := range pattern.FindAllStringSubmatch(stdout, -1) {
		line, _ := strconv.Atoi(match[2])
		column, _ := strconv.Atoi(match[3])
		if line < 1 {
			continue
		}
		leaks = append(leaks, report.LocatedLeak{
			File: relativeToRepo(repo, match[1]), Line: line, Column: column,
			RuleID: match[4], Description: match[5], Severity: "medium",
		})
	}
	return leaks
}

func pylintSeverity(kind string) string {
	switch strings.ToLower(kind) {
	case "error", "fatal":
		return "high"
	case "warning":
		return "medium"
	default:
		return "low"
	}
}

func parseBandit(stdout, repo string) []report.LocatedLeak {
	var leaks []report.LocatedLeak
	decodeJSONDocuments(stdout, func(raw json.RawMessage) {
		var document struct {
			Results []struct {
				Filename  string `json:"filename"`
				Line      int    `json:"line_number"`
				TestID    string `json:"test_id"`
				IssueText string `json:"issue_text"`
				Severity  string `json:"issue_severity"`
			} `json:"results"`
		}
		if json.Unmarshal(raw, &document) != nil {
			return
		}
		for _, row := range document.Results {
			line := row.Line
			if line < 1 {
				line = 1
			}
			leaks = append(leaks, report.LocatedLeak{
				File: relativeToRepo(repo, row.Filename), Line: line, Column: 1,
				RuleID: row.TestID, Description: row.IssueText, Severity: strings.ToLower(row.Severity),
			})
		}
	})
	return leaks
}

func parsePytest(stdout, repo string) []report.LocatedLeak {
	var leaks []report.LocatedLeak
	seen := map[string]bool{}
	add := func(file string, line int, rule, message string) {
		if line < 1 {
			line = 1
		}
		key := file + ":" + strconv.Itoa(line) + ":" + message
		if seen[key] {
			return
		}
		seen[key] = true
		leaks = append(leaks, report.LocatedLeak{
			File: relativeToRepo(repo, file), Line: line, Column: 1,
			RuleID: rule, Description: message, Severity: "high",
		})
	}
	located := regexp.MustCompile(`(?m)^(.+\.py):(\d+):\s+(.+)$`)
	for _, match := range located.FindAllStringSubmatch(stdout, -1) {
		line, _ := strconv.Atoi(match[2])
		add(match[1], line, "pytest", match[3])
	}
	failed := regexp.MustCompile(`(?m)^FAILED\s+(\S+?\.py)::(\S+)\s+-\s+(.+)$`)
	for _, match := range failed.FindAllStringSubmatch(stdout, -1) {
		add(match[1], 1, match[2], match[3])
	}
	return leaks
}

func parsePipAudit(stdout, repo string) []report.LocatedLeak {
	var leaks []report.LocatedLeak
	decodeJSONDocuments(stdout, func(raw json.RawMessage) {
		var document struct {
			Dependencies []struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				Vulns   []struct {
					ID          string   `json:"id"`
					Description string   `json:"description"`
					FixVersions []string `json:"fix_versions"`
				} `json:"vulns"`
			} `json:"dependencies"`
		}
		if json.Unmarshal(raw, &document) != nil {
			return
		}
		for _, dep := range document.Dependencies {
			for _, vuln := range dep.Vulns {
				message := strings.TrimSpace(dep.Name + " " + dep.Version + " — " + vuln.Description)
				if len(vuln.FixVersions) > 0 {
					message = strings.TrimSpace(message + " Correctif : " + strings.Join(vuln.FixVersions, ", "))
				}
				leaks = append(leaks, report.LocatedLeak{
					File: relativeToRepo(repo, "requirements.txt"), Line: 1, Column: 1,
					RuleID: vuln.ID, Description: message, Severity: "high",
				})
			}
		}
	})
	return leaks
}

func parseYamllint(stdout, repo string) []report.LocatedLeak {
	var leaks []report.LocatedLeak
	pattern := regexp.MustCompile(`(?m)^(.+?):(\d+):(\d+):\s+\[(\w+)\]\s+(.+?)\s+\(([^)]+)\)\s*$`)
	for _, match := range pattern.FindAllStringSubmatch(stdout, -1) {
		line, _ := strconv.Atoi(match[2])
		column, _ := strconv.Atoi(match[3])
		if line < 1 {
			continue
		}
		leaks = append(leaks, report.LocatedLeak{
			File: relativeToRepo(repo, match[1]), Line: line, Column: column,
			RuleID: match[6], Description: match[5], Severity: yamllintSeverity(match[4]),
		})
	}
	return leaks
}

func yamllintSeverity(level string) string {
	if strings.EqualFold(level, "error") {
		return "high"
	}
	return "low"
}
