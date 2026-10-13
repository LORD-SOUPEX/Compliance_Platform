package report

import (
	"encoding/json"
	"strings"
)

// NormalizeReport returns a copy of a report with volatile timing, path separators,
// and engine versions standardized to canonical values for strict equality comparison.
func NormalizeReport(rawJSON []byte) (map[string]interface{}, error) {
	var m map[string]interface{}
	if err := json.Unmarshal(rawJSON, &m); err != nil {
		return nil, err
	}

	normalizeMap(m)
	return m, nil
}

func normalizeMap(m map[string]interface{}) {
	for k, v := range m {
		switch k {
		case "generated_at", "execution_start", "execution_end":
			m[k] = "2026-10-13T00:00:00Z"
		case "duration_ms", "discovery_ms", "resolver_ms", "compliance_ms", "reporting_ms":
			m[k] = float64(0)
		case "engine_version":
			m[k] = "CANONICAL_ENGINE_VERSION"
		case "run_id":
			m[k] = "CANONICAL_RUN_ID"
		}

		if str, ok := v.(string); ok {
			// Normalize Windows path separators to forward slash
			if strings.Contains(str, "\\") {
				m[k] = strings.ReplaceAll(str, "\\", "/")
			}
		} else if subMap, ok := v.(map[string]interface{}); ok {
			normalizeMap(subMap)
		} else if list, ok := v.([]interface{}); ok {
			for _, item := range list {
				if itemMap, ok := item.(map[string]interface{}); ok {
					normalizeMap(itemMap)
				}
			}
		}
	}
}

// CompareCanonicalReports compares two canonicalized report maps, returning differences.
func CompareCanonicalReports(rep1, rep2 map[string]interface{}) []string {
	var diffs []string

	// Compare verdict
	v1, _ := rep1["verdict"].(string)
	v2, _ := rep2["verdict"].(string)
	if v1 != v2 {
		diffs = append(diffs, "Verdict mismatch: "+v1+" != "+v2)
	}

	// Compare summary
	s1, _ := rep1["summary"].(map[string]interface{})
	s2, _ := rep2["summary"].(map[string]interface{})
	if s1 != nil && s2 != nil {
		for _, key := range []string{"success", "fail", "error", "skipped"} {
			if s1[key] != s2[key] {
				diffs = append(diffs, "Summary "+key+" mismatch")
			}
		}
	}

	return diffs
}
