package server

import "testing"

func TestSkippedWithDiagnosticIsNotSucceeded(t *testing.T) {
	report := map[string]interface{}{
		"execution_status": "completed",
		"execution_results": []interface{}{
			map[string]interface{}{
				"control_id": "ansible/linting/ansible-lint/.",
				"status":     "skipped",
				"diagnostics": []interface{}{
					map[string]interface{}{"code": "technology_absent", "message": "Technologie absente."},
				},
			},
			map[string]interface{}{
				"control_id": "javascript/linting/eslint/.",
				"status":     "skipped",
				"diagnostics": []interface{}{
					map[string]interface{}{"code": "tool_unavailable", "message": "Outil manquant : eslint."},
				},
			},
		},
	}
	items, err := ComputePresentations(report)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, item := range items {
		got[item.ControlID] = item.Status
	}
	if got["ansible/linting/ansible-lint/."] != "Not applicable" {
		t.Fatalf("absent control shown as %s", got["ansible/linting/ansible-lint/."])
	}
	if got["javascript/linting/eslint/."] != "Blocked" {
		t.Fatalf("missing tool shown as %s", got["javascript/linting/eslint/."])
	}
	for _, status := range got {
		if status == "Succeeded" {
			t.Fatal("a non-executed control was presented as Succeeded")
		}
	}
}
