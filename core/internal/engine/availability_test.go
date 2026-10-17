package engine

import (
	"strings"
	"testing"

	"compliance/internal/matrix"
)

func TestProbeFailureIsNotInstallable(t *testing.T) {
	applicability, code, reason := refineUnavailableTool(
		"tool_unavailable", "tool_unavailable", "",
		"checkov", "windows-x64",
		&matrix.CandidateToolState{Status: "runtime_error", Command: "checkov", Reason: "Traceback (most recent call last): checkov import failed"},
	)
	if applicability != "probe_failed" || code != "probe_failed" || !strings.Contains(reason, "Traceback") || strings.Contains(reason, "installable") {
		t.Fatalf("checkov probe = %s %s %s", applicability, code, reason)
	}

	applicability, code, reason = refineUnavailableTool(
		"tool_unavailable", "tool_unavailable", "",
		"trivy", "windows-x64",
		&matrix.CandidateToolState{Status: "runtime_error", Command: "trivy", Reason: "Qualification d'execution impossible: exit status 1 (stdout: aucune sortie ; stderr: aucune sortie ; binaire: C:/trivy.exe)"},
	)
	if code != "probe_failed" || !strings.Contains(reason, "aucune sortie") || strings.Contains(reason, "installable") {
		t.Fatalf("trivy probe = %s %s", code, reason)
	}

	applicability, code, reason = refineUnavailableTool(
		"tool_unavailable", "tool_unavailable", "",
		"trivy", "windows-x64",
		&matrix.CandidateToolState{Status: "not_installed", Command: "trivy"},
	)
	if applicability != "tool_unavailable" || code != "tool_unavailable" || !strings.Contains(reason, "Outil installable depuis le manifeste : trivy.") {
		t.Fatalf("absent trivy = %s %s %s", applicability, code, reason)
	}
}
