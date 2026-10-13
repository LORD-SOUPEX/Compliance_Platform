package matrix

import (
	"path/filepath"
	"testing"

	"compliance/internal/catalog"
	"compliance/internal/discovery"
)

type mockToolResolver struct {
	available map[string]bool
}

func (m *mockToolResolver) ResolveCandidate(name, command string, platform PlatformInfo, repoRoot string) CandidateToolState {
	status := "not_installed"
	if m.available[command] {
		status = "available"
	}
	src := "/bin/" + command
	return CandidateToolState{
		Name:           name,
		Command:        command,
		Status:         status,
		Source:         &src,
		Platform:       platform.ID,
		RuntimeManaged: true,
	}
}

func TestBuildCapabilityMatrixAndResolution(t *testing.T) {
	catPath := filepath.Join("..", "..", "..", ".config", "control-catalog.json")
	cat, err := catalog.LoadCatalog(catPath)
	if err != nil {
		t.Fatalf("LoadCatalog failed: %v", err)
	}

	discoveries := []discovery.TechnologyRecord{
		{Technology: "python", Status: "detected", Roots: []string{"."}, Evidence: []string{"main.py"}, Ambiguities: []string{}},
		{Technology: "terraform", Status: "absent", Roots: []string{}, Evidence: []string{}, Ambiguities: []string{}},
		{Technology: "ansible", Status: "ambiguous", Roots: []string{}, Evidence: []string{}, Ambiguities: []string{"signal ambigu"}},
	}

	platform := PlatformInfo{OS: "windows", Architecture: "x64", ID: "windows-x64"}
	mockResolver := &mockToolResolver{
		available: map[string]bool{
			"ruff":   true,
			"bandit": true,
		},
	}

	mat := BuildCapabilityMatrix(discoveries, cat, platform, mockResolver, ".")
	if len(mat) != 3 {
		t.Fatalf("expected 3 entries in capability matrix, got %d", len(mat))
	}

	// Python entry
	pyEntry := mat[0]
	if pyEntry.Technology != "python" || pyEntry.TechnologyStatus != "detected" {
		t.Errorf("unexpected python entry: %+v", pyEntry)
	}
	if len(pyEntry.RequiredCapabilities) == 0 {
		t.Errorf("expected required capabilities for detected python")
	}

	// Terraform entry (absent)
	tfEntry := mat[1]
	for _, cap := range tfEntry.Capabilities {
		if cap.Availability != "not_applicable" {
			t.Errorf("expected absent technology capability to be not_applicable, got %s", cap.Availability)
		}
	}

	// Ansible entry (ambiguous)
	ansEntry := mat[2]
	for _, cap := range ansEntry.Capabilities {
		if cap.Availability != "ambiguous" {
			t.Errorf("expected ambiguous technology capability to be ambiguous, got %s", cap.Availability)
		}
	}

	// Resolve capability tools
	resolutions := ResolveCapabilityTools(mat)
	if len(resolutions) != 3 {
		t.Fatalf("expected 3 entries in tool resolution, got %d", len(resolutions))
	}

	pyRes := resolutions[0]
	if pyRes.Technology != "python" {
		t.Errorf("expected python resolution, got %s", pyRes.Technology)
	}
	// With ruff and bandit available, but pylint/pytest/pip-audit not available:
	if len(pyRes.SelectedTools) == 0 {
		t.Errorf("expected selected tools for python, got 0")
	}
	if pyRes.Status != "partial" {
		t.Errorf("expected partial status for python, got %s", pyRes.Status)
	}

	tfRes := resolutions[1]
	if tfRes.Status != "absent" {
		t.Errorf("expected absent status for terraform, got %s", tfRes.Status)
	}

	ansRes := resolutions[2]
	if ansRes.Status != "ambiguous" {
		t.Errorf("expected ambiguous status for ansible, got %s", ansRes.Status)
	}
}
