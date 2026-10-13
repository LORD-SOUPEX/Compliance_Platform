package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
)

// ControlApplicability specifies which technology status and evidence extensions match a control.
type ControlApplicability struct {
	TechnologyStatus   []string `json:"technology_status"`
	EvidenceExtensions []string `json:"evidence_extensions"`
}

// CatalogTool defines the tool identity for a control.
type CatalogTool struct {
	Name    string `json:"name"`
	Command string `json:"command"`
}

// CatalogControl represents a single control definition from .config/control-catalog.json.
type CatalogControl struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	Objective        string                 `json:"objective"`
	Technology       string                 `json:"technology"`
	Capability       string                 `json:"capability"`
	Tool             *CatalogTool           `json:"tool"`
	Severity         string                 `json:"severity"`           // low, medium, high, critical
	SelectionPolicy  string                 `json:"selection_policy"`    // all, alternative
	Applicability    ControlApplicability   `json:"applicability"`
	Parameters       map[string]interface{} `json:"parameters"`
	Dependencies     []string               `json:"dependencies"`
	TimeoutSeconds   int                    `json:"timeout_seconds"`
	Cost             string                 `json:"cost"`                // low, medium, high
	SideEffectLevel  string                 `json:"side_effect_level"`   // read_only, code_execution, network, network_code_execution
	Permissions      []string               `json:"permissions"`
	PlatformSupport  []string               `json:"platform_support"`
	Limitations      []string               `json:"limitations"`
}

// ControlCatalog contains all controls and the catalog checksum.
type ControlCatalog struct {
	SchemaVersion int              `json:"schema_version"`
	Controls      []CatalogControl `json:"controls"`
	ContentSHA256 string           `json:"content_sha256,omitempty"`
}

// CandidateToolDefinition provides tool metadata for capability profiles.
type CandidateToolDefinition struct {
	Name            string                 `json:"name"`
	Command         string                 `json:"command"`
	CatalogID       string                 `json:"catalog_id"`
	Severity        string                 `json:"severity"`
	SideEffectLevel string                 `json:"side_effect_level"`
	Permissions     []string               `json:"permissions"`
	TimeoutSeconds  int                    `json:"timeout_seconds"`
	Cost            string                 `json:"cost"`
	Parameters      map[string]interface{} `json:"parameters"`
	Dependencies    []string               `json:"dependencies"`
	Limitations     []string               `json:"limitations"`
	PlatformSupport []string               `json:"platform_support"`
}

// CapabilityProfile groups controls by capability for a technology.
type CapabilityProfile struct {
	Name            string                    `json:"name"`
	SelectionPolicy string                    `json:"selection_policy"`
	Controls        []CatalogControl          `json:"controls"`
	Tools           []CandidateToolDefinition `json:"tools"`
}

// LoadCatalog reads, validates, and hashes .config/control-catalog.json.
func LoadCatalog(path string) (*ControlCatalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("lecture du catalogue de contrôles impossible (%s): %w", path, err)
	}

	// Strip potential UTF-8 BOM
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		data = data[3:]
	}

	h := sha256.Sum256(data)
	contentSHA256 := hex.EncodeToString(h[:])

	var cat ControlCatalog
	if err := json.Unmarshal(data, &cat); err != nil {
		return nil, fmt.Errorf("désérialisation du catalogue de contrôles: %w", err)
	}

	if cat.SchemaVersion != 1 || len(cat.Controls) == 0 {
		return nil, errors.New("schéma Control Catalog invalide (schema_version != 1 ou controls vide)")
	}

	cat.ContentSHA256 = contentSHA256

	// Validate IDs and cycles
	ids := make(map[string]*CatalogControl)
	for i := range cat.Controls {
		c := &cat.Controls[i]
		if c.ID == "" || c.Name == "" || c.Technology == "" || c.Capability == "" {
			return nil, fmt.Errorf("contrôle avec identité incomplète: %+v", c)
		}
		if _, exists := ids[c.ID]; exists {
			return nil, fmt.Errorf("identifiant de contrôle en doublon: %s", c.ID)
		}
		ids[c.ID] = c
	}

	// Check dependencies exist
	for _, c := range cat.Controls {
		for _, dep := range c.Dependencies {
			if _, exists := ids[dep]; !exists {
				return nil, fmt.Errorf("dépendance de contrôle introuvable: %s pour %s", dep, c.ID)
			}
		}
	}

	// Check for dependency cycles
	for _, c := range cat.Controls {
		visited := make(map[string]bool)
		var checkCycle func(curr string) error
		checkCycle = func(curr string) error {
			if visited[curr] {
				return fmt.Errorf("cycle détecté dans les dépendances du catalogue: %s", curr)
			}
			visited[curr] = true
			if ctrl, ok := ids[curr]; ok {
				for _, dep := range ctrl.Dependencies {
					if err := checkCycle(dep); err != nil {
						return err
					}
				}
			}
			delete(visited, curr)
			return nil
		}
		if err := checkCycle(c.ID); err != nil {
			return nil, err
		}
	}

	return &cat, nil
}

// GetCapabilityProfile groups controls by capability for a given technology.
func (c *ControlCatalog) GetCapabilityProfile(technology string) []CapabilityProfile {
	var techControls []CatalogControl
	for _, ctrl := range c.Controls {
		if ctrl.Technology == technology {
			techControls = append(techControls, ctrl)
		}
	}

	// Group by capability
	groups := make(map[string][]CatalogControl)
	for _, ctrl := range techControls {
		groups[ctrl.Capability] = append(groups[ctrl.Capability], ctrl)
	}

	// Sort capability names
	var capNames []string
	for name := range groups {
		capNames = append(capNames, name)
	}
	sort.Strings(capNames)

	var profiles []CapabilityProfile
	for _, name := range capNames {
		ctrls := groups[name]
		// Sort controls by ID
		sort.Slice(ctrls, func(i, j int) bool {
			return ctrls[i].ID < ctrls[j].ID
		})

		policy := "all"
		if len(ctrls) > 0 && ctrls[0].SelectionPolicy != "" {
			policy = ctrls[0].SelectionPolicy
		}

		var tools []CandidateToolDefinition
		for _, ctrl := range ctrls {
			if ctrl.Tool != nil {
				tools = append(tools, CandidateToolDefinition{
					Name:            ctrl.Tool.Name,
					Command:         ctrl.Tool.Command,
					CatalogID:       ctrl.ID,
					Severity:        ctrl.Severity,
					SideEffectLevel: ctrl.SideEffectLevel,
					Permissions:     ctrl.Permissions,
					TimeoutSeconds:  ctrl.TimeoutSeconds,
					Cost:            ctrl.Cost,
					Parameters:      ctrl.Parameters,
					Dependencies:    ctrl.Dependencies,
					Limitations:     ctrl.Limitations,
					PlatformSupport: ctrl.PlatformSupport,
				})
			}
		}

		profiles = append(profiles, CapabilityProfile{
			Name:            name,
			SelectionPolicy: policy,
			Controls:        ctrls,
			Tools:           tools,
		})
	}

	return profiles
}
