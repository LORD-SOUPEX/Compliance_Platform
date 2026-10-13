package server

import (
	"compliance/internal/discovery"
)

// DaemonConfig holds configuration for the compliance daemon.
type DaemonConfig struct {
	ListenAddr         string   // Default "127.0.0.1:0"
	StateDir           string   // Directory for daemon.json, daemon.lock, daemon.token (e.g. ~/.compliance)
	ApprovedWorkspaces []string // Whitelist of allowed workspace root paths
	CatalogPath        string   // Path to control-catalog.json
	PlatformRoot       string   // Platform repository root
	Version            string   // Daemon version
}

// DaemonState is serialized to daemon.json upon successful startup.
type DaemonState struct {
	PID       int    `json:"pid"`
	Port      int    `json:"port"`
	Host      string `json:"host"`
	TokenPath string `json:"token_path"`
	StateDir  string `json:"state_dir"`
	StartedAt string `json:"started_at"`
	Version   string `json:"version"`
}

// HealthResponse represents response from GET /api/v1/health.
type HealthResponse struct {
	Status    string `json:"status"`
	Version   string `json:"version"`
	PID       int    `json:"pid"`
	Port      int    `json:"port"`
	StartedAt string `json:"started_at"`
}

// DiscoveryRequest represents request to POST /api/v1/discovery.
type DiscoveryRequest struct {
	TargetPath string `json:"target_path"`
}

// DiscoveryResponse represents response from POST /api/v1/discovery.
type DiscoveryResponse struct {
	TargetPath   string                       `json:"target_path"`
	Technologies []discovery.TechnologyRecord `json:"technologies"`
	ScanComplete bool                         `json:"scan_complete"`
}

// PlanRequest represents request to POST /api/v1/plans.
type PlanRequest struct {
	TargetPath         string `json:"target_path"`
	AllowNetwork       bool   `json:"allow_network"`
	AllowCodeExecution bool   `json:"allow_code_execution"`
	IncludeApplyDestroy bool  `json:"include_apply_destroy"`
}

// CreateRunRequest represents request to POST /api/v1/runs.
type CreateRunRequest struct {
	TargetPath          string   `json:"target_path"`
	RunID               string   `json:"run_id,omitempty"`
	OutputDir           string   `json:"output_dir,omitempty"`
	PlanOnly            bool     `json:"plan_only"`
	ControlID           string   `json:"control_id,omitempty"`           // Optional: run single control
	AllowNetwork        bool     `json:"allow_network"`
	AllowCodeExecution  bool     `json:"allow_code_execution"`
	ConfirmApplyDestroy bool     `json:"confirm_apply_destroy"`         // Required if running apply_destroy control
	RedactionPatterns   []string `json:"redaction_patterns,omitempty"`
}

// RunCreationResponse represents response from POST /api/v1/runs.
type RunCreationResponse struct {
	RunID     string `json:"run_id"`
	Status    string `json:"status"`
	EventsURL string `json:"events_url"`
	ReportURL string `json:"report_url"`
}

// CancelResponse represents response from POST /api/v1/runs/{id}/cancel.
type CancelResponse struct {
	RunID     string `json:"run_id"`
	Status    string `json:"status"`
	Cancelled bool   `json:"cancelled"`
}

// ControlLogsResponse represents response from GET /api/v1/runs/{id}/logs/{control_id}.
type ControlLogsResponse struct {
	RunID       string  `json:"run_id"`
	ControlID   string  `json:"control_id"`
	Status      string  `json:"status"`
	ExitCode    *int    `json:"exit_code"`
	Stdout      string  `json:"stdout"`
	Stderr      string  `json:"stderr"`
	DurationMs  int64   `json:"duration_ms"`
	ToolVersion *string `json:"tool_version,omitempty"`
}

// SessionEvent represents an SSE event adhering strictly to compliance-session.schema.json.
type SessionEvent struct {
	SchemaVersion int         `json:"schema_version"`
	RunID         string      `json:"run_id"`
	Sequence      int         `json:"sequence"`
	Timestamp     string      `json:"timestamp"`
	Type          string      `json:"type"`
	ControlID     *string     `json:"control_id"`
	Technology    *string     `json:"technology"`
	Root          *string     `json:"root"`
	Data          interface{} `json:"data"`
}

// WorkspaceApprovalRequest represents request to approve a workspace path.
type WorkspaceApprovalRequest struct {
	WorkspacePath string `json:"workspace_path"`
}

// ValidateReportRequest represents request to POST /api/v1/reports/validate.
type ValidateReportRequest struct {
	ReportSHA256 string                 `json:"report_sha256"`
	Report       map[string]interface{} `json:"report"`
}

// PresentationItem represents a control presentation state.
type PresentationItem struct {
	ControlID string      `json:"control_id"`
	Status    string      `json:"status"`
	Reason    interface{} `json:"reason"`
}

// ValidateReportResponse represents response from POST /api/v1/reports/validate.
type ValidateReportResponse struct {
	SchemaVersion int                `json:"schema_version"`
	ReportSHA256  string             `json:"report_sha256"`
	Presentations []PresentationItem `json:"presentations"`
}
