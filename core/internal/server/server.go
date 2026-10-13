package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"compliance/internal/discovery"
	"compliance/internal/engine"
	"compliance/internal/matrix"
	"compliance/internal/osutil"
	"compliance/internal/report"
)

var (
	ErrUnauthorized             = errors.New("authentification requise ou jeton Bearer invalide")
	ErrForbiddenHost            = errors.New("en-tête Host non autorisé (rejet DNS Rebinding)")
	ErrForbiddenOrigin          = errors.New("en-tête Origin externe ou non autorisé (rejet CSRF)")
	ErrWorkspaceUntrusted       = errors.New("répertoire cible hors périmètre des espaces autorisés")
	ErrRunNotFound             = errors.New("session d'audit introuvable")
	ErrRunAlreadyFinished      = errors.New("la session d'audit est déjà terminée")
	ErrApplyDestroyNeedsConfirm = errors.New("les étapes apply_destroy ne peuvent être exécutées que de manière unitaire avec confirmation explicite")
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
	TargetPath          string `json:"target_path"`
	AllowNetwork        bool   `json:"allow_network"`
	AllowCodeExecution  bool   `json:"allow_code_execution"`
	IncludeApplyDestroy bool   `json:"include_apply_destroy"`
}

// CreateRunRequest represents request to POST /api/v1/runs.
type CreateRunRequest struct {
	TargetPath          string   `json:"target_path"`
	RunID               string   `json:"run_id,omitempty"`
	OutputDir           string   `json:"output_dir,omitempty"`
	PlanOnly            bool     `json:"plan_only"`
	ControlID           string   `json:"control_id,omitempty"`   // Optional: run single control
	AllowNetwork        bool     `json:"allow_network"`
	AllowCodeExecution  bool     `json:"allow_code_execution"`
	ConfirmApplyDestroy bool     `json:"confirm_apply_destroy"` // Required if running apply_destroy control
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
	Path          string `json:"path"`
}

func (w WorkspaceApprovalRequest) Target() string {
	if w.WorkspacePath != "" {
		return w.WorkspacePath
	}
	return w.Path
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

// GenerateBearerToken generates a cryptographically secure 256-bit token (64 hex chars).
func GenerateBearerToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("génération du jeton cryptographique aléatoire: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// WriteProtectedToken writes token to path with POSIX 0600 or Windows ACL.
func WriteProtectedToken(path string, token string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("création du dossier du jeton: %w", err)
	}

	if err := os.WriteFile(path, []byte(token), 0600); err != nil {
		return fmt.Errorf("écriture du fichier de jeton: %w", err)
	}

	if runtime.GOOS == "windows" {
		grantTarget := ""
		if u, err := user.Current(); err == nil && u.Uid != "" {
			grantTarget = fmt.Sprintf("*%s:(F)", u.Uid)
		} else if username := os.Getenv("USERNAME"); username != "" {
			grantTarget = fmt.Sprintf("%s:(F)", username)
		}
		if grantTarget != "" {
			cmd := exec.Command("icacls", path, "/inheritance:r", "/grant:r", grantTarget)
			osutil.SetHideWindow(cmd)
			_ = cmd.Run() // Best effort on Windows environments
		}
	}

	return nil
}

// SecurityManager enforces authentication, host validation, origin checks, and workspace paths.
type SecurityManager struct {
	Token              string
	Port               int
	ApprovedWorkspaces []string
}

// NewSecurityManager creates a new SecurityManager.
func NewSecurityManager(token string, port int, approvedWorkspaces []string) *SecurityManager {
	canonicalWorkspaces := make([]string, 0, len(approvedWorkspaces))
	for _, ws := range approvedWorkspaces {
		c, err := CanonicalizePath(ws)
		if err == nil {
			canonicalWorkspaces = append(canonicalWorkspaces, c)
		}
	}
	return &SecurityManager{
		Token:              token,
		Port:               port,
		ApprovedWorkspaces: canonicalWorkspaces,
	}
}

// ValidateHost checks if the Host header corresponds to 127.0.0.1 or localhost on the expected port.
func (sm *SecurityManager) ValidateHost(hostHeader string) bool {
	if hostHeader == "" {
		return false
	}
	host, port, err := net.SplitHostPort(hostHeader)
	if err != nil {
		host = hostHeader
		port = ""
	}

	if port != "" && sm.Port > 0 {
		expectedPort := fmt.Sprintf("%d", sm.Port)
		if port != expectedPort {
			return false
		}
	}

	h := strings.ToLower(host)
	return h == "127.0.0.1" || h == "localhost" || h == "::1" || h == "[::1]"
}

// ValidateOrigin validates the Origin header.
func (sm *SecurityManager) ValidateOrigin(originHeader string) bool {
	if originHeader == "" {
		return true
	}

	trimmed := strings.TrimSpace(originHeader)
	if trimmed == "null" {
		return true
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return false
	}

	if parsed.Scheme == "vscode-webview" || parsed.Scheme == "vscode-file" {
		return true
	}

	if parsed.Scheme == "http" {
		hostname := strings.ToLower(parsed.Hostname())
		if hostname != "127.0.0.1" && hostname != "localhost" && hostname != "::1" {
			return false
		}
		port := parsed.Port()
		if sm.Port > 0 {
			expectedPort := fmt.Sprintf("%d", sm.Port)
			if port != expectedPort {
				return false
			}
		}
		if parsed.Path != "" && parsed.Path != "/" {
			return false
		}
		return true
	}

	return false
}

// ValidateToken verifies the Authorization header contains the valid Bearer token.
func (sm *SecurityManager) ValidateToken(authHeader string) bool {
	if authHeader == "" {
		return false
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return false
	}
	providedToken := strings.TrimSpace(parts[1])
	return subtle.ConstantTimeCompare([]byte(providedToken), []byte(sm.Token)) == 1
}

// AddApprovedWorkspace registers a new approved workspace root.
func (sm *SecurityManager) AddApprovedWorkspace(wsPath string) error {
	c, err := CanonicalizePath(wsPath)
	if err != nil {
		return err
	}
	for _, existing := range sm.ApprovedWorkspaces {
		if strings.EqualFold(existing, c) {
			return nil
		}
	}
	sm.ApprovedWorkspaces = append(sm.ApprovedWorkspaces, c)
	return nil
}

// ValidateTargetPath resolves symlinks and verifies the path belongs to an approved workspace.
func (sm *SecurityManager) ValidateTargetPath(targetPath string) (string, error) {
	if targetPath == "" {
		return "", errors.New("le chemin cible ne peut pas être vide")
	}

	canonicalTarget, err := CanonicalizePath(targetPath)
	if err != nil {
		return "", fmt.Errorf("résolution du chemin cible impossible (%s): %w", targetPath, err)
	}

	fi, err := os.Stat(canonicalTarget)
	if err != nil {
		return "", fmt.Errorf("chemin cible introuvable: %w", err)
	}
	if !fi.IsDir() {
		return "", errors.New("le chemin cible doit être un répertoire")
	}

	if len(sm.ApprovedWorkspaces) == 0 {
		return "", ErrWorkspaceUntrusted
	}

	for _, ws := range sm.ApprovedWorkspaces {
		matches := false
		if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
			targetLower := strings.ToLower(canonicalTarget)
			wsLower := strings.ToLower(ws)
			matches = (targetLower == wsLower || strings.HasPrefix(targetLower, wsLower+string(filepath.Separator)))
		} else {
			matches = (canonicalTarget == ws || strings.HasPrefix(canonicalTarget, ws+string(filepath.Separator)))
		}
		if matches {
			return canonicalTarget, nil
		}
	}

	return "", fmt.Errorf("%w: %s n'appartient à aucun workspace approuvé", ErrWorkspaceUntrusted, targetPath)
}

// CanonicalizePath cleans path and resolves all symlinks.
func CanonicalizePath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return filepath.Clean(abs), nil
		}
		return "", err
	}
	return filepath.Clean(real), nil
}

// Middleware creates an HTTP handler middleware enforcing Host, Origin, and Bearer authentication.
func (sm *SecurityManager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !sm.ValidateHost(r.Host) {
			http.Error(w, "Forbidden: invalid Host header", http.StatusForbidden)
			return
		}

		origin := r.Header.Get("Origin")
		if origin != "" && !sm.ValidateOrigin(origin) {
			http.Error(w, "Forbidden: untrusted Origin header", http.StatusForbidden)
			return
		}

		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, "Unauthorized: missing Authorization header", http.StatusUnauthorized)
			return
		}
		if !sm.ValidateToken(auth) {
			http.Error(w, "Forbidden: invalid Bearer token", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Session represents a compliance execution session with event history and SSE broadcasting.
type Session struct {
	mu          sync.RWMutex
	ID          string
	TargetPath  string
	State       string // "preparing", "running", "cancelling", "completed", "cancelled", "failed"
	StartedAt   time.Time
	EndedAt     *time.Time
	Report      *report.Report
	Events      []SessionEvent
	Subscribers map[chan SessionEvent]struct{}
	Cancel      context.CancelFunc
	Logs        map[string]*ControlLogsResponse
	OutputDir   string
	PlanOnly    bool
	Advisory    bool
	Permissions struct{ Network, CodeExecution bool }
}

// SessionManager manages active and persisted run sessions.
type SessionManager struct {
	mu           sync.RWMutex
	sessions     map[string]*Session
	stateDir     string
	platformRoot string
	catalogPath  string
	version      string
	resolver     *matrix.DefaultCandidateResolver
}

// NewSessionManager creates a new SessionManager.
func NewSessionManager(stateDir, platformRoot, catalogPath, version string) *SessionManager {
	sm := &SessionManager{
		sessions:     make(map[string]*Session),
		stateDir:     stateDir,
		platformRoot: platformRoot,
		catalogPath:  catalogPath,
		version:      version,
		resolver:     &matrix.DefaultCandidateResolver{PlatformRoot: platformRoot},
	}
	sm.CleanupStaleSessions()
	return sm
}

// GenerateRunID produces a random 32-character hexadecimal run ID.
func GenerateRunID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// CreateRun initializes and starts an execution run in background.
func (sm *SessionManager) CreateRun(ctx context.Context, req CreateRunRequest) (*Session, error) {
	runID := req.RunID
	if runID == "" {
		runID = GenerateRunID()
	}
	runDir := req.OutputDir
	if runDir == "" {
		runDir = filepath.Join(sm.stateDir, "runs", runID)
	}
	_ = os.MkdirAll(runDir, 0700)
	_ = os.MkdirAll(filepath.Join(runDir, "logs"), 0700)

	sessionPath := filepath.Join(runDir, "session.json")
	initSession := map[string]interface{}{
		"schema_version": 1,
		"run_id":         runID,
		"target":         req.TargetPath,
		"state":          "preparing",
		"permissions": map[string]bool{
			"network":        req.AllowNetwork,
			"code_execution": req.AllowCodeExecution,
		},
		"started_at": time.Now().UTC().Format(time.RFC3339),
		"ended_at":   nil,
	}
	if b, err := json.MarshalIndent(initSession, "", "  "); err == nil {
		_ = os.WriteFile(sessionPath, b, 0600)
	}

	runCtx, cancel := context.WithCancel(context.Background())

	session := &Session{
		ID:          runID,
		TargetPath:  req.TargetPath,
		State:       "preparing",
		StartedAt:   time.Now().UTC(),
		Events:      make([]SessionEvent, 0),
		Subscribers: make(map[chan SessionEvent]struct{}),
		Cancel:      cancel,
		Logs:        make(map[string]*ControlLogsResponse),
		OutputDir:   runDir,
		PlanOnly:    req.PlanOnly,
		Permissions: struct{ Network, CodeExecution bool }{
			Network:       req.AllowNetwork,
			CodeExecution: req.AllowCodeExecution,
		},
	}

	sm.mu.Lock()
	sm.sessions[runID] = session
	sm.mu.Unlock()

	session.emitEvent("session_started", nil, nil, nil, map[string]interface{}{
		"target":          req.TargetPath,
		"plan_only":       req.PlanOnly,
		"pipeline_source": sm.platformRoot,
	})

	go sm.executeRun(runCtx, session, req)

	return session, nil
}

func (sm *SessionManager) executeRun(ctx context.Context, s *Session, req CreateRunRequest) {
	defer func() {
		if r := recover(); r != nil {
			s.mu.Lock()
			s.State = "failed"
			now := time.Now().UTC()
			s.EndedAt = &now
			s.mu.Unlock()
			s.emitEvent("session_failed", nil, nil, nil, map[string]interface{}{
				"error": fmt.Sprintf("panique interne: %v", r),
			})
		}
	}()

	s.emitEvent("preparation_started", nil, nil, nil, map[string]interface{}{
		"target": req.TargetPath,
	})

	s.mu.Lock()
	s.State = "running"
	s.mu.Unlock()

	s.emitEvent("preparation_completed", nil, nil, nil, map[string]interface{}{
		"target": req.TargetPath,
	})

	opts := engine.ComplianceOptions{
		RepoRoot:          req.TargetPath,
		PlatformRoot:      sm.platformRoot,
		CatalogPath:       sm.catalogPath,
		AllowNetwork:      req.AllowNetwork,
		AllowCodeExecution: req.AllowCodeExecution,
		PlanOnly:          req.PlanOnly,
		RedactionPatterns: req.RedactionPatterns,
		RunID:             s.ID,
		SourceAdapter:     "VSCode",
		CandidateResolver: sm.resolver,
		OnPlanReady: func(planRep *report.Report) {
			if b, err := json.MarshalIndent(planRep, "", "  "); err == nil {
				planPath := filepath.Join(s.OutputDir, "execution-plan.json")
				_ = os.WriteFile(planPath, b, 0600)
			}
			s.emitEvent("plan_available", nil, nil, nil, planRep)
		},
		OnControlStart: func(ctrl *engine.PlannedControl) {
			ctrlID := ctrl.ID
			tech := ctrl.Technology
			root := ctrl.Root
			s.emitEvent("control_started", &ctrlID, &tech, &root, map[string]interface{}{
				"name":            ctrl.Name,
				"capability":      ctrl.Capability,
				"severity":        ctrl.Severity,
				"execution_start": time.Now().UTC().Format(time.RFC3339),
			})
		},
		OnControlDone: func(ctrl *engine.PlannedControl, res *report.ExecutionResult) {
			ctrlID := ctrl.ID
			tech := ctrl.Technology
			root := ctrl.Root

			s.mu.Lock()
			s.Logs[ctrl.ID] = &ControlLogsResponse{
				RunID:       s.ID,
				ControlID:   ctrl.ID,
				Status:      res.Status,
				ExitCode:    res.ExitCode,
				Stdout:      res.Stdout,
				Stderr:      res.Stderr,
				DurationMs:  res.DurationMs,
				ToolVersion: res.ToolVersion,
			}
			s.mu.Unlock()

			presStatus := mapPresentationStatus(res)
			var reasonObj map[string]interface{}
			if len(res.Diagnostics) > 0 {
				msg := res.Diagnostics[0].Message
				if msg == "" {
					msg = "Contrôle non exécuté selon le motif structuré du backend."
				}
				reasonObj = map[string]interface{}{
					"code":    res.Diagnostics[0].Code,
					"message": msg,
				}
			} else if presStatus == "Not applicable" || presStatus == "Skipped" || presStatus == "Blocked" || presStatus == "Warning" {
				reasonObj = map[string]interface{}{
					"code":    "not_applicable",
					"message": "Contrôle non applicable selon le backend.",
				}
			}

			logPath := filepath.Join(s.OutputDir, "logs", filepath.Base(ctrl.ID)+".log")
			_ = os.WriteFile(logPath, []byte(res.Stdout+"\n"+res.Stderr), 0600)

			s.emitEvent("control_completed", &ctrlID, &tech, &root, map[string]interface{}{
				"status":      presStatus,
				"reason":      reasonObj,
				"result":      res,
				"output_path": logPath,
			})
		},
	}

	rep, err := engine.RunCompliance(ctx, opts)

	s.mu.Lock()
	now := time.Now().UTC()
	s.EndedAt = &now
	if ctx.Err() != nil {
		s.State = "cancelled"
		if rep != nil {
			rep.ExecutionStatus = "blocked"
			failStr := "FAIL"
			rep.Verdict = &failStr
			rep.Coverage.Complete = false
			s.Report = rep
		}
		s.mu.Unlock()

		sessionPath := filepath.Join(s.OutputDir, "session.json")
		sessionData := map[string]interface{}{
			"schema_version": 1,
			"run_id":         s.ID,
			"target":         s.TargetPath,
			"state":          "cancelled",
			"permissions": map[string]bool{
				"network":        s.Permissions.Network,
				"code_execution": s.Permissions.CodeExecution,
			},
			"started_at": s.StartedAt.Format(time.RFC3339),
			"ended_at":   now.Format(time.RFC3339),
		}
		if sessBytes, sErr := json.MarshalIndent(sessionData, "", "  "); sErr == nil {
			_ = os.WriteFile(sessionPath, sessBytes, 0600)
		}

		reportPath := filepath.Join(s.OutputDir, "compliance-report.json")
		if rep != nil {
			if b, err := json.MarshalIndent(rep, "", "  "); err == nil {
				_ = os.WriteFile(reportPath, b, 0600)
			}
		}

		s.emitEvent("report_available", nil, nil, nil, map[string]interface{}{
			"report_path": reportPath,
			"verdict":     "FAIL",
		})

		s.emitEvent("session_cancelled", nil, nil, nil, map[string]interface{}{
			"verdict": "FAIL",
			"coverage": map[string]interface{}{
				"complete": false,
			},
			"reason": map[string]interface{}{
				"code":    "session_interrupted",
				"message": "Annulation demandée par le client.",
			},
		})
		return
	}

	if err != nil {
		s.State = "failed"
		s.mu.Unlock()
		s.emitEvent("session_failed", nil, nil, nil, map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	s.Report = rep
	s.State = "completed"
	s.mu.Unlock()

	reportPath := filepath.Join(s.OutputDir, "compliance-report.json")
	if repBytes, mErr := json.MarshalIndent(rep, "", "  "); mErr == nil {
		_ = os.WriteFile(reportPath, repBytes, 0600)
	}

	planPath := filepath.Join(s.OutputDir, "execution-plan.json")
	if _, err := os.Stat(planPath); os.IsNotExist(err) {
		if planBytes, pErr := json.MarshalIndent(rep, "", "  "); pErr == nil {
			_ = os.WriteFile(planPath, planBytes, 0600)
		}
	}

	sessionPath := filepath.Join(s.OutputDir, "session.json")
	sessionData := map[string]interface{}{
		"schema_version": 1,
		"run_id":         s.ID,
		"target":         s.TargetPath,
		"state":          "completed",
		"permissions": map[string]bool{
			"network":        s.Permissions.Network,
			"code_execution": s.Permissions.CodeExecution,
		},
		"started_at": s.StartedAt.Format(time.RFC3339),
		"ended_at":   now.Format(time.RFC3339),
	}
	if sessBytes, sErr := json.MarshalIndent(sessionData, "", "  "); sErr == nil {
		_ = os.WriteFile(sessionPath, sessBytes, 0600)
	}

	s.emitEvent("report_available", nil, nil, nil, map[string]interface{}{
		"report_path": reportPath,
		"verdict":     rep.Verdict,
	})

	s.emitEvent("session_completed", nil, nil, nil, map[string]interface{}{
		"verdict":         rep.Verdict,
		"verdict_reasons": rep.VerdictReasons,
		"coverage": map[string]interface{}{
			"complete": rep.Coverage.Complete,
		},
	})
}

func mapPresentationStatus(res *report.ExecutionResult) string {
	if len(res.Diagnostics) > 0 {
		code := res.Diagnostics[0].Code
		switch code {
		case "dependency_failed", "ambiguous", "capability_unavailable", "tool_unavailable":
			return "Blocked"
		case "permission_denied", "cancelled_before_start", "cancelled_during_execution":
			return "Skipped"
		}
	}
	switch res.Status {
	case "success":
		if res.OutputTruncated || len(res.Diagnostics) > 0 {
			return "Warning"
		}
		return "Succeeded"
	case "fail":
		return "Failed"
	case "error":
		return "Error"
	case "skipped":
		return "Not applicable"
	default:
		return "Succeeded"
	}
}

func (s *Session) emitEvent(eventType string, ctrlID, tech, root *string, data interface{}) {
	s.mu.Lock()
	seq := len(s.Events) + 1
	event := SessionEvent{
		SchemaVersion: 1,
		RunID:         s.ID,
		Sequence:      seq,
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		Type:          eventType,
		ControlID:     ctrlID,
		Technology:    tech,
		Root:          root,
		Data:          data,
	}
	s.Events = append(s.Events, event)

	if s.OutputDir != "" {
		if b, err := json.Marshal(event); err == nil {
			eventsPath := filepath.Join(s.OutputDir, "events.ndjson")
			if f, err := os.OpenFile(eventsPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600); err == nil {
				_, _ = f.Write(append(b, '\n'))
				_ = f.Close()
			}
		}
	}

	for ch := range s.Subscribers {
		select {
		case ch <- event:
		default:
		}
	}
	s.mu.Unlock()
}

// SubscribeEvents registers a channel for SSE event streaming with replay of past events from lastSeq.
func (s *Session) SubscribeEvents(lastSeq int) (chan SessionEvent, func()) {
	ch := make(chan SessionEvent, 100)

	s.mu.Lock()
	for _, ev := range s.Events {
		if ev.Sequence > lastSeq {
			ch <- ev
		}
	}
	s.Subscribers[ch] = struct{}{}
	s.mu.Unlock()

	unsubscribe := func() {
		s.mu.Lock()
		delete(s.Subscribers, ch)
		close(ch)
		s.mu.Unlock()
	}

	return ch, unsubscribe
}

// CancelSession cleanly cancels an ongoing run.
func (s *Session) CancelSession() error {
	s.mu.Lock()
	if s.State != "running" && s.State != "preparing" {
		s.mu.Unlock()
		return ErrRunAlreadyFinished
	}
	s.State = "cancelling"
	cancelFunc := s.Cancel
	s.mu.Unlock()

	s.emitEvent("session_cancelling", nil, nil, nil, map[string]interface{}{
		"reason": "Annulation requise par le client HTTP.",
	})

	if cancelFunc != nil {
		cancelFunc()
	}
	return nil
}

// GetSession retrieves a session by ID.
func (sm *SessionManager) GetSession(id string) (*Session, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	session, ok := sm.sessions[id]
	if !ok {
		return nil, ErrRunNotFound
	}
	return session, nil
}

// CleanupStaleSessions purges sessions older than 7 days, retaining up to 20 recent sessions.
func (sm *SessionManager) CleanupStaleSessions() {
	runsDir := filepath.Join(sm.stateDir, "runs")
	entries, err := os.ReadDir(runsDir)
	if err != nil {
		return
	}

	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		path := filepath.Join(runsDir, e.Name())
		fi, err := e.Info()
		if err != nil {
			continue
		}
		if fi.ModTime().Before(cutoff) {
			_ = os.RemoveAll(path)
		}
	}
}

// DaemonServer represents the running HTTP/SSE daemon.
type DaemonServer struct {
	cfg        DaemonConfig
	listener   net.Listener
	httpServer *http.Server
	security   *SecurityManager
	sessions   *SessionManager
	startedAt  time.Time
	tokenPath  string
	lockPath   string
	statePath  string
	mu         sync.Mutex
	closed     bool
}

// StartDaemon initializes and starts the compliance daemon on a dynamic loopback port.
func StartDaemon(cfg DaemonConfig) (*DaemonServer, error) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:0"
	}
	if cfg.StateDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "."
		}
		cfg.StateDir = filepath.Join(home, ".compliance")
	}
	if cfg.Version == "" {
		cfg.Version = "2.0.0"
	}

	lockPath := filepath.Join(cfg.StateDir, "daemon.lock")
	tokenPath := filepath.Join(cfg.StateDir, "daemon.token")
	statePath := filepath.Join(cfg.StateDir, "daemon.json")

	if err := AcquireLock(lockPath); err != nil {
		return nil, err
	}

	token, err := GenerateBearerToken()
	if err != nil {
		ReleaseLock(lockPath)
		return nil, err
	}

	if err := WriteProtectedToken(tokenPath, token); err != nil {
		ReleaseLock(lockPath)
		return nil, err
	}

	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		ReleaseLock(lockPath)
		_ = os.Remove(tokenPath)
		return nil, fmt.Errorf("écoute sur %s impossible: %w", cfg.ListenAddr, err)
	}

	tcpAddr := listener.Addr().(*net.TCPAddr)
	port := tcpAddr.Port

	security := NewSecurityManager(token, port, cfg.ApprovedWorkspaces)
	sessions := NewSessionManager(cfg.StateDir, cfg.PlatformRoot, cfg.CatalogPath, cfg.Version)

	srv := &DaemonServer{
		cfg:        cfg,
		listener:   listener,
		security:   security,
		sessions:   sessions,
		startedAt:  time.Now().UTC(),
		tokenPath:  tokenPath,
		lockPath:   lockPath,
		statePath:  statePath,
	}

	state := DaemonState{
		PID:       os.Getpid(),
		Port:      port,
		Host:      "127.0.0.1",
		TokenPath: tokenPath,
		StateDir:  cfg.StateDir,
		StartedAt: srv.startedAt.Format(time.RFC3339),
		Version:   cfg.Version,
	}
	if err := WriteDaemonState(statePath, state); err != nil {
		_ = listener.Close()
		ReleaseLock(lockPath)
		_ = os.Remove(tokenPath)
		return nil, err
	}

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	srv.httpServer = &http.Server{
		Handler:      security.Middleware(mux),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0,
	}

	go func() {
		_ = srv.httpServer.Serve(listener)
	}()

	return srv, nil
}

// AddApprovedWorkspace registers an approved workspace with the running daemon.
func (s *DaemonServer) AddApprovedWorkspace(ws string) error {
	return s.security.AddApprovedWorkspace(ws)
}

// Port returns the dynamic port allocated to the daemon.
func (s *DaemonServer) Port() int {
	return s.security.Port
}

// Token returns the active Bearer token.
func (s *DaemonServer) Token() string {
	return s.security.Token
}

// URL returns the base URL of the daemon.
func (s *DaemonServer) URL() string {
	return fmt.Sprintf("http://127.0.0.1:%d", s.Port())
}

// Sessions returns the active SessionManager.
func (s *DaemonServer) Sessions() *SessionManager {
	return s.sessions
}

// Close gracefully shuts down the daemon and cleans up state, lock, and token files.
func (s *DaemonServer) Close(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	var firstErr error
	if err := s.httpServer.Shutdown(ctx); err != nil {
		firstErr = err
	}

	ReleaseLock(s.lockPath)
	_ = os.Remove(s.tokenPath)
	_ = os.Remove(s.statePath)

	return firstErr
}

func (s *DaemonServer) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	mux.HandleFunc("POST /api/v1/workspaces/approve", s.handleApproveWorkspace)
	mux.HandleFunc("POST /api/v1/discovery", s.handleDiscovery)
	mux.HandleFunc("POST /api/v1/plans", s.handlePlan)
	mux.HandleFunc("POST /api/v1/runs", s.handleCreateRun)
	mux.HandleFunc("GET /api/v1/runs/{id}/events", s.handleEvents)
	mux.HandleFunc("POST /api/v1/runs/{id}/cancel", s.handleCancel)
	mux.HandleFunc("GET /api/v1/runs/{id}/report", s.handleReport)
	mux.HandleFunc("GET /api/v1/runs/{id}/logs/{control_id...}", s.handleControlLogs)
	mux.HandleFunc("POST /api/v1/reports/validate", s.handleValidateReport)
	mux.HandleFunc("POST /api/v1/shutdown", s.handleShutdown)
}

func (s *DaemonServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	resp := HealthResponse{
		Status:    "ok",
		Version:   s.cfg.Version,
		PID:       os.Getpid(),
		Port:      s.Port(),
		StartedAt: s.startedAt.Format(time.RFC3339),
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *DaemonServer) handleApproveWorkspace(w http.ResponseWriter, r *http.Request) {
	var req WorkspaceApprovalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Requête JSON invalide", http.StatusBadRequest)
		return
	}
	targetPath := req.Target()
	if targetPath == "" {
		http.Error(w, "Chemin de workspace manquant", http.StatusBadRequest)
		return
	}
	if err := s.security.AddApprovedWorkspace(targetPath); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "approved",
		"workspace": targetPath,
		"path":      targetPath,
	})
}

func (s *DaemonServer) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	var req DiscoveryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Requête JSON invalide", http.StatusBadRequest)
		return
	}

	canonicalTarget, err := s.security.ValidateTargetPath(req.TargetPath)
	if err != nil {
		if errors.Is(err, ErrWorkspaceUntrusted) {
			http.Error(w, err.Error(), http.StatusForbidden)
		} else {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
		return
	}

	res, err := discovery.DiscoverAll(canonicalTarget)
	if err != nil {
		http.Error(w, fmt.Sprintf("Erreur de découverte: %v", err), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, DiscoveryResponse{
		TargetPath:   canonicalTarget,
		Technologies: res.Technologies,
		ScanComplete: res.ScanComplete,
	})
}

func (s *DaemonServer) handlePlan(w http.ResponseWriter, r *http.Request) {
	var req PlanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Requête JSON invalide", http.StatusBadRequest)
		return
	}

	canonicalTarget, err := s.security.ValidateTargetPath(req.TargetPath)
	if err != nil {
		if errors.Is(err, ErrWorkspaceUntrusted) {
			http.Error(w, err.Error(), http.StatusForbidden)
		} else {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
		return
	}

	opts := engine.ComplianceOptions{
		RepoRoot:           canonicalTarget,
		PlatformRoot:       s.cfg.PlatformRoot,
		CatalogPath:        s.cfg.CatalogPath,
		AllowNetwork:       req.AllowNetwork,
		AllowCodeExecution: req.AllowCodeExecution,
		PlanOnly:           true,
		SourceAdapter:      "VSCode",
		RunID:              GenerateRunID(),
		CandidateResolver:  s.sessions.resolver,
	}

	rep, err := engine.RunCompliance(r.Context(), opts)
	if err != nil {
		http.Error(w, fmt.Sprintf("Génération du plan échouée: %v", err), http.StatusInternalServerError)
		return
	}

	if !req.IncludeApplyDestroy {
		filtered := make([]interface{}, 0, len(rep.ExecutionPlan.Controls))
		for _, c := range rep.ExecutionPlan.Controls {
			isApplyDestroy := false
			if m, ok := c.(map[string]interface{}); ok {
				if id, ok := m["id"].(string); ok {
					idLower := strings.ToLower(id)
					if strings.Contains(idLower, "apply") || strings.Contains(idLower, "destroy") {
						isApplyDestroy = true
					}
				}
			}
			if !isApplyDestroy {
				filtered = append(filtered, c)
			}
		}
		rep.ExecutionPlan.Controls = filtered
	}

	writeJSON(w, http.StatusOK, rep)
}

func (s *DaemonServer) handleCreateRun(w http.ResponseWriter, r *http.Request) {
	var req CreateRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Requête JSON invalide", http.StatusBadRequest)
		return
	}

	canonicalTarget, err := s.security.ValidateTargetPath(req.TargetPath)
	if err != nil {
		if errors.Is(err, ErrWorkspaceUntrusted) {
			http.Error(w, err.Error(), http.StatusForbidden)
		} else {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
		return
	}
	req.TargetPath = canonicalTarget

	if req.ControlID != "" && (strings.Contains(strings.ToLower(req.ControlID), "apply") || strings.Contains(strings.ToLower(req.ControlID), "destroy")) {
		if !req.ConfirmApplyDestroy {
			http.Error(w, ErrApplyDestroyNeedsConfirm.Error(), http.StatusBadRequest)
			return
		}
	}

	session, err := s.sessions.CreateRun(r.Context(), req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Création de session échouée: %v", err), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusCreated, RunCreationResponse{
		RunID:     session.ID,
		Status:    session.State,
		EventsURL: fmt.Sprintf("/api/v1/runs/%s/events", session.ID),
		ReportURL: fmt.Sprintf("/api/v1/runs/%s/report", session.ID),
	})
}

func (s *DaemonServer) handleEvents(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("id")
	session, err := s.sessions.GetSession(runID)
	if err != nil {
		http.Error(w, "Session introuvable", http.StatusNotFound)
		return
	}

	lastSeq := 0
	if lastEventID := r.Header.Get("Last-Event-ID"); lastEventID != "" {
		if seq, err := strconv.Atoi(lastEventID); err == nil {
			lastSeq = seq
		}
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming SSE non supporté", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	eventCh, unsubscribe := session.SubscribeEvents(lastSeq)
	defer unsubscribe()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-eventCh:
			if !ok {
				return
			}
			dataBytes, _ := json.Marshal(ev)
			fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", ev.Sequence, ev.Type, string(dataBytes))
			flusher.Flush()

			if ev.Type == "session_completed" || ev.Type == "session_cancelled" || ev.Type == "session_failed" {
				return
			}
		}
	}
}

func (s *DaemonServer) handleCancel(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("id")
	session, err := s.sessions.GetSession(runID)
	if err != nil {
		http.Error(w, "Session introuvable", http.StatusNotFound)
		return
	}

	if err := session.CancelSession(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	writeJSON(w, http.StatusOK, CancelResponse{
		RunID:     runID,
		Status:    session.State,
		Cancelled: true,
	})
}

func (s *DaemonServer) handleReport(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("id")
	session, err := s.sessions.GetSession(runID)
	if err != nil {
		http.Error(w, "Session introuvable", http.StatusNotFound)
		return
	}

	session.mu.RLock()
	rep := session.Report
	state := session.State
	session.mu.RUnlock()

	if rep == nil {
		if state == "running" || state == "preparing" {
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  state,
				"message": "Audit en cours de traitement",
			})
			return
		}
		http.Error(w, "Rapport non disponible pour cette session", http.StatusNotFound)
		return
	}

	writeJSON(w, http.StatusOK, rep)
}

func (s *DaemonServer) handleControlLogs(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("id")
	rawControlID := r.PathValue("control_id")

	controlID := rawControlID
	if unescaped, err := url.PathUnescape(rawControlID); err == nil && unescaped != "" {
		controlID = unescaped
	}
	controlID = strings.TrimPrefix(controlID, "/")

	session, err := s.sessions.GetSession(runID)
	if err != nil {
		http.Error(w, "Session introuvable", http.StatusNotFound)
		return
	}

	session.mu.RLock()
	logs, ok := session.Logs[controlID]
	if !ok {
		logs, ok = session.Logs[rawControlID]
	}
	if !ok {
		logs, ok = session.Logs[controlID+"/."]
	}
	if !ok && strings.HasSuffix(controlID, "/.") {
		logs, ok = session.Logs[strings.TrimSuffix(controlID, "/.")]
	}
	session.mu.RUnlock()

	if !ok {
		http.Error(w, fmt.Sprintf("Logs introuvables pour le contrôle %s", controlID), http.StatusNotFound)
		return
	}

	writeJSON(w, http.StatusOK, logs)
}

func (s *DaemonServer) handleShutdown(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "shutting_down",
		"message": "Arrêt propre du démon initié",
	})
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = s.Close(context.Background())
	}()
}

func writeJSON(w http.ResponseWriter, statusCode int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *DaemonServer) handleValidateReport(w http.ResponseWriter, r *http.Request) {
	var req ValidateReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Requête JSON invalide: %v", err), http.StatusBadRequest)
		return
	}

	rep := req.Report
	if rep == nil {
		http.Error(w, "Rapport manquant dans la requête", http.StatusBadRequest)
		return
	}

	v, ok := rep["schema_version"].(float64)
	if !ok || int(v) != 1 {
		http.Error(w, "Rapport v1 invalide ou version inconnue", http.StatusBadRequest)
		return
	}

	presentations, err := ComputePresentations(rep)
	if err != nil {
		http.Error(w, fmt.Sprintf("Échec du calcul des présentations: %v", err), http.StatusBadRequest)
		return
	}

	reportSHA := req.ReportSHA256
	if reportSHA == "" {
		repBytes, _ := json.Marshal(rep)
		h := sha256.Sum256(repBytes)
		reportSHA = hex.EncodeToString(h[:])
	}

	writeJSON(w, http.StatusOK, ValidateReportResponse{
		SchemaVersion: 1,
		ReportSHA256:  reportSHA,
		Presentations: presentations,
	})
}

// ComputePresentations produces the visual presentation array for UI / ReportPanel display.
func ComputePresentations(rep map[string]interface{}) ([]PresentationItem, error) {
	var presentations []PresentationItem
	results, _ := rep["execution_results"].([]interface{})
	plan, _ := rep["execution_plan"].(map[string]interface{})
	var planControls []interface{}
	if plan != nil {
		planControls, _ = plan["controls"].([]interface{})
	}
	discovery, _ := rep["discovery"].(map[string]interface{})
	scanComplete := true
	if discovery != nil {
		if sc, ok := discovery["scan_complete"].(bool); ok {
			scanComplete = sc
		}
	}
	execStatus, _ := rep["execution_status"].(string)

	seenResults := make(map[string]bool)
	for _, resRaw := range results {
		resMap, ok := resRaw.(map[string]interface{})
		if !ok {
			continue
		}
		ctrlID, _ := resMap["control_id"].(string)
		seenResults[ctrlID] = true
		statusStr, _ := resMap["status"].(string)

		presStatus := "Succeeded"
		var reasonObj interface{}
		diags, _ := resMap["diagnostics"].([]interface{})
		if len(diags) > 0 {
			if firstDiag, ok := diags[0].(map[string]interface{}); ok {
				code, _ := firstDiag["code"].(string)
				msg, _ := firstDiag["message"].(string)
				switch code {
				case "dependency_failed", "ambiguous", "capability_unavailable", "tool_unavailable":
					presStatus = "Blocked"
				case "permission_denied", "cancelled_before_start", "cancelled_during_execution":
					presStatus = "Skipped"
				default:
					if statusStr == "fail" {
						presStatus = "Failed"
					} else if statusStr == "error" {
						presStatus = "Error"
					}
				}
				reasonObj = map[string]interface{}{
					"code":    code,
					"message": msg,
				}
			}
		} else {
			switch statusStr {
			case "success":
				presStatus = "Succeeded"
			case "fail":
				presStatus = "Failed"
			case "error":
				presStatus = "Error"
			case "skipped":
				presStatus = "Not applicable"
				reasonObj = map[string]interface{}{
					"code":    "not_applicable",
					"message": "Contrôle non exécuté selon le motif structuré du backend.",
				}
			default:
				presStatus = "Succeeded"
			}
		}

		if (presStatus == "Warning" || presStatus == "Skipped" || presStatus == "Blocked" || presStatus == "Not applicable") && reasonObj == nil {
			reasonObj = map[string]interface{}{
				"code":    "not_applicable",
				"message": "Contrôle non exécuté selon le motif structuré du backend.",
			}
		}

		presentations = append(presentations, PresentationItem{
			ControlID: ctrlID,
			Status:    presStatus,
			Reason:    reasonObj,
		})
	}

	for _, ctrlRaw := range planControls {
		ctrlMap, ok := ctrlRaw.(map[string]interface{})
		if !ok {
			continue
		}
		ctrlID, _ := ctrlMap["id"].(string)
		if seenResults[ctrlID] {
			continue
		}
		applicability, _ := ctrlMap["applicability"].(string)
		reasonCode, _ := ctrlMap["reason_code"].(string)
		code := applicability
		if reasonCode != "" {
			code = reasonCode
		}
		if !scanComplete {
			code = "incomplete_scan"
		}

		var status string
		var reasonObj interface{}
		if !scanComplete {
			status = "Blocked"
		} else if execStatus != "planned" {
			status = "Error"
		} else if applicability == "applicable" {
			status = "Pending"
		} else if code == "permission_denied" {
			status = "Skipped"
		} else if applicability == "ambiguous" || applicability == "capability_unavailable" || applicability == "tool_unavailable" {
			status = "Blocked"
		} else {
			status = "Not applicable"
		}

		if status != "Pending" {
			reasonObj = map[string]interface{}{
				"code":    code,
				"message": "Controle non execute selon le plan backend.",
			}
		}

		presentations = append(presentations, PresentationItem{
			ControlID: ctrlID,
			Status:    status,
			Reason:    reasonObj,
		})
	}

	return presentations, nil
}
