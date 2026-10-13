package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"compliance/internal/engine"
	"compliance/internal/matrix"
	"compliance/internal/report"
)

var (
	ErrRunNotFound             = errors.New("session d'audit introuvable")
	ErrRunAlreadyFinished      = errors.New("la session d'audit est déjà terminée")
	ErrApplyDestroyNeedsConfirm = errors.New("les étapes apply_destroy ne peuvent être exécutées que de manière unitaire avec confirmation explicite")
)

// Session represents a compliance execution session with event history and SSE broadcasting.
type Session struct {
	mu           sync.RWMutex
	ID           string
	TargetPath   string
	State        string // "preparing", "running", "cancelling", "completed", "cancelled", "failed"
	StartedAt    time.Time
	EndedAt      *time.Time
	Report       *report.Report
	Events       []SessionEvent
	Subscribers  map[chan SessionEvent]struct{}
	Cancel       context.CancelFunc
	Logs         map[string]*ControlLogsResponse
	OutputDir    string
	PlanOnly     bool
	Advisory     bool
	Permissions  struct{ Network, CodeExecution bool }
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

	// 1. Emit session_started event
	session.emitEvent("session_started", nil, nil, nil, map[string]interface{}{
		"target":          req.TargetPath,
		"plan_only":       req.PlanOnly,
		"pipeline_source": sm.platformRoot,
	})

	// Start asynchronous execution
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

	// Setup Callbacks for live event streaming
	opts := engine.ComplianceOptions{
		RepoRoot:             req.TargetPath,
		PlatformRoot:         sm.platformRoot,
		CatalogPath:          sm.catalogPath,
		AllowNetwork:         req.AllowNetwork,
		AllowCodeExecution:   req.AllowCodeExecution,
		PlanOnly:             req.PlanOnly,
		RedactionPatterns: req.RedactionPatterns,
		RunID:                s.ID,
		SourceAdapter:        "VSCode",
		CandidateResolver:    sm.resolver,
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

			// Store logs
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

			// Map status for compliance-session schema
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

	// Persist report to disk
	reportPath := filepath.Join(s.OutputDir, "compliance-report.json")
	if repBytes, mErr := json.MarshalIndent(rep, "", "  "); mErr == nil {
		_ = os.WriteFile(reportPath, repBytes, 0600)
	}

	// Persist execution-plan snapshot if missing
	planPath := filepath.Join(s.OutputDir, "execution-plan.json")
	if _, err := os.Stat(planPath); os.IsNotExist(err) {
		if planBytes, pErr := json.MarshalIndent(rep, "", "  "); pErr == nil {
			_ = os.WriteFile(planPath, planBytes, 0600)
		}
	}

	// Persist session.json
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

	// Persist event to events.ndjson
	if s.OutputDir != "" {
		if b, err := json.Marshal(event); err == nil {
			eventsPath := filepath.Join(s.OutputDir, "events.ndjson")
			if f, err := os.OpenFile(eventsPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600); err == nil {
				_, _ = f.Write(append(b, '\n'))
				_ = f.Close()
			}
		}
	}

	// Broadcast to active SSE subscribers
	for ch := range s.Subscribers {
		select {
		case ch <- event:
		default:
			// Non-blocking write to avoid stuck subscriber
		}
	}
	s.mu.Unlock()
}

// SubscribeEvents registers a channel for SSE event streaming with replay of past events from lastSeq.
func (s *Session) SubscribeEvents(lastSeq int) (chan SessionEvent, func()) {
	ch := make(chan SessionEvent, 100)

	s.mu.Lock()
	// Replay past events
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
