package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"compliance/internal/discovery"
	"compliance/internal/engine"
)

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
		cfg.Version = "0.4.0-phase4"
	}

	lockPath := filepath.Join(cfg.StateDir, "daemon.lock")
	tokenPath := filepath.Join(cfg.StateDir, "daemon.token")
	statePath := filepath.Join(cfg.StateDir, "daemon.json")

	// 1. Acquire single-instance lock (with crash recovery)
	if err := AcquireLock(lockPath); err != nil {
		return nil, err
	}

	// 2. Generate 256-bit cryptographically secure Bearer token
	token, err := GenerateBearerToken()
	if err != nil {
		ReleaseLock(lockPath)
		return nil, err
	}

	// 3. Write protected token (POSIX 0600 / Windows ACL)
	if err := WriteProtectedToken(tokenPath, token); err != nil {
		ReleaseLock(lockPath)
		return nil, err
	}

	// 4. Bind strictly to local loopback
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		ReleaseLock(lockPath)
		_ = os.Remove(tokenPath)
		return nil, fmt.Errorf("écoute sur %s impossible: %w", cfg.ListenAddr, err)
	}

	tcpAddr := listener.Addr().(*net.TCPAddr)
	port := tcpAddr.Port

	// 5. Initialize Security & Sessions
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

	// 6. Write daemon.json state file
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

	// 7. Configure HTTP mux
	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	// Wrap entire mux with security middleware (Host & Origin validation)
	srv.httpServer = &http.Server{
		Handler:      security.Middleware(mux),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0, // SSE streams require no write timeout
	}

	// Start serving in background
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
	mux.HandleFunc("GET /api/v1/runs/{id}/logs/{control_id}", s.handleControlLogs)
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
	if err := s.security.AddApprovedWorkspace(req.WorkspacePath); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "approved",
		"workspace": req.WorkspacePath,
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

	// Run compliance in PlanOnly mode
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

	// Filter out apply_destroy if not requested
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

	// Guardrail: verify apply_destroy constraints
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

	// Check Last-Event-ID for reconnection and replay
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

			// Close stream upon terminal event
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
	controlID := r.PathValue("control_id")

	session, err := s.sessions.GetSession(runID)
	if err != nil {
		http.Error(w, "Session introuvable", http.StatusNotFound)
		return
	}

	session.mu.RLock()
	logs, ok := session.Logs[controlID]
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

	// Validate minimal report schema v1
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

// ComputePresentations produces the visual presentation array for reportReader display.
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
