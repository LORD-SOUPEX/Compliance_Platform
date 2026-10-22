package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"compliance/internal/distribution"
	"compliance/internal/osutil"
)

// RegistryInfo is the manifest and catalog the daemon uses, as shown by /health and /registry.
type RegistryInfo struct {
	Source       string `json:"source"`
	ManifestPath string `json:"manifest_path"`
	CatalogPath  string `json:"catalog_path"`
	SigPath      string `json:"sig_path"`
	RegistryURL  string `json:"registry_url"`
	Refreshing   bool   `json:"refreshing"`
}

var (
	// clientTTL is how long a VS Code window counts as alive after its last heartbeat.
	clientTTL = 3 * time.Minute
	// idleCheckInterval paces the idle watch.
	idleCheckInterval = 30 * time.Second
)

// runtimeState holds what changes while the daemon runs: registry, upgrades,
// connected windows and activity. It feeds /health and the idle shutdown.
type runtimeState struct {
	mu           sync.Mutex
	phase        string
	registry     RegistryInfo
	upgrading    map[string]bool
	clients      map[string]time.Time
	everClient   bool
	activeWork   int
	lastActivity time.Time
	done         chan struct{}
	doneOnce     sync.Once
}

func newRuntimeState() *runtimeState {
	return &runtimeState{
		phase:        "ready",
		upgrading:    map[string]bool{},
		clients:      map[string]time.Time{},
		lastActivity: time.Now(),
		done:         make(chan struct{}),
	}
}

func (rt *runtimeState) begin() {
	rt.mu.Lock()
	rt.activeWork++
	rt.lastActivity = time.Now()
	rt.mu.Unlock()
}

func (rt *runtimeState) end() {
	rt.mu.Lock()
	if rt.activeWork > 0 {
		rt.activeWork--
	}
	rt.lastActivity = time.Now()
	rt.mu.Unlock()
}

func (rt *runtimeState) liveClients(now time.Time) int {
	count := 0
	for id, seen := range rt.clients {
		if now.Sub(seen) > clientTTL {
			delete(rt.clients, id)
			continue
		}
		count++
	}
	return count
}

// SetRegistry publishes the registry selection.
func (s *DaemonServer) SetRegistry(info RegistryInfo) {
	s.rt.mu.Lock()
	s.rt.registry = info
	s.rt.mu.Unlock()
}

// SetCatalogPath switches the catalog for the next plans and runs.
func (s *DaemonServer) SetCatalogPath(path string) {
	if path == "" {
		return
	}
	s.sessions.SetCatalogPath(path)
	slog.Info("catalog_switched", "catalog", path)
}

// SetToolUpgrading marks a background upgrade in /health.
func (s *DaemonServer) SetToolUpgrading(tool string, active bool) {
	s.rt.mu.Lock()
	if active {
		s.rt.upgrading[tool] = true
	} else {
		delete(s.rt.upgrading, tool)
	}
	s.rt.mu.Unlock()
}

// Done is closed once the daemon has shut down (signal, /shutdown or idle).
func (s *DaemonServer) Done() <-chan struct{} { return s.rt.done }

// WatchIdle stops the daemon when, after at least one VS Code window registered,
// no window has sent a heartbeat for clientTTL, nothing runs, and the last request
// is older than idle. A daemon started by hand (no client ever) never stops itself.
func (s *DaemonServer) WatchIdle(idle time.Duration) {
	if idle <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(idleCheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-s.rt.done:
				return
			case now := <-ticker.C:
				s.rt.mu.Lock()
				stop := s.rt.everClient && s.rt.liveClients(now) == 0 && s.rt.activeWork == 0 &&
					s.sessions.ActiveRuns() == 0 && now.Sub(s.rt.lastActivity) > idle
				s.rt.mu.Unlock()
				if stop {
					slog.Info("daemon_idle_shutdown", "idle_ms", idle.Milliseconds())
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					_ = s.Close(ctx)
					cancel()
					return
				}
			}
		}
	}()
}

type clientRequest struct {
	ClientID string `json:"client_id"`
	PID      int    `json:"pid"`
	Label    string `json:"label"`
}

func (s *DaemonServer) handleClientRegister(w http.ResponseWriter, r *http.Request) {
	var req clientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.ClientID) == "" || len(req.ClientID) > 128 {
		http.Error(w, "client_id requis", http.StatusBadRequest)
		return
	}
	s.rt.mu.Lock()
	_, known := s.rt.clients[req.ClientID]
	s.rt.clients[req.ClientID] = time.Now()
	s.rt.everClient = true
	s.rt.lastActivity = time.Now()
	count := s.rt.liveClients(time.Now())
	s.rt.mu.Unlock()
	if !known {
		slog.Info("client_registered", "client_id", req.ClientID, "pid", req.PID, "label", req.Label, "clients", count)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"clients": count})
}

func (s *DaemonServer) handleClientUnregister(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.rt.mu.Lock()
	delete(s.rt.clients, id)
	s.rt.lastActivity = time.Now()
	count := s.rt.liveClients(time.Now())
	s.rt.mu.Unlock()
	slog.Info("client_unregistered", "client_id", id, "clients", count)
	writeJSON(w, http.StatusOK, map[string]interface{}{"clients": count})
}

func (s *DaemonServer) handleRegistry(w http.ResponseWriter, _ *http.Request) {
	s.rt.mu.Lock()
	info := s.rt.registry
	s.rt.mu.Unlock()
	writeJSON(w, http.StatusOK, info)
}

func (s *DaemonServer) handleInvalidateTools(w http.ResponseWriter, _ *http.Request) {
	count := s.sessions.resolver.Invalidate()
	slog.Info("probe_cache_invalidated", "entries", count)
	writeJSON(w, http.StatusOK, map[string]interface{}{"invalidated": count})
}

func (s *DaemonServer) healthDetails(resp *HealthResponse) {
	s.rt.mu.Lock()
	defer s.rt.mu.Unlock()
	resp.Phase = s.rt.phase
	registry := s.rt.registry
	resp.Registry = &registry
	resp.ToolsUpgrading = make([]string, 0, len(s.rt.upgrading))
	for tool := range s.rt.upgrading {
		resp.ToolsUpgrading = append(resp.ToolsUpgrading, tool)
	}
	sort.Strings(resp.ToolsUpgrading)
	resp.Clients = s.rt.liveClients(time.Now())
	resp.ActiveRuns = s.sessions.ActiveRuns()
}

// prepareToolUse refreshes PATH, then takes the shared tools lock so that no
// installation replaces a binary while it is probed or executed.
func prepareToolUse(ctx context.Context, clientPath, purpose string, log *slog.Logger) (func(), error) {
	if added := osutil.RefreshPath(clientPath); len(added) > 0 {
		log.Info("path_refreshed", "added", added, "purpose", purpose)
	}
	return distribution.LockTools(ctx, "", false, purpose)
}

// IdleTimeout reads COMPLIANCE_DAEMON_IDLE_MINUTES (0 disables), 30 minutes by default.
func IdleTimeout() time.Duration {
	value := strings.TrimSpace(os.Getenv("COMPLIANCE_DAEMON_IDLE_MINUTES"))
	if value == "" {
		return 30 * time.Minute
	}
	minutes, err := time.ParseDuration(value + "m")
	if err != nil || minutes < 0 {
		return 30 * time.Minute
	}
	return minutes
}
