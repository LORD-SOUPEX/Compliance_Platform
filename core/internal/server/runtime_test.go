package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func startTestDaemon(t *testing.T) *DaemonServer {
	t.Helper()
	srv, err := StartDaemon(DaemonConfig{StateDir: filepath.Join(t.TempDir(), "state"), Version: "test", PlatformRoot: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func call(t *testing.T, srv *DaemonServer, method, path string, body interface{}) map[string]interface{} {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, srv.URL()+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+srv.Token())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s %s = %d", method, path, resp.StatusCode)
	}
	out := map[string]interface{}{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

func TestClientsIdleShutdownAndHealth(t *testing.T) {
	previousCheck, previousTTL := idleCheckInterval, clientTTL
	idleCheckInterval, clientTTL = 50*time.Millisecond, 5*time.Second
	defer func() { idleCheckInterval, clientTTL = previousCheck, previousTTL }()

	srv := startTestDaemon(t)
	srv.SetRegistry(RegistryInfo{Source: "local", Refreshing: true})
	srv.SetToolUpgrading("trivy", true)
	srv.WatchIdle(100 * time.Millisecond)

	if got := call(t, srv, "POST", "/api/v1/clients", map[string]interface{}{"client_id": "window-a", "pid": 1}); got["clients"] != float64(1) {
		t.Fatalf("register = %v", got)
	}
	health := call(t, srv, "GET", "/api/v1/health", nil)
	registry, _ := health["registry"].(map[string]interface{})
	upgrading, _ := health["tools_upgrading"].([]interface{})
	if health["phase"] != "ready" || health["clients"] != float64(1) || registry["source"] != "local" || len(upgrading) != 1 {
		t.Fatalf("health = %v", health)
	}

	// A live client keeps the daemon up past the idle delay.
	for i := 0; i < 4; i++ {
		time.Sleep(100 * time.Millisecond)
		call(t, srv, "POST", "/api/v1/clients", map[string]interface{}{"client_id": "window-a"})
	}
	select {
	case <-srv.Done():
		t.Fatal("daemon stopped while a window was connected")
	default:
	}

	call(t, srv, "DELETE", "/api/v1/clients/window-a", nil)
	select {
	case <-srv.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("daemon did not stop once idle without clients")
	}
}

func TestDaemonWithoutClientsNeverStopsItself(t *testing.T) {
	previousCheck := idleCheckInterval
	idleCheckInterval = 20 * time.Millisecond
	defer func() { idleCheckInterval = previousCheck }()
	srv := startTestDaemon(t)
	defer srv.Close(context.Background())
	srv.WatchIdle(10 * time.Millisecond)
	time.Sleep(200 * time.Millisecond)
	select {
	case <-srv.Done():
		t.Fatal("a hand-started daemon stopped by itself")
	default:
	}
	if got := call(t, srv, "POST", "/api/v1/tools/invalidate", nil); got["invalidated"] == nil {
		t.Fatalf("invalidate = %v", got)
	}
}
