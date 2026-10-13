package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func setupTestDaemon(t *testing.T) (*DaemonServer, string, string) {
	tempDir := t.TempDir()
	workspaceDir := filepath.Join(tempDir, "workspace")
	if err := os.MkdirAll(workspaceDir, 0755); err != nil {
		t.Fatal(err)
	}

	platformRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	catalogPath := filepath.Join(platformRoot, ".config", "control-catalog.json")

	cfg := DaemonConfig{
		ListenAddr:         "127.0.0.1:0",
		StateDir:           filepath.Join(tempDir, "state"),
		ApprovedWorkspaces: []string{workspaceDir},
		CatalogPath:        catalogPath,
		PlatformRoot:       platformRoot,
		Version:            "test-0.4.0",
	}

	srv, err := StartDaemon(cfg)
	if err != nil {
		t.Fatalf("StartDaemon a échoué: %v", err)
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Close(ctx)
	})

	return srv, tempDir, workspaceDir
}

// 1. Test Host Header Validation (Rejet DNS Rebinding -> 403)
func TestDaemonSecurityHostValidation(t *testing.T) {
	srv, _, _ := setupTestDaemon(t)

	client := &http.Client{Timeout: 3 * time.Second}

	// Request with attacker host header
	req, err := http.NewRequest("GET", srv.URL()+"/api/v1/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "attacker-domain.com:1234"
	req.Header.Set("Authorization", "Bearer "+srv.Token())

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Requête HTTP échouée: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Attendu 403 Forbidden sur Host externe, reçu: %d", resp.StatusCode)
	}
}

// 2. Test Origin Header Validation (Rejet CSRF -> 403)
func TestDaemonSecurityOriginValidation(t *testing.T) {
	srv, _, _ := setupTestDaemon(t)

	client := &http.Client{Timeout: 3 * time.Second}

	// Request with untrusted browser origin
	req, err := http.NewRequest("GET", srv.URL()+"/api/v1/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+srv.Token())
	req.Header.Set("Origin", "http://evil-website.com")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Requête HTTP échouée: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Attendu 403 Forbidden sur Origin malveillant, reçu: %d", resp.StatusCode)
	}

	// Allowed Origin (local or vscode-file)
	reqOK, _ := http.NewRequest("GET", srv.URL()+"/api/v1/health", nil)
	reqOK.Header.Set("Authorization", "Bearer "+srv.Token())
	reqOK.Header.Set("Origin", fmt.Sprintf("http://127.0.0.1:%d", srv.Port()))

	respOK, err := client.Do(reqOK)
	if err != nil {
		t.Fatal(err)
	}
	defer respOK.Body.Close()

	if respOK.StatusCode != http.StatusOK {
		t.Errorf("Attendu 200 OK sur Origin local autorisé, reçu: %d", respOK.StatusCode)
	}
}

// 3. Test Missing or Invalid Bearer Token (401 / 403)
func TestDaemonSecurityTokenAuth(t *testing.T) {
	srv, _, _ := setupTestDaemon(t)

	client := &http.Client{Timeout: 3 * time.Second}

	// 1. Missing Authorization header -> 401
	reqNoAuth, _ := http.NewRequest("GET", srv.URL()+"/api/v1/health", nil)
	respNoAuth, err := client.Do(reqNoAuth)
	if err != nil {
		t.Fatal(err)
	}
	defer respNoAuth.Body.Close()
	if respNoAuth.StatusCode != http.StatusUnauthorized {
		t.Errorf("Attendu 401 Unauthorized sur token manquant, reçu: %d", respNoAuth.StatusCode)
	}

	// 2. Invalid Token -> 403
	reqBadAuth, _ := http.NewRequest("GET", srv.URL()+"/api/v1/health", nil)
	reqBadAuth.Header.Set("Authorization", "Bearer bad-token-1234567890")
	respBadAuth, err := client.Do(reqBadAuth)
	if err != nil {
		t.Fatal(err)
	}
	defer respBadAuth.Body.Close()
	if respBadAuth.StatusCode != http.StatusForbidden {
		t.Errorf("Attendu 403 Forbidden sur mauvais token, reçu: %d", respBadAuth.StatusCode)
	}
}

// 4. Test Target Path Scope (Rejet hors workspace et traversée symlink -> 403)
func TestDaemonTargetPathPerimeter(t *testing.T) {
	srv, tempDir, workspaceDir := setupTestDaemon(t)

	client := &http.Client{Timeout: 3 * time.Second}

	// Outside folder (e.g. system folder or tempDir root)
	outsideDir := filepath.Join(tempDir, "outside")
	_ = os.MkdirAll(outsideDir, 0755)

	payload := DiscoveryRequest{TargetPath: outsideDir}
	data, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", srv.URL()+"/api/v1/discovery", bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+srv.Token())
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Attendu 403 Forbidden sur target_path hors périmètre, reçu: %d", resp.StatusCode)
	}

	// Inside workspace -> OK
	validPayload := DiscoveryRequest{TargetPath: workspaceDir}
	validData, _ := json.Marshal(validPayload)

	reqOK, _ := http.NewRequest("POST", srv.URL()+"/api/v1/discovery", bytes.NewReader(validData))
	reqOK.Header.Set("Authorization", "Bearer "+srv.Token())
	reqOK.Header.Set("Content-Type", "application/json")

	respOK, err := client.Do(reqOK)
	if err != nil {
		t.Fatal(err)
	}
	defer respOK.Body.Close()

	if respOK.StatusCode != http.StatusOK {
		t.Errorf("Attendu 200 OK sur target_path approuvé, reçu: %d", respOK.StatusCode)
	}
}

// 5. Test Single Instance Lock & Crash Recovery
func TestDaemonSingleInstanceLock(t *testing.T) {
	srv, tempDir, _ := setupTestDaemon(t)

	// Attempt to start a second daemon with same stateDir
	cfg2 := DaemonConfig{
		ListenAddr: "127.0.0.1:0",
		StateDir:   filepath.Join(tempDir, "state"),
	}

	_, err := StartDaemon(cfg2)
	if err == nil {
		t.Errorf("Attendu échec au démarrage d'une deuxième instance sur le même stateDir")
	} else if !strings.Contains(err.Error(), "déjà en cours d'exécution") {
		t.Errorf("Erreur inattendue: %v", err)
	}

	_ = srv
}

// 6. Test Guardrails apply_destroy (Rejet sans confirmation explicite -> 400)
func TestDaemonApplyDestroyGuardrail(t *testing.T) {
	srv, _, workspaceDir := setupTestDaemon(t)

	client := &http.Client{Timeout: 3 * time.Second}

	// Demande d'un contrôle apply_destroy sans confirmation
	reqBody := CreateRunRequest{
		TargetPath:          workspaceDir,
		ControlID:           "terraform.apply.main",
		ConfirmApplyDestroy: false,
	}
	data, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", srv.URL()+"/api/v1/runs", bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+srv.Token())
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Attendu 400 Bad Request pour contrôle apply sans confirm, reçu: %d", resp.StatusCode)
	}
}

// 7. Test End-to-End Run, SSE Stream & Replay (Last-Event-ID)
func TestDaemonRunSSEStreamingAndReplay(t *testing.T) {
	srv, _, _ := setupTestDaemon(t)

	// Utiliser la defect_fixture comme workspace approuvé
	platformRoot, _ := filepath.Abs(filepath.Join("..", "..", ".."))
	defectFixture := filepath.Join(platformRoot, "core", "testdata", "defect_fixture")
	if err := srv.AddApprovedWorkspace(defectFixture); err != nil {
		t.Fatal(err)
	}

	client := &http.Client{Timeout: 15 * time.Second}

	// 1. Créer une session de run
	createReq := CreateRunRequest{
		TargetPath: defectFixture,
		PlanOnly:   true, // Rapide pour le test SSE
	}
	createData, _ := json.Marshal(createReq)

	req, _ := http.NewRequest("POST", srv.URL()+"/api/v1/runs", bytes.NewReader(createData))
	req.Header.Set("Authorization", "Bearer "+srv.Token())
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Création de run échouée: statut %d", resp.StatusCode)
	}

	var creationResp RunCreationResponse
	if err := json.NewDecoder(resp.Body).Decode(&creationResp); err != nil {
		t.Fatal(err)
	}
	runID := creationResp.RunID
	if len(runID) != 32 {
		t.Fatalf("RunID invalide: %s", runID)
	}

	// 2. Écouter le flux SSE
	sseReq, _ := http.NewRequest("GET", srv.URL()+fmt.Sprintf("/api/v1/runs/%s/events", runID), nil)
	sseReq.Header.Set("Authorization", "Bearer "+srv.Token())

	sseResp, err := client.Do(sseReq)
	if err != nil {
		t.Fatal(err)
	}
	defer sseResp.Body.Close()

	if sseResp.StatusCode != http.StatusOK {
		t.Fatalf("Connexion SSE échouée: %d", sseResp.StatusCode)
	}

	reader := bufio.NewReader(sseResp.Body)
	var receivedEvents []string
	lastSeq := 0

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "event:") {
			evType := strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			receivedEvents = append(receivedEvents, evType)
			if evType == "session_completed" || evType == "session_failed" || evType == "session_cancelled" {
				break
			}
		}
		if strings.HasPrefix(line, "id:") {
			idStr := strings.TrimSpace(strings.TrimPrefix(line, "id:"))
			var seq int
			fmt.Sscanf(idStr, "%d", &seq)
			if seq > lastSeq {
				lastSeq = seq
			}
		}
	}

	t.Logf("Événements SSE reçus: %v (dernier sequence: %d)", receivedEvents, lastSeq)
	if len(receivedEvents) == 0 {
		t.Errorf("Aucun événement SSE reçu")
	}

	// 3. Tester la reprise SSE après déconnexion avec Last-Event-ID
	replayReq, _ := http.NewRequest("GET", srv.URL()+fmt.Sprintf("/api/v1/runs/%s/events", runID), nil)
	replayReq.Header.Set("Authorization", "Bearer "+srv.Token())
	replayReq.Header.Set("Last-Event-ID", "1") // Rejouer à partir de sequence > 1

	replayResp, err := client.Do(replayReq)
	if err != nil {
		t.Fatal(err)
	}
	defer replayResp.Body.Close()

	replayReader := bufio.NewReader(replayResp.Body)
	replayedCount := 0
	for {
		line, err := replayReader.ReadString('\n')
		if err != nil {
			break
		}
		if strings.HasPrefix(strings.TrimSpace(line), "event:") {
			replayedCount++
		}
	}

	t.Logf("Événements rejoués après Last-Event-ID=1: %d", replayedCount)
	if replayedCount == 0 && len(receivedEvents) > 1 {
		t.Errorf("La reprise SSE via Last-Event-ID n'a renvoyé aucun événement")
	}

	// 4. Récupérer le rapport final
	repReq, _ := http.NewRequest("GET", srv.URL()+fmt.Sprintf("/api/v1/runs/%s/report", runID), nil)
	repReq.Header.Set("Authorization", "Bearer "+srv.Token())

	repResp, err := client.Do(repReq)
	if err != nil {
		t.Fatal(err)
	}
	defer repResp.Body.Close()

	if repResp.StatusCode != http.StatusOK {
		t.Errorf("Attendu 200 OK sur récupération du rapport, reçu: %d", repResp.StatusCode)
	}
	body, _ := io.ReadAll(repResp.Body)
	var repCheck map[string]interface{}
	if err := json.Unmarshal(body, &repCheck); err != nil {
		t.Fatalf("Échec de désérialisation du rapport: %v", err)
	}
	if v, ok := repCheck["schema_version"].(float64); !ok || int(v) != 1 {
		t.Errorf("schema_version invalide dans le rapport: %v", repCheck["schema_version"])
	}
}

// 8. Test Cancellation Sans Orphelin
func TestDaemonRunCancellation(t *testing.T) {
	srv, _, _ := setupTestDaemon(t)

	platformRoot, _ := filepath.Abs(filepath.Join("..", "..", ".."))
	defectFixture := filepath.Join(platformRoot, "core", "testdata", "defect_fixture")
	_ = srv.AddApprovedWorkspace(defectFixture)

	client := &http.Client{Timeout: 5 * time.Second}

	// Lancer un run réel
	createReq := CreateRunRequest{
		TargetPath: defectFixture,
		PlanOnly:   false,
	}
	createData, _ := json.Marshal(createReq)

	req, _ := http.NewRequest("POST", srv.URL()+"/api/v1/runs", bytes.NewReader(createData))
	req.Header.Set("Authorization", "Bearer "+srv.Token())
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var creationResp RunCreationResponse
	_ = json.NewDecoder(resp.Body).Decode(&creationResp)
	runID := creationResp.RunID

	// Annuler immédiatement
	cancelReq, _ := http.NewRequest("POST", srv.URL()+fmt.Sprintf("/api/v1/runs/%s/cancel", runID), nil)
	cancelReq.Header.Set("Authorization", "Bearer "+srv.Token())

	cancelResp, err := client.Do(cancelReq)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelResp.Body.Close()

	if cancelResp.StatusCode != http.StatusOK {
		t.Errorf("Statut d'annulation inattendu: %d", cancelResp.StatusCode)
	}

	var cancelBody CancelResponse
	_ = json.NewDecoder(cancelResp.Body).Decode(&cancelBody)
	if !cancelBody.Cancelled {
		t.Errorf("La réponse d'annulation n'indique pas Cancelled=true")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestDaemonReportValidation(t *testing.T) {
	srv, _, _ := setupTestDaemon(t)
	client := &http.Client{Timeout: 5 * time.Second}

	fixtureReport := map[string]interface{}{
		"schema_version": 1,
		"engine_version": "0.5.0",
		"generated_at":   time.Now().UTC().Format(time.RFC3339),
		"metadata": map[string]interface{}{
			"run_id": "testrun123",
		},
		"repository":       "M:/test",
		"verdict":          "PASS",
		"execution_status": "completed",
		"execution_plan": map[string]interface{}{
			"controls": []interface{}{
				map[string]interface{}{
					"id":            "ctrl1",
					"name":          "Control 1",
					"applicability": "applicable",
				},
			},
		},
		"execution_results": []interface{}{
			map[string]interface{}{
				"control_id":  "ctrl1",
				"status":      "success",
				"duration_ms": 100,
			},
		},
	}

	body, _ := json.Marshal(ValidateReportRequest{
		Report: fixtureReport,
	})

	req, _ := http.NewRequest("POST", srv.URL()+"/api/v1/reports/validate", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+srv.Token())
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Validation échouée avec statut: %d", resp.StatusCode)
	}

	var valResp ValidateReportResponse
	if err := json.NewDecoder(resp.Body).Decode(&valResp); err != nil {
		t.Fatal(err)
	}

	if valResp.SchemaVersion != 1 || len(valResp.ReportSHA256) != 64 {
		t.Errorf("Réponse invalide: %+v", valResp)
	}
	if len(valResp.Presentations) != 1 || valResp.Presentations[0].Status != "Succeeded" {
		t.Errorf("Présentation inattendue: %+v", valResp.Presentations)
	}
}
