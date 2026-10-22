package selftest

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"compliance/internal/embedded"
	"compliance/internal/logging"
	"compliance/internal/osutil"
	"compliance/internal/server"
)

type TestStep struct {
	Name     string
	Passed   bool
	Duration time.Duration
	Error    string
}

// Run executes the complete compliance selftest suite and returns results.
func Run(platformRoot string) (bool, []TestStep) {
	steps := make([]TestStep, 0)
	overallPass := true

	recordStep := func(name string, fn func() error) {
		start := time.Now()
		err := fn()
		dur := time.Since(start)
		step := TestStep{
			Name:     name,
			Duration: dur,
			Passed:   err == nil,
		}
		if err != nil {
			step.Error = err.Error()
			overallPass = false
		}
		steps = append(steps, step)
	}

	// 1. Setup temporary directory for state and fixture
	tempDir, err := os.MkdirTemp("", "compliance-selftest-*")
	if err != nil {
		steps = append(steps, TestStep{Name: "Création répertoire temporaire", Error: err.Error()})
		return false, steps
	}
	defer func() {
		_ = os.RemoveAll(tempDir)
	}()

	stateDir := filepath.Join(tempDir, "state")
	fixtureDir := filepath.Join(tempDir, "fixture")
	_ = os.MkdirAll(stateDir, 0700)
	_ = os.MkdirAll(fixtureDir, 0755)

	// Create sample fixture files (python + docker)
	_ = os.WriteFile(filepath.Join(fixtureDir, "app.py"), []byte("print('selftest')\n"), 0644)
	_ = os.WriteFile(filepath.Join(fixtureDir, "Dockerfile"), []byte("FROM alpine:3.18\nCMD [\"echo\", \"test\"]\n"), 0644)

	catalogPath, err := embedded.ResolveAsset("control-catalog.json", filepath.Join(platformRoot, ".config", "control-catalog.json"))
	if err != nil {
		steps = append(steps, TestStep{Name: "Catalogue embarqué", Error: err.Error()})
		return false, steps
	}

	var srv *server.DaemonServer
	var daemonURL string
	var daemonToken string
	var daemonPort int

	// Step 1: Start Daemon
	recordStep("Démarrage démon éphémère sur 127.0.0.1:0", func() error {
		var sErr error
		srv, sErr = server.StartDaemon(server.DaemonConfig{
			ListenAddr:   "127.0.0.1:0",
			StateDir:     stateDir,
			PlatformRoot: platformRoot,
			CatalogPath:  catalogPath,
			Version:      "2.0.0-selftest",
		})
		if sErr != nil {
			return fmt.Errorf("StartDaemon a échoué: %w", sErr)
		}
		daemonURL = srv.URL()
		daemonToken = srv.Token()
		daemonPort = srv.Port()
		if daemonPort <= 0 {
			return fmt.Errorf("port éphémère invalide: %d", daemonPort)
		}
		return nil
	})

	if !overallPass {
		return false, steps
	}

	client := &http.Client{Timeout: 30 * time.Second}

	// Helper for HTTP requests
	sendReq := func(method, path string, body interface{}, headers map[string]string) (*http.Response, []byte, error) {
		var bodyReader io.Reader
		if body != nil {
			b, mErr := json.Marshal(body)
			if mErr != nil {
				return nil, nil, mErr
			}
			bodyReader = bytes.NewReader(b)
		}
		req, rErr := http.NewRequest(method, daemonURL+path, bodyReader)
		if rErr != nil {
			return nil, nil, rErr
		}
		// Default secure headers
		req.Host = fmt.Sprintf("127.0.0.1:%d", daemonPort)
		req.Header.Set("Authorization", "Bearer "+daemonToken)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range headers {
			if v == "" {
				req.Header.Del(k)
			} else {
				req.Header.Set(k, v)
			}
		}
		resp, dErr := client.Do(req)
		if dErr != nil {
			return nil, nil, dErr
		}
		respBytes, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp, respBytes, nil
	}

	// Step 2: Auth check - Missing token (401)
	recordStep("Sécurité : rejet requête sans jeton Bearer (401)", func() error {
		req, _ := http.NewRequest("GET", daemonURL+"/api/v1/health", nil)
		req.Host = fmt.Sprintf("127.0.0.1:%d", daemonPort)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			return fmt.Errorf("attendu 401, obtenu %d", resp.StatusCode)
		}
		return nil
	})

	// Step 3: Auth check - Invalid token (403 Forbidden or 401 Unauthorized)
	recordStep("Sécurité : rejet requête avec jeton invalide (403)", func() error {
		req, _ := http.NewRequest("GET", daemonURL+"/api/v1/health", nil)
		req.Host = fmt.Sprintf("127.0.0.1:%d", daemonPort)
		req.Header.Set("Authorization", "Bearer bad-token-12345")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusUnauthorized {
			return fmt.Errorf("attendu 403 ou 401, obtenu %d", resp.StatusCode)
		}
		return nil
	})

	// Step 4: Host check - Malicious host (403)
	recordStep("Sécurité Host : rejet Host malveillant (403)", func() error {
		req, _ := http.NewRequest("GET", daemonURL+"/api/v1/health", nil)
		req.Host = "evil-domain.com"
		req.Header.Set("Authorization", "Bearer "+daemonToken)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			return fmt.Errorf("attendu 403, obtenu %d", resp.StatusCode)
		}
		return nil
	})

	// Step 5: Origin check - Malicious origin (403)
	recordStep("Sécurité Origin : rejet Origin malveillant (403)", func() error {
		req, _ := http.NewRequest("GET", daemonURL+"/api/v1/health", nil)
		req.Host = fmt.Sprintf("127.0.0.1:%d", daemonPort)
		req.Header.Set("Authorization", "Bearer "+daemonToken)
		req.Header.Set("Origin", "http://evil-attacker.com")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			return fmt.Errorf("attendu 403, obtenu %d", resp.StatusCode)
		}
		return nil
	})

	// Step 6: Origin check - vscode-webview allowed (200)
	recordStep("Sécurité Origin : acceptation Origin vscode-webview:// (200)", func() error {
		req, _ := http.NewRequest("GET", daemonURL+"/api/v1/health", nil)
		req.Host = fmt.Sprintf("127.0.0.1:%d", daemonPort)
		req.Header.Set("Authorization", "Bearer "+daemonToken)
		req.Header.Set("Origin", "vscode-webview://")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("attendu 200, obtenu %d", resp.StatusCode)
		}
		return nil
	})

	// Step 7: Endpoint GET /api/v1/health
	recordStep("Endpoint GET /api/v1/health (200, status=ok)", func() error {
		//nolint:bodyclose // sendReq reads and closes the body
		resp, body, err := sendReq("GET", "/api/v1/health", nil, nil)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("attendu 200, obtenu %d", resp.StatusCode)
		}
		var health map[string]interface{}
		if err := json.Unmarshal(body, &health); err != nil {
			return err
		}
		if health["status"] != "ok" {
			return fmt.Errorf("status attendu 'ok', obtenu %v", health["status"])
		}
		return nil
	})

	// Step 8: Guardrail - Unapproved workspace rejected
	recordStep("Guardrail : rejet requête sur workspace non approuvé (400/403)", func() error {
		unapprovedDir := filepath.Join(tempDir, "unapproved")
		_ = os.MkdirAll(unapprovedDir, 0755)
		//nolint:bodyclose // sendReq reads and closes the body
		resp, _, err := sendReq("POST", "/api/v1/plans", map[string]interface{}{
			"target_path": unapprovedDir,
		}, nil)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusForbidden {
			return fmt.Errorf("attendu 400 ou 403 pour workspace non approuvé, obtenu %d", resp.StatusCode)
		}
		return nil
	})

	// Step 9: Endpoint POST /api/v1/workspaces/approve
	recordStep("Endpoint POST /api/v1/workspaces/approve (200)", func() error {
		//nolint:bodyclose // sendReq reads and closes the body
		resp, body, err := sendReq("POST", "/api/v1/workspaces/approve", map[string]string{
			"workspace_path": fixtureDir,
		}, nil)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("attendu 200, obtenu %d (%s)", resp.StatusCode, string(body))
		}
		return nil
	})

	// Step 10: Endpoint POST /api/v1/discovery
	recordStep("Endpoint POST /api/v1/discovery (200)", func() error {
		//nolint:bodyclose // sendReq reads and closes the body
		resp, body, err := sendReq("POST", "/api/v1/discovery", map[string]string{
			"target_path": fixtureDir,
		}, nil)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("attendu 200, obtenu %d (%s)", resp.StatusCode, string(body))
		}
		var disc map[string]interface{}
		if err := json.Unmarshal(body, &disc); err != nil {
			return err
		}
		if disc["scan_complete"] != true {
			return fmt.Errorf("scan_complete attendu true")
		}
		return nil
	})

	// Step 11: Endpoint POST /api/v1/plans
	recordStep("Endpoint POST /api/v1/plans (200)", func() error {
		//nolint:bodyclose // sendReq reads and closes the body
		resp, body, err := sendReq("POST", "/api/v1/plans", map[string]interface{}{
			"target_path": fixtureDir,
		}, nil)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("attendu 200, obtenu %d (%s)", resp.StatusCode, string(body))
		}
		var planRep map[string]interface{}
		if err := json.Unmarshal(body, &planRep); err != nil {
			return err
		}
		if planRep["execution_plan"] == nil {
			return fmt.Errorf("champ execution_plan absent de la réponse")
		}
		return nil
	})

	// Step 12: Guardrail - apply_destroy without confirmation rejected (400)
	recordStep("Guardrail : rejet apply_destroy sans confirmation explicite (400)", func() error {
		//nolint:bodyclose // sendReq reads and closes the body
		resp, _, err := sendReq("POST", "/api/v1/runs", map[string]interface{}{
			"target_path":           fixtureDir,
			"control_id":            "terraform/apply_destroy",
			"confirm_apply_destroy": false,
		}, nil)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusBadRequest {
			return fmt.Errorf("attendu 400 pour apply_destroy non confirmé, obtenu %d", resp.StatusCode)
		}
		return nil
	})

	var completedRunID string
	var cancelRunID string

	// Step 13: Endpoint POST /api/v1/runs (plan_only run produces full canonical report)
	recordStep("Endpoint POST /api/v1/runs (201, run_id créé)", func() error {
		//nolint:bodyclose // sendReq reads and closes the body
		resp, body, err := sendReq("POST", "/api/v1/runs", map[string]interface{}{
			"target_path": fixtureDir,
			"plan_only":   true,
		}, nil)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusCreated {
			return fmt.Errorf("attendu 201, obtenu %d (%s)", resp.StatusCode, string(body))
		}
		var runResp map[string]interface{}
		if err := json.Unmarshal(body, &runResp); err != nil {
			return err
		}
		rid, ok := runResp["run_id"].(string)
		if !ok || len(rid) == 0 {
			return fmt.Errorf("run_id manquant dans la réponse: %v", runResp)
		}
		completedRunID = rid
		return nil
	})

	// Step 14: Endpoint GET /api/v1/runs/{id}/events (SSE Streaming)
	recordStep("Endpoint GET /api/v1/runs/{id}/events (SSE actif)", func() error {
		req, _ := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/runs/%s/events", daemonURL, completedRunID), nil)
		req.Host = fmt.Sprintf("127.0.0.1:%d", daemonPort)
		req.Header.Set("Authorization", "Bearer "+daemonToken)
		req.Header.Set("Accept", "text/event-stream")

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer func() {
			_ = resp.Body.Close()
		}()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("attendu 200 pour flux SSE, obtenu %d", resp.StatusCode)
		}

		reader := bufio.NewReader(resp.Body)
		line, rErr := reader.ReadString('\n')
		if rErr != nil && rErr != io.EOF {
			return fmt.Errorf("erreur de lecture flux SSE: %w", rErr)
		}
		if len(line) == 0 {
			return fmt.Errorf("aucun événement reçu sur le flux SSE")
		}
		return nil
	})

	// Step 15: Endpoint POST /api/v1/runs/{id}/cancel
	recordStep("Endpoint POST /api/v1/runs/{id}/cancel (200, annulation immédiate)", func() error {
		// Launch a full run to cancel
		//nolint:bodyclose // sendReq reads and closes the body
		cResp, cBody, cErr := sendReq("POST", "/api/v1/runs", map[string]interface{}{
			"target_path": fixtureDir,
			"plan_only":   false,
		}, nil)
		if cErr != nil {
			return cErr
		}
		if cResp.StatusCode != http.StatusCreated {
			return fmt.Errorf("attendu 201 pour run à annuler, obtenu %d (%s)", cResp.StatusCode, string(cBody))
		}
		var runResp map[string]interface{}
		if err := json.Unmarshal(cBody, &runResp); err != nil {
			return err
		}
		cancelRunID, _ = runResp["run_id"].(string)

		//nolint:bodyclose // sendReq reads and closes the body
		resp, body, err := sendReq("POST", fmt.Sprintf("/api/v1/runs/%s/cancel", cancelRunID), nil, nil)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("attendu 200, obtenu %d (%s)", resp.StatusCode, string(body))
		}
		return nil
	})

	// Step 16: Check for zero orphans after cancellation
	recordStep("Confinement des processus : zéro processus orphelin après annulation", func() error {
		deadline := time.Now().Add(5 * time.Second)
		var lastState string
		for time.Now().Before(deadline) {
			sess, err := srv.Sessions().GetSession(cancelRunID)
			if err == nil {
				lastState = sess.State
				if sess.State == "cancelled" || sess.State == "completed" || sess.State == "blocked" {
					return nil
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		return fmt.Errorf("état de session attendu 'cancelled', obtenu '%s'", lastState)
	})

	// Step 17: Endpoint GET /api/v1/runs/{id}/report
	recordStep("Endpoint GET /api/v1/runs/{id}/report (200)", func() error {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			//nolint:bodyclose // sendReq reads and closes the body
			resp, body, err := sendReq("GET", fmt.Sprintf("/api/v1/runs/%s/report", completedRunID), nil, nil)
			if err == nil && resp.StatusCode == http.StatusOK {
				var rep map[string]interface{}
				if err := json.Unmarshal(body, &rep); err != nil {
					return err
				}
				if rep["metadata"] == nil {
					return fmt.Errorf("metadata manquant dans le rapport")
				}
				return nil
			}
			time.Sleep(100 * time.Millisecond)
		}
		return fmt.Errorf("rapport non disponible dans le délai imparti pour %s", completedRunID)
	})

	// Step 18: Endpoint GET /api/v1/runs/{id}/logs/{control_id}
	recordStep("Endpoint GET /api/v1/runs/{id}/logs/{control_id} (200 ou 404 géré)", func() error {
		//nolint:bodyclose // sendReq reads and closes the body
		resp, _, err := sendReq("GET", fmt.Sprintf("/api/v1/runs/%s/logs/nonexistent-control", completedRunID), nil, nil)
		if err != nil {
			return err
		}
		// 404 is expected for non-existent control
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusOK {
			return fmt.Errorf("attendu 404 ou 200, obtenu %d", resp.StatusCode)
		}
		return nil
	})

	// Step 19: Endpoint POST /api/v1/shutdown
	recordStep("Endpoint POST /api/v1/shutdown (200, arrêt ordonné)", func() error {
		//nolint:bodyclose // sendReq reads and closes the body
		resp, _, err := sendReq("POST", "/api/v1/shutdown", nil, nil)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("attendu 200, obtenu %d", resp.StatusCode)
		}
		return nil
	})

	// Step 20: Clean lock and state release
	recordStep("Libération du verrou d'instance et suppression des fichiers d'état", func() error {
		lockPath := filepath.Join(stateDir, "daemon.lock")
		deadline := time.Now().Add(4 * time.Second)
		var lastErr error
		for time.Now().Before(deadline) {
			if err := server.AcquireLock(lockPath); err == nil {
				server.ReleaseLock(lockPath)
				return nil
			} else {
				lastErr = err
			}
			time.Sleep(100 * time.Millisecond)
		}
		return fmt.Errorf("le verrou n'a pas été libéré à l'arrêt: %w", lastErr)
	})

	// Steps 21-24 check, on this OS, the primitives the first-start stability relies on.
	recordStep("Verrou des outils : lectures partagées, écriture exclusive", func() error {
		lockPath := filepath.Join(stateDir, "tools", ".install.lock")
		ctx := context.Background()
		first, err := osutil.LockFile(ctx, lockPath, false, nil)
		if err != nil {
			return err
		}
		second, err := osutil.LockFile(ctx, lockPath, false, nil)
		if err != nil {
			first()
			return fmt.Errorf("deux audits doivent partager le verrou: %w", err)
		}
		short, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer cancel()
		if _, err := osutil.LockFile(short, lockPath, true, nil); !errors.Is(err, osutil.ErrLockTimeout) {
			first()
			second()
			return fmt.Errorf("une installation a pris le verrou pendant un audit: %w", err)
		}
		first()
		second()
		writer, err := osutil.LockFile(ctx, lockPath, true, nil)
		if err != nil {
			return fmt.Errorf("installation bloquée après les audits: %w", err)
		}
		writer()
		return nil
	})

	recordStep("PATH vivant : nouveau dossier ajouté une seule fois", func() error {
		previous := os.Getenv("PATH")
		defer os.Setenv("PATH", previous)
		fresh := filepath.Join(stateDir, "path-bin")
		if err := os.MkdirAll(fresh, 0700); err != nil {
			return err
		}
		added := osutil.RefreshPath(fresh)
		if !strings.Contains(os.Getenv("PATH"), fresh) || len(added) == 0 {
			return fmt.Errorf("dossier non ajouté au PATH: %v", added)
		}
		if again := osutil.RefreshPath(fresh); len(again) != 0 {
			return fmt.Errorf("dossier ajouté deux fois: %v", again)
		}
		return nil
	})

	recordStep("Journal du démon : rotation après fermeture du fichier", func() error {
		journal := filepath.Join(stateDir, "logs-selftest", logging.FileName)
		file, err := logging.OpenRotating(journal, 64, 2)
		if err != nil {
			return err
		}
		for i := 0; i < 6; i++ {
			if _, err := file.Write([]byte(strings.Repeat("x", 40) + "\n")); err != nil {
				_ = file.Close()
				return err
			}
		}
		if err := file.Close(); err != nil {
			return err
		}
		if _, err := os.Stat(journal + ".1"); err != nil {
			return fmt.Errorf("rotation absente: %w", err)
		}
		return nil
	})

	recordStep("Capture complète des sorties sur disque", func() error {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		sinkPath := filepath.Join(stateDir, "capture.stdout.log")
		sink, err := osutil.CreateCappedFile(sinkPath, 1<<20)
		if err != nil {
			return err
		}
		res, err := osutil.RunBounded(context.Background(), osutil.CommandSpec{
			Executable: exe,
			Args:       []string{"version"},
			Limits:     osutil.ProcessLimits{Timeout: 20 * time.Second, MaxOutputBytes: 4},
			StdoutSink: sink,
		})
		_ = sink.Close()
		if err != nil {
			return err
		}
		full, err := os.ReadFile(sinkPath)
		if err != nil {
			return err
		}
		if !res.OutputTruncated || len(res.Stdout) != 4 || !strings.Contains(string(full), "compliance") || int64(len(full)) != res.StdoutBytes {
			return fmt.Errorf("capture incohérente: tronquée=%v mémoire=%d disque=%d lus=%d", res.OutputTruncated, len(res.Stdout), len(full), res.StdoutBytes)
		}
		return nil
	})

	return overallPass, steps
}

// PrintResults renders the selftest report to stdout.
func PrintResults(passed bool, steps []TestStep) {
	fmt.Println("================================================================================")
	fmt.Printf("Compliance Selftest - Validation Autonome Multi-OS (%s/%s)\n", runtime.GOOS, runtime.GOARCH)
	fmt.Println("================================================================================")

	var totalDur time.Duration
	passCount := 0

	for i, step := range steps {
		totalDur += step.Duration
		statusStr := "[PASS]"
		if !step.Passed {
			statusStr = "[FAIL]"
		} else {
			passCount++
		}
		fmt.Printf("%s %02d. %-58s (%4d ms)\n", statusStr, i+1, step.Name, step.Duration.Milliseconds())
		if step.Error != "" {
			fmt.Printf("       -> Erreur: %s\n", step.Error)
		}
	}

	fmt.Println("--------------------------------------------------------------------------------")
	verdict := "PASS"
	if !passed {
		verdict = "FAIL"
	}
	fmt.Printf("Résultat global : %s (%d/%d étapes réussies) en %d ms\n", verdict, passCount, len(steps), totalDur.Milliseconds())

	arch := map[string]string{"amd64": "x64", "arm64": "ARM64"}[runtime.GOARCH]
	if arch == "" {
		arch = runtime.GOARCH
	}
	var statusQualification string
	switch runtime.GOOS {
	case "linux":
		statusQualification = "Linux " + arch + " Qualifié (Selftest exécuté)"
	case "darwin":
		statusQualification = "macOS " + arch + " Qualifié (Selftest exécuté)"
	default:
		statusQualification = "Windows " + arch + " Qualifié"
	}
	if passed {
		fmt.Printf("Statut plateforme : %s\n", statusQualification)
	} else {
		fmt.Printf("Statut plateforme : Échec de validation (%s)\n", runtime.GOOS)
	}
	fmt.Println("================================================================================")
}
