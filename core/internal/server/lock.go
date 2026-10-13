package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var (
	ErrDaemonAlreadyRunning = errors.New("une instance du démon compliance est déjà en cours d'exécution")
)

// AcquireLock attempts to acquire the single-instance lock file.
// If an existing lock is held by a dead process (crash recovery), it removes the stale lock.
func AcquireLock(lockPath string) error {
	dir := filepath.Dir(lockPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("création du dossier de verrou: %w", err)
	}

	if data, err := os.ReadFile(lockPath); err == nil {
		pidStr := strings.TrimSpace(string(data))
		if pid, err := strconv.Atoi(pidStr); err == nil {
			if isProcessAlive(pid) {
				return fmt.Errorf("%w (PID %d)", ErrDaemonAlreadyRunning, pid)
			}
			// Stale lock detected (crash recovery): remove and continue
			_ = os.Remove(lockPath)
		}
	}

	// Write current PID to lock file
	myPID := os.Getpid()
	if err := os.WriteFile(lockPath, []byte(strconv.Itoa(myPID)), 0600); err != nil {
		return fmt.Errorf("écriture du verrou daemon: %w", err)
	}

	return nil
}

// ReleaseLock removes the lock file if it belongs to the current process.
func ReleaseLock(lockPath string) {
	if data, err := os.ReadFile(lockPath); err == nil {
		if strings.TrimSpace(string(data)) == strconv.Itoa(os.Getpid()) {
			_ = os.Remove(lockPath)
		}
	}
}

// WriteDaemonState writes daemon.json atomically.
func WriteDaemonState(statePath string, state DaemonState) error {
	dir := filepath.Dir(statePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("création du dossier d'état: %w", err)
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("sérialisation de l'état daemon: %w", err)
	}

	tmpPath := statePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("écriture temporaire de l'état daemon: %w", err)
	}

	if err := os.Rename(tmpPath, statePath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("renommage atomique de l'état daemon: %w", err)
	}

	return nil
}

// ReadDaemonState reads daemon.json.
func ReadDaemonState(statePath string) (*DaemonState, error) {
	data, err := os.ReadFile(statePath)
	if err != nil {
		return nil, err
	}
	var state DaemonState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("désérialisation daemon.json: %w", err)
	}
	return &state, nil
}

