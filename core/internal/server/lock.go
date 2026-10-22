package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var (
	ErrDaemonAlreadyRunning = errors.New("une instance du démon compliance est déjà en cours d'exécution")
)

// ExitAlreadyRunning is the daemon exit code when another instance holds the lock.
// A client that sees it waits for the running daemon instead of reporting a failure.
const ExitAlreadyRunning = 3

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
	if err := os.Chmod(tmpPath, 0600); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("restriction de l'état daemon: %w", err)
	}

	if err := os.Rename(tmpPath, statePath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("renommage atomique de l'état daemon: %w", err)
	}
	if err := os.Chmod(statePath, 0600); err != nil {
		return fmt.Errorf("restriction de daemon.json: %w", err)
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
