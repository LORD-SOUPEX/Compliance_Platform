//go:build windows

package server

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// AcquireLock writes a PID lock and treats a live holder as an existing daemon.
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
			_ = os.Remove(lockPath)
		}
	}

	myPID := os.Getpid()
	if err := os.WriteFile(lockPath, []byte(strconv.Itoa(myPID)), 0600); err != nil {
		return fmt.Errorf("écriture du verrou daemon: %w", err)
	}
	if err := os.Chmod(lockPath, 0600); err != nil {
		return fmt.Errorf("restriction du verrou daemon: %w", err)
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

// isProcessAlive checks if a process with the given PID is currently running on Windows.
func isProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	const processQueryLimitedInfo = 0x1000
	handle, err := syscall.OpenProcess(processQueryLimitedInfo, false, uint32(pid))
	if err != nil {
		return false
	}
	var exitCode uint32
	err = syscall.GetExitCodeProcess(handle, &exitCode)
	_ = syscall.CloseHandle(handle)
	if err != nil {
		return false
	}
	const STILL_ACTIVE = 259
	return exitCode == STILL_ACTIVE
}
