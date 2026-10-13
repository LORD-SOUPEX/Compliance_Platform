//go:build !windows

package server

import (
	"os"
	"syscall"
)

// isProcessAlive checks if a process with the given PID is currently running on POSIX systems.
func isProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = process.Signal(syscall.Signal(0))
	return err == nil
}
