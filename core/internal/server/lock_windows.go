//go:build windows

package server

import (
	"syscall"
)

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
