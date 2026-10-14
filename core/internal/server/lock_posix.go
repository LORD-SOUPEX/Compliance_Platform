//go:build !windows

package server

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
)

var (
	posixLockMu sync.Mutex
	posixLocks  = map[string]*os.File{}
)

// AcquireLock takes an exclusive non-blocking flock on daemon.lock and keeps
// the descriptor open for the lifetime of the daemon. The kernel drops the
// lock if the process exits, including on SIGKILL.
func AcquireLock(lockPath string) error {
	posixLockMu.Lock()
	defer posixLockMu.Unlock()

	if existing, ok := posixLocks[lockPath]; ok && existing != nil {
		return fmt.Errorf("%w (PID %d)", ErrDaemonAlreadyRunning, os.Getpid())
	}

	dir := filepath.Dir(lockPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("création du dossier de verrou: %w", err)
	}

	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("ouverture du verrou daemon: %w", err)
	}
	if err := os.Chmod(lockPath, 0600); err != nil {
		_ = file.Close()
		return fmt.Errorf("restriction du verrou daemon: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if err == syscall.EWOULDBLOCK || err == syscall.EAGAIN {
			return fmt.Errorf("%w", ErrDaemonAlreadyRunning)
		}
		return fmt.Errorf("verrou exclusif daemon: %w", err)
	}

	_ = file.Truncate(0)
	_, _ = file.Seek(0, 0)
	if _, err := file.WriteString(strconv.Itoa(os.Getpid())); err != nil {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
		return fmt.Errorf("écriture du verrou daemon: %w", err)
	}

	posixLocks[lockPath] = file
	return nil
}

// ReleaseLock unlocks and closes the flock held by this process.
func ReleaseLock(lockPath string) {
	posixLockMu.Lock()
	defer posixLockMu.Unlock()
	file, ok := posixLocks[lockPath]
	if !ok || file == nil {
		return
	}
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
	delete(posixLocks, lockPath)
	_ = os.Remove(lockPath)
}

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
