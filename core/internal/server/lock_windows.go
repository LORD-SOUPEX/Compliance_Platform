//go:build windows

package server

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"unsafe"
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = kernel32.NewProc("LockFileEx")
	procUnlockFileEx = kernel32.NewProc("UnlockFileEx")

	windowsLockMu sync.Mutex
	windowsLocks  = map[string]*os.File{}
)

const (
	lockfileFailImmediately = 0x00000001
	lockfileExclusiveLock   = 0x00000002
	errorLockViolation      = syscall.Errno(33)
	errorIOPending          = syscall.Errno(997)
	// The locked byte sits far beyond the PID text, so other processes can still read the file.
	lockOffsetHigh = 0x7FFFFFFF
)

// AcquireLock takes an exclusive LockFileEx lock on daemon.lock and keeps the
// handle open for the daemon's lifetime. Windows drops the lock when the process
// dies, even after TerminateProcess, so a stale file or a reused PID never blocks
// a new daemon (the former PID file did).
func AcquireLock(lockPath string) error {
	windowsLockMu.Lock()
	defer windowsLockMu.Unlock()

	if existing, ok := windowsLocks[lockPath]; ok && existing != nil {
		return fmt.Errorf("%w (PID %d)", ErrDaemonAlreadyRunning, os.Getpid())
	}
	if err := os.MkdirAll(filepath.Dir(lockPath), 0700); err != nil {
		return fmt.Errorf("création du dossier de verrou: %w", err)
	}
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("ouverture du verrou daemon: %w", err)
	}
	var overlapped syscall.Overlapped
	overlapped.OffsetHigh = lockOffsetHigh
	r1, _, callErr := procLockFileEx.Call(file.Fd(), lockfileExclusiveLock|lockfileFailImmediately, 0, 1, 0, uintptr(unsafe.Pointer(&overlapped)))
	if r1 == 0 {
		_ = file.Close()
		if errors.Is(callErr, errorLockViolation) || errors.Is(callErr, errorIOPending) {
			holder := ""
			if data, readErr := os.ReadFile(lockPath); readErr == nil && len(data) > 0 {
				holder = fmt.Sprintf(" (PID %s)", string(data))
			}
			return fmt.Errorf("%w%s", ErrDaemonAlreadyRunning, holder)
		}
		return fmt.Errorf("verrou exclusif daemon: %w", callErr)
	}
	_ = file.Truncate(0)
	_, _ = file.Seek(0, 0)
	if _, err := file.WriteString(strconv.Itoa(os.Getpid())); err != nil {
		unlock(file)
		_ = file.Close()
		return fmt.Errorf("écriture du verrou daemon: %w", err)
	}
	windowsLocks[lockPath] = file
	return nil
}

func unlock(file *os.File) {
	var overlapped syscall.Overlapped
	overlapped.OffsetHigh = lockOffsetHigh
	_, _, _ = procUnlockFileEx.Call(file.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&overlapped)))
}

// ReleaseLock unlocks and removes the lock held by this process.
func ReleaseLock(lockPath string) {
	windowsLockMu.Lock()
	defer windowsLockMu.Unlock()
	file, ok := windowsLocks[lockPath]
	if !ok || file == nil {
		return
	}
	unlock(file)
	_ = file.Close()
	delete(windowsLocks, lockPath)
	_ = os.Remove(lockPath)
}
