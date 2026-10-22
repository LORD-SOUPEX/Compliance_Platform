//go:build windows

package osutil

import (
	"os"
	"syscall"
	"unsafe"
)

var (
	procLockFileEx   = kernel32.NewProc("LockFileEx")
	procUnlockFileEx = kernel32.NewProc("UnlockFileEx")
)

const (
	lockfileFailImmediately = 0x00000001
	lockfileExclusiveLock   = 0x00000002
	errorLockViolation      = syscall.Errno(33)
	errorIOPending          = syscall.Errno(997)
	// One byte far beyond any content: the lock never blocks reads of the file itself.
	lockOffsetHigh = 0x7FFFFFFF
)

func tryLock(file *os.File, exclusive bool) (bool, error) {
	flags := uintptr(lockfileFailImmediately)
	if exclusive {
		flags |= lockfileExclusiveLock
	}
	var overlapped syscall.Overlapped
	overlapped.OffsetHigh = lockOffsetHigh
	r1, _, err := procLockFileEx.Call(file.Fd(), flags, 0, 1, 0, uintptr(unsafe.Pointer(&overlapped)))
	if r1 != 0 {
		return true, nil
	}
	if err == errorLockViolation || err == errorIOPending {
		return false, nil
	}
	return false, err
}

func unlockFile(file *os.File) {
	var overlapped syscall.Overlapped
	overlapped.OffsetHigh = lockOffsetHigh
	_, _, _ = procUnlockFileEx.Call(file.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&overlapped)))
}
