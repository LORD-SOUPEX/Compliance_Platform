package osutil

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ErrLockTimeout is returned when the lock is still held by someone else at the deadline.
var ErrLockTimeout = errors.New("verrou toujours détenu à l'échéance")

// LockFile takes a cross-process lock on path: shared (readers, e.g. a run
// using the tools) or exclusive (a writer, e.g. a tool installation). It waits
// until ctx ends, polling every 200 ms, and calls onWait once if it has to wait.
// The OS releases the lock if the process dies (flock on Linux and macOS,
// LockFileEx on Windows), so a crash never leaves the tools folder locked.
func LockFile(ctx context.Context, path string, exclusive bool, onWait func()) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("ouverture du verrou %s: %w", path, err)
	}
	waited := false
	for {
		locked, lockErr := tryLock(file, exclusive)
		if lockErr != nil {
			_ = file.Close()
			return nil, fmt.Errorf("verrou %s: %w", path, lockErr)
		}
		if locked {
			return func() {
				unlockFile(file)
				_ = file.Close()
			}, nil
		}
		if !waited && onWait != nil {
			onWait()
		}
		waited = true
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, fmt.Errorf("%w (%s): %v", ErrLockTimeout, path, ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
}
