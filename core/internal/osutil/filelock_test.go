package osutil

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestFileLockSharedAndExclusive(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".install.lock")
	ctx := context.Background()
	readerA, err := LockFile(ctx, path, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	readerB, err := LockFile(ctx, path, false, nil)
	if err != nil {
		t.Fatalf("two readers must share the lock: %v", err)
	}

	short, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	waited := false
	if _, err := LockFile(short, path, true, func() { waited = true }); !errors.Is(err, ErrLockTimeout) || !waited {
		t.Fatalf("writer acquired the lock during reads: err=%v waited=%v", err, waited)
	}

	readerA()
	readerB()
	writer, err := LockFile(ctx, path, true, nil)
	if err != nil {
		t.Fatalf("writer blocked after readers left: %v", err)
	}
	blocked, cancelReader := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancelReader()
	if _, err := LockFile(blocked, path, false, nil); !errors.Is(err, ErrLockTimeout) {
		t.Fatalf("reader entered during a write: %v", err)
	}
	writer()
}
