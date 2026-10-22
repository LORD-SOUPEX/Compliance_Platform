package server

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// TestLockHelperProcess holds the lock in a child process until killed.
func TestLockHelperProcess(t *testing.T) {
	path := os.Getenv("COMPLIANCE_LOCK_HELPER")
	if path == "" {
		return
	}
	if err := AcquireLock(path); err != nil {
		os.Exit(2)
	}
	_ = os.WriteFile(path+".ready", []byte("1"), 0600)
	time.Sleep(time.Minute)
}

// The lock follows the process, not the file: a killed holder leaves its file
// and its PID behind, and a new daemon still starts. Same contract on every OS.
func TestLockIsReleasedWhenHolderIsKilled(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "daemon.lock")
	child := exec.Command(os.Args[0], "-test.run=^TestLockHelperProcess$")
	child.Env = append(os.Environ(), "COMPLIANCE_LOCK_HELPER="+lockPath)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(lockPath + ".ready"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = child.Process.Kill()
			t.Fatal("helper never took the lock")
		}
		time.Sleep(50 * time.Millisecond)
	}

	err := AcquireLock(lockPath)
	if !errors.Is(err, ErrDaemonAlreadyRunning) {
		ReleaseLock(lockPath)
		_ = child.Process.Kill()
		t.Fatalf("second holder err = %v, want ErrDaemonAlreadyRunning", err)
	}
	if body, readErr := os.ReadFile(lockPath); readErr != nil || string(body) != strconv.Itoa(child.Process.Pid) {
		t.Fatalf("lock file must stay readable with the holder PID: %q %v", body, readErr)
	}

	_ = child.Process.Kill()
	_, _ = child.Process.Wait()
	if err := AcquireLock(lockPath); err != nil {
		t.Fatalf("lock not released after kill: %v", err)
	}
	ReleaseLock(lockPath)
}
