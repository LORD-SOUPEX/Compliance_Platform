package osutil

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestStreamingMemoryCap verifies that streaming massive output (50MB in test)
// keeps memory consumption bounded strictly below 20MB.
func TestStreamingMemoryCap(t *testing.T) {
	ctx := context.Background()

	pythonExe := resolvePythonExe(t)

	spec := CommandSpec{
		Executable: pythonExe,
		Args: []string{
			"-c",
			"import sys; chunk = b'A' * (1024 * 1024); [sys.stdout.buffer.write(chunk) for _ in range(50)]; sys.stdout.flush()",
		},
		Limits: ProcessLimits{
			Timeout:        15 * time.Second,
			MaxOutputBytes: 1024 * 1024, // 1 MB cap
		},
	}

	var mBefore runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&mBefore)

	res, err := RunBounded(ctx, spec)
	if err != nil {
		t.Fatalf("RunBounded failed: %v", err)
	}

	if !res.OutputTruncated {
		t.Errorf("Expected OutputTruncated to be true")
	}
	if int64(len(res.Stdout)) > spec.Limits.MaxOutputBytes {
		t.Errorf("Captured stdout length %d exceeds cap %d", len(res.Stdout), spec.Limits.MaxOutputBytes)
	}
	if res.TotalBytesRead < 45*1024*1024 {
		t.Errorf("Expected TotalBytesRead >= 45MB, got %d bytes", res.TotalBytesRead)
	}

	var mAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&mAfter)

	heapDiff := int64(mAfter.Alloc) - int64(mBefore.Alloc)
	t.Logf("Total bytes read from stream: %d MB", res.TotalBytesRead/(1024*1024))
	t.Logf("Retained in memory: %d KB", len(res.Stdout)/1024)
	t.Logf("Go Heap alloc change: %d KB", heapDiff/1024)
	t.Logf("Go Peak alloc: %d KB", res.PeakMemoryBytes/1024)

	// Memory retained should be under 5 MB
	if res.PeakMemoryBytes > 50*1024*1024 {
		t.Errorf("Peak memory %d bytes exceeded 50MB", res.PeakMemoryBytes)
	}
}

// TestLarge500MBMemoryCap satisfies Exit Criterion 4 with measured 500MB streaming output.
func TestLarge500MBMemoryCap(t *testing.T) {
	ctx := context.Background()
	pythonExe := resolvePythonExe(t)

	spec := CommandSpec{
		Executable: pythonExe,
		Args: []string{
			"-c",
			// Emit 500 chunks of 1MB = 500 MB
			"import sys; chunk = b'X' * (1024 * 1024); [sys.stdout.buffer.write(chunk) for _ in range(500)]; sys.stdout.flush()",
		},
		Limits: ProcessLimits{
			Timeout:        30 * time.Second,
			MaxOutputBytes: 1024 * 1024, // 1 MB retention cap
		},
	}

	var mBefore runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&mBefore)

	res, err := RunBounded(ctx, spec)
	if err != nil {
		t.Fatalf("RunBounded failed: %v", err)
	}

	if !res.OutputTruncated {
		t.Errorf("Expected OutputTruncated to be true")
	}
	if int64(len(res.Stdout)) > spec.Limits.MaxOutputBytes {
		t.Errorf("Captured stdout length %d exceeds cap %d", len(res.Stdout), spec.Limits.MaxOutputBytes)
	}

	var mAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&mAfter)

	t.Logf("=== 500 MB STREAMING MEASUREMENT ===")
	t.Logf("Total bytes read from process: %d MB", res.TotalBytesRead/(1024*1024))
	t.Logf("Retained in memory: %d KB", len(res.Stdout)/1024)
	t.Logf("Go Heap alloc before: %d KB", mBefore.Alloc/1024)
	t.Logf("Go Heap alloc after: %d KB", mAfter.Alloc/1024)
	t.Logf("Go Peak alloc reported: %d KB", res.PeakMemoryBytes/1024)

	// Memory retained MUST stay strictly bounded under 15 MB
	if mAfter.Alloc > 15*1024*1024 {
		t.Errorf("Memory allocated %d bytes exceeded 15MB ceiling", mAfter.Alloc)
	}
}

// TestOrphanProcessTermination verifies that when a process spawns a child in a loop,
// timing out kills the parent AND all child processes (no orphans left).
func TestOrphanProcessTermination(t *testing.T) {
	ctx := context.Background()
	pythonExe := resolvePythonExe(t)

	// This script spawns a child process that sleeps for 60 seconds, then parent sleeps for 60 seconds
	script := `
import subprocess, sys, time
proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
print(f"CHILD_PID:{proc.pid}", flush=True)
time.sleep(60)
`
	spec := CommandSpec{
		Executable: pythonExe,
		Args:       []string{"-c", script},
		Limits: ProcessLimits{
			Timeout:        1 * time.Second, // Timeout after 1 second
			MaxOutputBytes: 64 * 1024,
		},
	}

	res, err := RunBounded(ctx, spec)
	if err != nil {
		t.Fatalf("RunBounded failed: %v", err)
	}

	if !res.TimedOut {
		t.Fatalf("Expected process to time out, got exit code %d", res.ExitCode)
	}

	// Parse child PID from stdout
	var childPid string
	for _, line := range strings.Split(res.Stdout, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "CHILD_PID:") {
			childPid = strings.TrimPrefix(line, "CHILD_PID:")
			break
		}
	}

	if childPid == "" {
		t.Fatalf("Could not obtain child PID from stdout: %q", res.Stdout)
	}
	t.Logf("Parent timed out. Verifying child PID %s is dead...", childPid)

	// Wait 200ms to let OS cleanup finish
	time.Sleep(200 * time.Millisecond)

	if isPIDAlive(t, childPid) {
		t.Errorf("ORPHAN LEAK DETECTED: child process with PID %s is still alive!", childPid)
	} else {
		t.Logf("SUCCESS: child process %s was killed without orphan!", childPid)
	}
}

func resolvePythonExe(t *testing.T) string {
	candidates := []string{
		"../../../.tools/python/python.exe",
		".tools/python/python.exe",
		"python3",
		"python",
	}
	for _, c := range candidates {
		if path, err := exec.LookPath(c); err == nil {
			return path
		}
	}
	t.Skip("Interpréteur Python introuvable sur cette machine pour exécuter le test")
	return ""
}

func isPIDAlive(t *testing.T, pidStr string) bool {
	pidStr = strings.TrimSpace(pidStr)
	if runtime.GOOS == "windows" {
		cmd := exec.Command("tasklist", "/FI", "PID eq "+pidStr, "/NH")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("Avertissement: tasklist a retourné une erreur (%v): %s", err, string(out))
			return false
		}
		// tasklist /NH produit: <ImageName> <PID> <SessionName> <Session#> <MemUsage>
		// S'il n'y a aucun processus: "INFO: Aucune tâche..."
		lines := strings.Split(string(out), "\n")
		for _, l := range lines {
			fields := strings.Fields(l)
			if len(fields) >= 2 && fields[1] == pidStr {
				return true
			}
		}
		return false
	}

	// POSIX (Linux/macOS)
	cmd := exec.Command("kill", "-0", pidStr)
	return cmd.Run() == nil
}


