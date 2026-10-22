package osutil

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestHelperProcess is re-executed by the sink test as a portable child process.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("COMPLIANCE_HELPER_PROCESS") != "1" {
		return
	}
	fmt.Fprint(os.Stdout, strings.Repeat("o", 4096))
	fmt.Fprint(os.Stderr, "tail-of-stderr")
	os.Exit(7)
}

func TestSinksKeepWhatTheReportTruncates(t *testing.T) {
	dir := t.TempDir()
	stdout, err := CreateCappedFile(filepath.Join(dir, "out.log"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := CreateCappedFile(filepath.Join(dir, "err.log"), 4)
	if err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "COMPLIANCE_HELPER_PROCESS=1")
	res, err := RunBounded(context.Background(), CommandSpec{
		Executable: os.Args[0],
		Args:       []string{"-test.run=^TestHelperProcess$"},
		Env:        env,
		Limits:     ProcessLimits{Timeout: 30 * time.Second, MaxOutputBytes: 100},
		StdoutSink: stdout,
		StderrSink: stderr,
	})
	_ = stdout.Close()
	_ = stderr.Close()
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 7 || !res.OutputTruncated || len(res.Stdout) != 100 {
		t.Fatalf("exit=%d truncated=%v len=%d", res.ExitCode, res.OutputTruncated, len(res.Stdout))
	}
	if res.StdoutBytes != 4096 || res.StderrBytes != int64(len("tail-of-stderr")) {
		t.Fatalf("bytes = %d %d", res.StdoutBytes, res.StderrBytes)
	}
	full, _ := os.ReadFile(filepath.Join(dir, "out.log"))
	if len(full) != 4096 {
		t.Fatalf("disk copy = %d bytes, want 4096", len(full))
	}
	capped, _ := os.ReadFile(filepath.Join(dir, "err.log"))
	if string(capped) != "tail" || !stderr.Truncated() || stdout.Truncated() {
		t.Fatalf("capped = %q truncated=%v/%v", capped, stderr.Truncated(), stdout.Truncated())
	}
}
