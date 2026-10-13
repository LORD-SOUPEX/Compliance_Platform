package osutil

import (
	"context"
	"time"
)

// ProcessLimits defines execution constraints for a command.
type ProcessLimits struct {
	Timeout        time.Duration
	MaxOutputBytes int64 // Maximum bytes to retain in memory for stdout/stderr
}

// ProcessResult captures the outcome of a bounded process execution.
type ProcessResult struct {
	Stdout          string
	Stderr          string
	ExitCode        int
	Duration        time.Duration
	OutputTruncated bool
	TimedOut        bool
	Cancelled       bool
	TotalBytesRead  int64
	PeakMemoryBytes uint64 // Tracked or estimated process runner memory overhead
}

// CommandSpec specifies the process invocation parameters.
type CommandSpec struct {
	Executable       string
	Args             []string
	WorkingDirectory string
	Env              []string
	Limits           ProcessLimits
}

// RunBounded executes a process under OS-specific job/group containment,
// ensuring strict timeout, orphan destruction, and bounded memory streaming.
func RunBounded(ctx context.Context, spec CommandSpec) (*ProcessResult, error) {
	return runBoundedOS(ctx, spec)
}
