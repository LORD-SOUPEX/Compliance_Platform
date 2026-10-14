package osutil

import (
	"bytes"
	"context"
	"io"
	"sync"
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
	CommandLine      string
	WorkingDirectory string
	Env              []string
	Limits           ProcessLimits
}

// RunBounded executes a process under OS-specific job/group containment,
// ensuring strict timeout, orphan destruction, and bounded memory streaming.
func RunBounded(ctx context.Context, spec CommandSpec) (*ProcessResult, error) {
	return runBoundedOS(ctx, spec)
}

// BoundedCapture reads from an io.Reader and retains up to maxBytes in memory,
// while continuing to drain the reader to prevent process pipe deadlock.
type BoundedCapture struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	maxBytes  int64
	truncated bool
	totalRead int64
}

// NewBoundedCapture creates a new BoundedCapture with a retention limit.
func NewBoundedCapture(maxBytes int64) *BoundedCapture {
	if maxBytes <= 0 {
		maxBytes = 1024 * 1024 // 1 MB default
	}
	return &BoundedCapture{
		maxBytes: maxBytes,
	}
}

// ReadFrom reads data from r until EOF, keeping up to maxBytes.
func (b *BoundedCapture) ReadFrom(r io.Reader) (int64, error) {
	scratch := make([]byte, 32*1024)
	var total int64

	for {
		n, err := r.Read(scratch)
		if n > 0 {
			total += int64(n)
			b.mu.Lock()
			b.totalRead += int64(n)
			currentLen := int64(b.buf.Len())
			if currentLen < b.maxBytes {
				allowed := b.maxBytes - currentLen
				if int64(n) <= allowed {
					b.buf.Write(scratch[:n])
				} else {
					b.buf.Write(scratch[:allowed])
					b.truncated = true
				}
			} else {
				b.truncated = true
			}
			b.mu.Unlock()
		}
		if err != nil {
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
	}
}

// String returns the captured content as string.
func (b *BoundedCapture) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Truncated returns whether output exceeded maxBytes.
func (b *BoundedCapture) Truncated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.truncated
}

// TotalRead returns the total bytes emitted by the stream.
func (b *BoundedCapture) TotalRead() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.totalRead
}
