package osutil

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
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
	StdoutBytes     int64
	StderrBytes     int64
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
	// StdoutSink and StderrSink receive the complete streams, beyond MaxOutputBytes.
	// They are optional; a CappedFile keeps the disk copy bounded.
	StdoutSink io.Writer
	StderrSink io.Writer
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
	sink      io.Writer
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

// NewBoundedCaptureWithSink also copies every byte read to sink, which may be nil.
func NewBoundedCaptureWithSink(maxBytes int64, sink io.Writer) *BoundedCapture {
	capture := NewBoundedCapture(maxBytes)
	capture.sink = sink
	return capture
}

// ReadFrom reads data from r until EOF, keeping up to maxBytes.
func (b *BoundedCapture) ReadFrom(r io.Reader) (int64, error) {
	scratch := make([]byte, 32*1024)
	var total int64

	for {
		n, err := r.Read(scratch)
		if n > 0 {
			total += int64(n)
			if b.sink != nil {
				if _, sinkErr := b.sink.Write(scratch[:n]); sinkErr != nil {
					b.sink = nil
				}
			}
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

// CappedFile is a sink that stops writing past its limit instead of failing the
// capture. Truncated tells whether bytes were dropped from the disk copy.
type CappedFile struct {
	mu        sync.Mutex
	file      *os.File
	limit     int64
	written   int64
	truncated bool
}

// CreateCappedFile creates path with owner-only permissions.
func CreateCappedFile(path string, limit int64) (*CappedFile, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &CappedFile{file: file, limit: limit}, nil
}

func (c *CappedFile) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	room := c.limit - c.written
	chunk := p
	if c.limit > 0 && int64(len(chunk)) > room {
		if room < 0 {
			room = 0
		}
		chunk = chunk[:room]
		c.truncated = true
	}
	if len(chunk) > 0 {
		n, err := c.file.Write(chunk)
		c.written += int64(n)
		if err != nil {
			return n, err
		}
	}
	return len(p), nil
}

// Truncated reports whether the limit dropped bytes.
func (c *CappedFile) Truncated() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.truncated
}

// Close closes the file.
func (c *CappedFile) Close() error {
	return c.file.Close()
}
