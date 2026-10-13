//go:build !windows

package osutil

import (
	"context"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"time"
)

func runBoundedOS(ctx context.Context, spec CommandSpec) (*ProcessResult, error) {
	timeout := spec.Limits.Timeout
	if timeout <= 0 {
		timeout = 300 * time.Second
	}
	ctxTimeout, cancelTimeout := context.WithTimeout(ctx, timeout)
	defer cancelTimeout()

	cmd := exec.Command(spec.Executable, spec.Args...)
	cmd.Dir = spec.WorkingDirectory
	if len(spec.Env) > 0 {
		cmd.Env = spec.Env
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}

	maxOutput := spec.Limits.MaxOutputBytes
	if maxOutput <= 0 {
		maxOutput = 1024 * 1024
	}
	stdoutCap := NewBoundedCapture(maxOutput)
	stderrCap := NewBoundedCapture(maxOutput)

	startTime := time.Now()
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	pgid := cmd.Process.Pid

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = stdoutCap.ReadFrom(stdoutPipe)
	}()
	go func() {
		defer wg.Done()
		_, _ = stderrCap.ReadFrom(stderrPipe)
	}()

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()

	result := &ProcessResult{}
	var timedOut, cancelled bool

	select {
	case <-ctxTimeout.Done():
		if ctx.Err() == context.Canceled {
			cancelled = true
		} else {
			timedOut = true
		}
		// Kill the entire process group
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		<-waitCh
	case waitErr := <-waitCh:
		if waitErr != nil {
			if exitErr, ok := waitErr.(*exec.ExitError); ok {
				result.ExitCode = exitErr.ExitCode()
			} else {
				result.ExitCode = 1
			}
		} else {
			result.ExitCode = 0
		}
	}

	wg.Wait()
	result.Duration = time.Since(startTime)
	result.Stdout = stdoutCap.String()
	result.Stderr = stderrCap.String()
	result.OutputTruncated = stdoutCap.Truncated() || stderrCap.Truncated()
	result.TotalBytesRead = stdoutCap.TotalRead() + stderrCap.TotalRead()
	result.TimedOut = timedOut
	result.Cancelled = cancelled

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	result.PeakMemoryBytes = m.Alloc

	return result, nil
}

// SetHideWindow is a no-op on POSIX operating systems.
func SetHideWindow(cmd *exec.Cmd) {
}
