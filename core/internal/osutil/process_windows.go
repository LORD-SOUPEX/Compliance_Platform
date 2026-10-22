//go:build windows

package osutil

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	procCreateJobObjectW         = kernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject  = kernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObject = kernel32.NewProc("AssignProcessToJobObject")
	procTerminateJobObject       = kernel32.NewProc("TerminateJobObject")
	procCloseHandle              = kernel32.NewProc("CloseHandle")
)

const (
	jobObjectExtendedLimitInformationClass = 9
	jobObjectLimitKillOnJobClose           = 0x2000
)

type ioCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type jobObjectBasicLimitInformation struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type structJobObjectExtendedLimitInformation struct {
	BasicLimitInformation jobObjectBasicLimitInformation
	IoInfo                ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

func createJobObject() (syscall.Handle, error) {
	r1, _, err := procCreateJobObjectW.Call(0, 0)
	if r1 == 0 {
		return 0, err
	}
	hJob := syscall.Handle(r1)

	var info structJobObjectExtendedLimitInformation
	info.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnJobClose

	r2, _, err2 := procSetInformationJobObject.Call(
		uintptr(hJob),
		uintptr(jobObjectExtendedLimitInformationClass),
		uintptr(unsafe.Pointer(&info)),
		uintptr(unsafe.Sizeof(info)),
	)
	if r2 == 0 {
		procCloseHandle.Call(uintptr(hJob))
		return 0, err2
	}
	return hJob, nil
}

func assignProcessToJob(hJob syscall.Handle, pid int) error {
	const processSetQuota = 0x0100
	const processTerminate = 0x0001
	hProc, err := syscall.OpenProcess(processSetQuota|processTerminate, false, uint32(pid))
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(hProc)

	r1, _, err2 := procAssignProcessToJobObject.Call(uintptr(hJob), uintptr(hProc))
	if r1 == 0 {
		return err2
	}
	return nil
}

func terminateJob(hJob syscall.Handle, exitCode uint32) error {
	r1, _, err := procTerminateJobObject.Call(uintptr(hJob), uintptr(exitCode))
	if r1 == 0 {
		return err
	}
	return nil
}

func closeJobHandle(hJob syscall.Handle) {
	if hJob != 0 {
		procCloseHandle.Call(uintptr(hJob))
	}
}

func runBoundedOS(ctx context.Context, spec CommandSpec) (*ProcessResult, error) {
	hJob, err := createJobObject()
	if err != nil {
		return nil, err
	}
	defer closeJobHandle(hJob)

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
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
		HideWindow:    true,
		CmdLine:       spec.CommandLine,
	}

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
	stdoutCap := NewBoundedCaptureWithSink(maxOutput, spec.StdoutSink)
	stderrCap := NewBoundedCaptureWithSink(maxOutput, spec.StderrSink)

	startTime := time.Now()
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	// Assign immediately to the job object so any descendant process is enclosed
	if err := assignProcessToJob(hJob, cmd.Process.Pid); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("assignation du processus au Job Object Windows échouée (pid %d): %w", cmd.Process.Pid, err)
	}

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
		if errorsIs(ctx.Err(), context.Canceled) {
			cancelled = true
		} else {
			timedOut = true
		}
		// Terminate the entire job object immediately
		_ = terminateJob(hJob, 1)
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
	result.StdoutBytes = stdoutCap.TotalRead()
	result.StderrBytes = stderrCap.TotalRead()
	result.TimedOut = timedOut
	result.Cancelled = cancelled

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	result.PeakMemoryBytes = m.Alloc

	return result, nil
}

// SetHideWindow configures the process attributes to prevent console window creation on Windows.
func SetHideWindow(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= 0x08000000 // CREATE_NO_WINDOW
	cmd.SysProcAttr.HideWindow = true
}

func errorsIs(err, target error) bool {
	return err == target
}
