package osutil

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ProbeTimeoutFor is the qualification deadline. Checkov imports a large
// tree that antivirus products scan on first use; the other tools stay short.
var ProbeTimeoutFor = func(command string) time.Duration {
	if command == "checkov" {
		return 60 * time.Second
	}
	return 10 * time.Second
}

// CheckovProbeArgs imports the package and prints its version without
// starting the Checkov CLI, which pulls policies and the network.
func CheckovProbeArgs() []string {
	return []string{"-c", "import checkov; print(getattr(checkov, '__version__', ''))"}
}

// PythonModuleArgs builds `python -m <module> <version args>`.
func PythonModuleArgs(module string, versionArgs []string) []string {
	if module == "" {
		module = "unknown"
	}
	if len(versionArgs) == 0 {
		versionArgs = []string{"--version"}
	}
	args := make([]string, 0, 2+len(versionArgs))
	args = append(args, "-m", module)
	args = append(args, versionArgs...)
	return args
}

// RunCaptured starts exe and keeps stdout and stderr separate.
// A Windows .cmd/.bat launcher is handed to cmd.exe.
func RunCaptured(ctx context.Context, exe string, args []string, env []string, hideWindow bool) (string, string, error) {
	commandExe, commandArgs := exe, args
	if strings.EqualFold(filepath.Ext(exe), ".cmd") || strings.EqualFold(filepath.Ext(exe), ".bat") {
		commandExe = "cmd.exe"
		commandArgs = append([]string{"/c", exe}, args...)
	}
	cmd := exec.CommandContext(ctx, commandExe, commandArgs...)
	if len(env) > 0 {
		cmd.Env = env
	}
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	if hideWindow {
		SetHideWindow(cmd)
	}
	err := cmd.Run()
	return stdoutBuf.String(), stderrBuf.String(), err
}

// FormatProbeFailure is the sentence stored on a candidate when qualification fails.
func FormatProbeFailure(exe string, err error, stdout, stderr string, elapsed time.Duration) string {
	out := strings.TrimSpace(stdout)
	errText := strings.TrimSpace(stderr)
	if out == "" {
		out = "aucune sortie"
	}
	if errText == "" {
		errText = "aucune sortie"
	}
	if err == nil {
		err = errors.New("échec de sonde")
	}
	if elapsed < 0 {
		elapsed = 0
	}
	return fmt.Sprintf("Qualification d'execution impossible: %v (stdout: %s ; stderr: %s ; duree: %s ; binaire: %s)", err, out, errText, elapsed.Truncate(time.Millisecond), exe)
}

// ProbeQuiet runs the qualification command with the tool environment.
// Trivy is retried once without a hidden console when it exits 1 and writes nothing.
func ProbeQuiet(ctx context.Context, command, exe string, args []string) (string, string, error) {
	stdout, stderr, err := RunCaptured(ctx, exe, args, ToolEnviron(command), true)
	if command == "trivy" && silentExitOne(err, stdout, stderr) && ctx.Err() == nil {
		stdout, stderr, err = RunCaptured(ctx, exe, args, ToolEnviron(command), false)
	}
	return stdout, stderr, err
}

func silentExitOne(err error, stdout, stderr string) bool {
	if strings.TrimSpace(stdout) != "" || strings.TrimSpace(stderr) != "" || err == nil {
		return false
	}
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr) && exitErr.ExitCode() == 1
}

// QualifyCheckov imports checkov with the isolated interpreter environment.
func QualifyCheckov(ctx context.Context, pythonExe string) error {
	start := time.Now()
	stdout, stderr, err := ProbeQuiet(ctx, "checkov", pythonExe, CheckovProbeArgs())
	if err != nil {
		return errors.New(FormatProbeFailure(pythonExe, err, stdout, stderr, time.Since(start)))
	}
	if strings.TrimSpace(stdout) == "" && strings.TrimSpace(stderr) == "" {
		return errors.New(FormatProbeFailure(pythonExe, errors.New("version vide"), stdout, stderr, time.Since(start)))
	}
	return nil
}

// QualifyTrivy runs trivy --version in the local silent environment.
func QualifyTrivy(ctx context.Context, exe string) error {
	start := time.Now()
	stdout, stderr, err := ProbeQuiet(ctx, "trivy", exe, []string{"--version"})
	if err != nil {
		return errors.New(FormatProbeFailure(exe, err, stdout, stderr, time.Since(start)))
	}
	return nil
}
