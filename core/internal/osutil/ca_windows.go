//go:build windows

package osutil

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// exportSystemRoots writes the machine and user root stores to
// ~/.compliance/cache/ca-bundle.pem. Go on Windows does not enumerate
// SystemCertPool, so the tools receive an explicit PEM instead.
func exportSystemRoots() (dest string, err error) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", err
	}
	dest = filepath.Join(home, ".compliance", "cache", "ca-bundle.pem")
	if info, statErr := os.Stat(dest); statErr == nil && !info.IsDir() && info.Size() > 0 && time.Since(info.ModTime()) < 24*time.Hour {
		return dest, nil
	}
	script := `$ErrorActionPreference = 'Stop'
foreach ($store in @('Cert:\LocalMachine\Root', 'Cert:\CurrentUser\Root')) {
  if (-not (Test-Path -LiteralPath $store)) { continue }
  Get-ChildItem -LiteralPath $store | ForEach-Object {
    $raw = $_.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    '-----BEGIN CERTIFICATE-----'
    [Convert]::ToBase64String($raw, 'InsertLineBreaks')
    '-----END CERTIFICATE-----'
  }
}`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	SetHideWindow(cmd)
	out, err := cmd.Output()
	if err != nil || !strings.Contains(string(out), "BEGIN CERTIFICATE") {
		return "", nil
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return "", err
	}
	temp := dest + ".tmp"
	if err := os.WriteFile(temp, out, 0o644); err != nil {
		return "", err
	}
	if err := os.Rename(temp, dest); err != nil {
		_ = os.Remove(temp)
		return "", err
	}
	return dest, nil
}
