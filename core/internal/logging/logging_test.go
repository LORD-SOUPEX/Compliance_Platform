package logging

import (
	"bufio"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRotatingFileKeepsBoundedHistory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	file, err := OpenRotating(path, 64, 2)
	if err != nil {
		t.Fatal(err)
	}
	line := []byte(strings.Repeat("x", 40) + "\n")
	for i := 0; i < 10; i++ {
		if _, err := file.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{FileName, FileName + ".1", FileName + ".2"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("%s absent: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, FileName+".3")); !os.IsNotExist(err) {
		t.Fatalf("rotation keeps more than 2 files: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %v", info.Mode().Perm())
		}
	}
}

func TestSetupWritesJSONAndFeedsSubscribers(t *testing.T) {
	previous := slog.Default()
	defer slog.SetDefault(previous)
	dir := t.TempDir()
	closeLog, err := Setup(Options{Dir: dir, Level: slog.LevelInfo})
	if err != nil {
		t.Fatal(err)
	}
	feed, cancel := Stream().Subscribe(slog.LevelDebug, 8)
	slog.With("run_id", "abc").Debug("probe", "err", errors.New("boom"))
	slog.Info("ready", "port", 4242)
	cancel()
	closeLog()

	first := <-feed
	if first.Message != "probe" || first.Level != "debug" || first.Attrs["run_id"] != "abc" || first.Attrs["err"] != "boom" {
		t.Fatalf("stream entry = %+v", first)
	}
	body, err := os.Open(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	scanner := bufio.NewScanner(body)
	var lines []map[string]interface{}
	for scanner.Scan() {
		var record map[string]interface{}
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatalf("not JSON: %s", scanner.Text())
		}
		lines = append(lines, record)
	}
	if len(lines) != 1 || lines[0]["msg"] != "ready" || lines[0]["level"] != "info" {
		t.Fatalf("file below info level or wrong format: %v", lines)
	}
}

func TestRedaction(t *testing.T) {
	args := RedactArgs([]string{"runtime", "sync", "-registry-token", "s3cr3t", "--password=x", "https://user:pw@mirror.local/tools"})
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "s3cr3t") || strings.Contains(joined, "=x") || strings.Contains(joined, "user:pw") {
		t.Fatalf("secret leaked: %s", joined)
	}
	if RedactEnvValue("HTTPS_PROXY", "http://me:pw@proxy:3128") != "http://"+Masked+"@proxy:3128" {
		t.Fatal("proxy credentials kept")
	}
	if RedactEnvValue("COMPLIANCE_REGISTRY_TOKEN", "abc") != Masked || RedactEnvValue("PATH", "/usr/bin") != "/usr/bin" {
		t.Fatal("env redaction")
	}
	added, removed := EnvDiff([]string{"PATH=/bin", "TRIVY_CONFIG=x", "HOME=/h"}, []string{"PATH=/bin", "HOME=/h", "NO_COLOR=1", "GITHUB_TOKEN=t"})
	if added["NO_COLOR"] != "1" || added["GITHUB_TOKEN"] != Masked || len(added) != 2 || len(removed) != 1 || removed[0] != "TRIVY_CONFIG" {
		t.Fatalf("diff = %v %v", added, removed)
	}
}
