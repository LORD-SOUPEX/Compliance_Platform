package distribution

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMaterializePrefixesLongWindowsPath(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("extended paths are a Windows limit")
	}
	base := filepath.Join(t.TempDir(), strings.Repeat("a", 180), strings.Repeat("b", 80))
	got := materialize(base)
	if !strings.HasPrefix(got, `\\?\`) {
		t.Fatalf("path = %s", got)
	}
	short := filepath.Join(t.TempDir(), "ok")
	if materialize(short) != short && len(short) < 248 {
		t.Fatalf("short path changed: %s", materialize(short))
	}
}
