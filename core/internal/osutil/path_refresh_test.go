package osutil

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRefreshPathAppendsNewExistingFoldersOnce(t *testing.T) {
	known := t.TempDir()
	fresh := t.TempDir()
	t.Setenv("PATH", known)
	client := strings.Join([]string{known, fresh, filepath.Join(fresh, "absent"), ""}, string(os.PathListSeparator))

	added := RefreshPath(client)
	found := false
	for _, entry := range added {
		if entry == fresh {
			found = true
		}
		if entry == known || strings.HasSuffix(entry, "absent") {
			t.Fatalf("unexpected addition %q", entry)
		}
	}
	if !found {
		t.Fatalf("client folder not added: %v", added)
	}
	parts := filepath.SplitList(os.Getenv("PATH"))
	if parts[0] != known {
		t.Fatalf("existing entries lost their priority: %v", parts)
	}
	if again := RefreshPath(client); len(again) != 0 {
		t.Fatalf("second refresh added %v", again)
	}
	if runtime.GOOS == "windows" {
		if upper := RefreshPath(strings.ToUpper(fresh)); len(upper) != 0 {
			t.Fatalf("Windows PATH comparison must ignore case: %v", upper)
		}
	}
}

func TestSystemPathEntriesReadsTheRegistryOnWindows(t *testing.T) {
	entries := systemPathEntries()
	if runtime.GOOS != "windows" {
		if len(entries) != 0 {
			t.Fatalf("no persistent PATH outside Windows: %v", entries)
		}
		return
	}
	for _, entry := range entries {
		if strings.Contains(entry, "%") {
			t.Fatalf("unexpanded entry %q", entry)
		}
		if strings.HasSuffix(strings.ToLower(strings.TrimRight(entry, `\`)), `\system32`) {
			return
		}
	}
	t.Fatalf("System32 absent from the registry PATH: %v", entries)
}
