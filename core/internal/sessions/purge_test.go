package sessions

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPurgeKeepsFiveAndProtectsCurrent(t *testing.T) {
	root := t.TempDir()
	var names []string
	for i := 0; i < 7; i++ {
		name := sessionID(i)
		names = append(names, name)
		writeSession(t, filepath.Join(root, name), time.Now().Add(time.Duration(i)*time.Second))
	}
	foreign := filepath.Join(root, "notes-utilisateur")
	if err := os.Mkdir(foreign, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(foreign, "secret.txt"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "keep.txt"), []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Purge(root, Options{Keep: 5, Protect: []string{names[0]}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Removed) != 2 {
		t.Fatalf("removed = %v, want 2 oldest unprotected (ceiling clamped to 5, oldest protected)", result.Removed)
	}
	if _, err := os.Stat(filepath.Join(root, names[0])); err != nil {
		t.Fatal("protected oldest session was deleted")
	}
	if _, err := os.Stat(filepath.Join(foreign, "secret.txt")); err != nil {
		t.Fatal("foreign directory was deleted")
	}
	if _, err := os.Stat(filepath.Join(outside, "keep.txt")); err != nil {
		t.Fatal("path outside the session root was deleted")
	}
	remaining := 0
	entries, _ := os.ReadDir(root)
	for _, entry := range entries {
		if sessionName.MatchString(entry.Name()) {
			remaining++
		}
	}
	if remaining != 5 {
		t.Fatalf("recognized sessions left = %d, want 5", remaining)
	}
}

func TestPurgeIgnoresSymlinkAndRefusesSymlinkedRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "payload.txt"), []byte("safe"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink not permitted on this host: %v", err)
	}
	writeSession(t, filepath.Join(root, sessionID(1)), time.Now())
	result, err := Purge(root, Options{Keep: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(outside, "payload.txt")); err != nil {
		t.Fatal("symlink target was deleted")
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatal("symlink itself was removed")
	}
	joined := ""
	for _, note := range result.Notes {
		joined += note
	}
	if !contains(joined, "lien symbolique") {
		t.Fatalf("notes = %v", result.Notes)
	}
	if _, err := Purge(link, Options{}); err == nil {
		t.Fatal("symlink root was accepted")
	}
}

func TestKeepBoundsAndDangerousRoots(t *testing.T) {
	if err := ValidateKeep(1); err != nil {
		t.Fatal(err)
	}
	if err := ValidateKeep(1000); err != nil {
		t.Fatal(err)
	}
	if ValidateKeep(0) == nil || ValidateKeep(1001) == nil {
		t.Fatal("out of range keep was accepted")
	}
	if _, err := ResolveSessionRoot(string(filepath.Separator), nil); err == nil {
		t.Fatal("disk root accepted")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveSessionRoot(home, nil); err == nil {
		t.Fatal("home directory accepted")
	}
	extension := t.TempDir()
	if _, err := ResolveSessionRoot(extension, []string{extension}); err == nil {
		t.Fatal("extension directory accepted")
	}
	chosen := t.TempDir()
	resolved, err := ResolveSessionRoot(chosen, nil)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(resolved) != "compliance-sessions" {
		t.Fatalf("resolved = %s", resolved)
	}
}

func TestRemoveRejectsPathOutsideRoot(t *testing.T) {
	root := t.TempDir()
	if err := removeSession(root, ".."); err == nil {
		t.Fatal("parent path was accepted")
	}
	if err := removeSession(root, filepath.Join("..", "outside")); err == nil {
		t.Fatal("escaped path was accepted")
	}
}

func writeSession(t *testing.T, dir string, when time.Time) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "session.json")
	if err := os.WriteFile(marker, []byte(`{"schema_version":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(marker, when, when); err != nil {
		t.Fatal(err)
	}
}

func sessionID(n int) string {
	const alphabet = "0123456789abcdef"
	id := make([]byte, 32)
	for i := range id {
		id[i] = alphabet[(n+i)%len(alphabet)]
	}
	id[31] = alphabet[n%len(alphabet)]
	return string(id)
}

func contains(value, part string) bool {
	return len(part) == 0 || (len(value) >= len(part) && (value == part || len(value) > 0 && (stringIndex(value, part) >= 0)))
}

func stringIndex(value, part string) int {
	for i := 0; i+len(part) <= len(value); i++ {
		if value[i:i+len(part)] == part {
			return i
		}
	}
	return -1
}
