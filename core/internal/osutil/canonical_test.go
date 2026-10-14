package osutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCanonicalPathResolvesParentSymlinkWhenLeafIsMissing(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink non disponible: %v", err)
	}

	missing := filepath.Join(link, "not-yet")
	got, err := CanonicalPath(missing)
	if err != nil {
		t.Fatal(err)
	}

	resolvedReal, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(resolvedReal, "not-yet")
	if filepath.Clean(got) != filepath.Clean(want) {
		t.Fatalf("CanonicalPath() = %q, want %q", got, want)
	}
}

func TestCanonicalPathExistingDirectory(t *testing.T) {
	dir := t.TempDir()
	got, err := CanonicalPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(got) != filepath.Clean(want) {
		t.Fatalf("CanonicalPath() = %q, want %q", got, want)
	}
}
