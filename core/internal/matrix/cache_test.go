package matrix

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProbeCacheForgetsStaleResults(t *testing.T) {
	cacheRoot := t.TempDir()
	exe := filepath.Join(t.TempDir(), "tool.exe")
	if err := os.WriteFile(exe, []byte("v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := &DefaultCandidateResolver{CacheRoot: cacheRoot}
	ok := CandidateToolState{Command: "tool", Status: "available"}

	r.remember("k", exe, ok)
	if _, hit := r.cached("k", exe); !hit {
		t.Fatal("fresh success not cached")
	}

	// Another process installed tools: the generation file moved.
	if err := os.WriteFile(filepath.Join(cacheRoot, ".generation"), []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, hit := r.cached("k", exe); hit {
		t.Fatal("result kept across an installation")
	}

	r.remember("k", exe, ok)
	if err := os.WriteFile(exe, []byte("version two"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, hit := r.cached("k", exe); hit {
		t.Fatal("result kept after the executable changed")
	}

	failed := CandidateToolState{Command: "tool", Status: "runtime_error"}
	r.remember("k", exe, failed)
	if _, hit := r.cached("k", exe); !hit {
		t.Fatal("recent failure not cached")
	}
	value, _ := r.cache.Load("k")
	entry := value.(cachedProbe)
	entry.storedAt = time.Now().Add(-2 * negativeProbeTTL)
	r.cache.Store("k", entry)
	if _, hit := r.cached("k", exe); hit {
		t.Fatal("old failure still trusted")
	}

	r.remember("k", exe, ok)
	if r.Invalidate() != 1 {
		t.Fatal("invalidate count")
	}
	if _, hit := r.cached("k", exe); hit {
		t.Fatal("invalidate kept the entry")
	}
}
