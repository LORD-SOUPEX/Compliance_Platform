package distribution

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// macos-x64 and macos-arm64 are the engine ids for darwin-x64 and darwin-arm64.
func TestManifestURLsAndStructure(t *testing.T) {
	path := filepath.Join("..", "..", "..", ".config", "runtime-manifest.json")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var manifest RuntimeManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		t.Fatal(err)
	}
	platforms := []string{"windows-x64", "linux-x64", "macos-x64", "macos-arm64"}
	var baseline []string
	for i, platform := range platforms {
		entry, ok := manifest.Platforms[platform]
		if !ok {
			t.Fatalf("plateforme absente: %s", platform)
		}
		names := make([]string, 0, len(entry.Tools))
		for name, tool := range entry.Tools {
			names = append(names, name)
			if strings.TrimSpace(tool.ArchiveURL) == "" || !strings.HasPrefix(tool.ArchiveURL, "https://") {
				t.Fatalf("%s/%s URL invalide: %s", platform, name, tool.ArchiveURL)
			}
		}
		sort.Strings(names)
		if i == 0 {
			baseline = names
			continue
		}
		if strings.Join(names, ",") != strings.Join(baseline, ",") {
			t.Fatalf("%s = %v, windows-x64 = %v", platform, names, baseline)
		}
	}
	seen := map[string]struct{}{}
	var urls []string
	for _, platform := range platforms {
		for _, tool := range manifest.Platforms[platform].Tools {
			if _, ok := seen[tool.ArchiveURL]; ok {
				continue
			}
			seen[tool.ArchiveURL] = struct{}{}
			urls = append(urls, tool.ArchiveURL)
		}
	}
	client := &http.Client{Timeout: 30 * time.Second}
	for _, raw := range urls {
		status, err := probeURL(client, raw)
		if err != nil || status != http.StatusOK {
			t.Errorf("%s -> %d (%v)", raw, status, err)
		}
	}
}

func probeURL(client *http.Client, raw string) (int, error) {
	for _, method := range []string{http.MethodHead, http.MethodGet} {
		req, err := http.NewRequest(method, raw, nil)
		if err != nil {
			return 0, err
		}
		if method == http.MethodGet {
			req.Header.Set("Range", "bytes=0-0")
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusPartialContent {
			return http.StatusOK, nil
		}
		if method == http.MethodHead && (resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusForbidden) {
			continue
		}
		if method == http.MethodGet {
			return resp.StatusCode, nil
		}
	}
	return 0, nil
}
