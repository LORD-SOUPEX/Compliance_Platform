package discovery

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestNodeModulesDoesNotDetectAnsibleAndStaysSmall(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "package.json"), `{"name":"bforge"}`)
	mustWrite(t, filepath.Join(repo, "src", "app.js"), "console.log(1)\n")
	role := filepath.Join(repo, "node_modules", "aria-query", "lib", "roles")
	mustWrite(t, filepath.Join(role, "checkboxRole.js"), "module.exports = {}\n")
	for i := 0; i < 2000; i++ {
		mustWrite(t, filepath.Join(repo, "node_modules", "pkg", "file"+strconv.Itoa(i)+".js"), "x")
	}
	// A roles/ path outside node_modules is still not Ansible without a real marker.
	mustWrite(t, filepath.Join(repo, "src", "roles", "checkboxRole.js"), "export {}\n")
	mustWrite(t, filepath.Join(repo, ".gitignore"), "ignored-vendor/\n")
	mustWrite(t, filepath.Join(repo, "ignored-vendor", "package.json"), `{"name":"hidden"}`)

	res, err := DiscoverAll(repo)
	if err != nil {
		t.Fatal(err)
	}
	js := tech(t, res, "javascript")
	if js.Status != "detected" {
		t.Fatalf("javascript status = %s", js.Status)
	}
	ansible := tech(t, res, "ansible")
	if ansible.Status != "absent" || ansible.EvidenceTotal != 0 {
		t.Fatalf("ansible falsely detected: %+v", ansible)
	}
	if js.EvidenceTotal < 2 {
		t.Fatalf("expected package.json and src/app.js to be counted, total=%d", js.EvidenceTotal)
	}
	if len(js.Evidence) > maxEvidence {
		t.Fatalf("evidence leaked: %d paths", len(js.Evidence))
	}
	for _, ev := range js.Evidence {
		if strings.Contains(ev, "node_modules") || strings.Contains(ev, "ignored-vendor") {
			t.Fatalf("ignored path kept as evidence: %s", ev)
		}
	}
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 1<<20 {
		t.Fatalf("discovery JSON = %d bytes, want <= 1 MiB", len(raw))
	}
}

func TestAnsibleMarkers(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "ansible.cfg"), "[defaults]\n")
	mustWrite(t, filepath.Join(repo, "roles", "web", "tasks", "main.yml"), "- debug: msg=ok\n")
	res, err := DiscoverAll(repo)
	if err != nil {
		t.Fatal(err)
	}
	ansible := tech(t, res, "ansible")
	if ansible.Status != "detected" || ansible.EvidenceTotal < 2 {
		t.Fatalf("ansible markers missed: %+v", ansible)
	}
}

func TestVueProjectPlansEslint(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "package.json"), `{"name":"vue-app"}`)
	mustWrite(t, filepath.Join(repo, "vite.config.js"), "export default {}\n")
	mustWrite(t, filepath.Join(repo, "src", "App.vue"), "<template><p>ok</p></template>\n")
	mustWrite(t, filepath.Join(repo, "README.md"), "# doc\n")
	res, err := DiscoverAll(repo)
	if err != nil {
		t.Fatal(err)
	}
	if tech(t, res, "javascript").Status != "detected" {
		t.Fatal("javascript/vue not detected")
	}
	if tech(t, res, "markdown").Status != "detected" {
		t.Fatal("markdown not detected")
	}
	raw, _ := json.Marshal(res)
	if !strings.Contains(string(raw), "App.vue") && tech(t, res, "javascript").EvidenceTotal < 2 {
		t.Fatal("vue file was not counted")
	}
}

func TestPlaybookRequiresHostsAndTasks(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "deploy.yml"), "hosts: all\ntasks:\n  - debug: msg=ok\n")
	res, err := DiscoverAll(repo)
	if err != nil {
		t.Fatal(err)
	}
	if tech(t, res, "ansible").Status != "detected" {
		t.Fatal("playbook with hosts and tasks was not detected")
	}

	other := t.TempDir()
	mustWrite(t, filepath.Join(other, "notes.yml"), "hosts: all\n")
	res, err = DiscoverAll(other)
	if err != nil {
		t.Fatal(err)
	}
	if tech(t, res, "ansible").Status != "absent" {
		t.Fatal("yaml with only hosts: must not be Ansible")
	}
}

func TestUnmarkedTfDefaultsToTerraform(t *testing.T) {
	t.Setenv("COMPLIANCE_IAC_DEFAULT", "terraform")
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "stack", "main.tf"), "resource \"null_resource\" \"x\" {}\n")
	res, err := DiscoverAll(repo)
	if err != nil {
		t.Fatal(err)
	}
	tf := tech(t, res, "terraform")
	tofu := tech(t, res, "opentofu")
	if tf.Status != "detected" {
		t.Fatalf("terraform = %+v", tf)
	}
	if tofu.Status == "detected" || tofu.Status == "ambiguous" || len(tofu.Ambiguities) > 0 {
		t.Fatalf("opentofu = %+v", tofu)
	}
}

func TestTestdataAndFixturesAreNotRoots(t *testing.T) {
	t.Setenv("COMPLIANCE_IAC_DEFAULT", "terraform")
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "main.tf"), "resource \"a\" \"b\" {}\n")
	mustWrite(t, filepath.Join(repo, "testdata", "hidden.tf"), "resource \"c\" \"d\" {}\n")
	mustWrite(t, filepath.Join(repo, "fixtures", "alt.tf"), "resource \"e\" \"f\" {}\n")
	mustWrite(t, filepath.Join(repo, "__snapshots__", "snap.tf"), "resource \"g\" \"h\" {}\n")
	res, err := DiscoverAll(repo)
	if err != nil {
		t.Fatal(err)
	}
	tf := tech(t, res, "terraform")
	for _, ev := range tf.Evidence {
		if strings.Contains(ev, "testdata") || strings.Contains(ev, "fixtures") || strings.Contains(ev, "__snapshots__") {
			t.Fatalf("fixture kept as evidence: %s", ev)
		}
	}
	named := filepath.Join(t.TempDir(), "testdata")
	mustWrite(t, filepath.Join(named, "main.tf"), "resource \"a\" \"b\" {}\n")
	res, err = DiscoverAll(named)
	if err != nil {
		t.Fatal(err)
	}
	if tech(t, res, "terraform").Status != "detected" {
		t.Fatal("a target named testdata must still be scanned")
	}
}

func TestContainerFilesInSubdirectories(t *testing.T) {
	repo := t.TempDir()
	mustWrite(t, filepath.Join(repo, "Dockerfile"), "FROM scratch\n")
	mustWrite(t, filepath.Join(repo, "Dockerfile.ci"), "FROM scratch\n")
	mustWrite(t, filepath.Join(repo, "images", "Containerfile"), "FROM scratch\n")
	mustWrite(t, filepath.Join(repo, ".gitpod.Dockerfile"), "FROM scratch\n")
	mustWrite(t, filepath.Join(repo, "Dockerfiles", "compliance_operator_content.Dockerfile"), "FROM scratch\n")
	res, err := DiscoverAll(repo)
	if err != nil {
		t.Fatal(err)
	}
	docker := tech(t, res, "docker")
	if docker.Status != "detected" || docker.EvidenceTotal < 5 {
		t.Fatalf("docker = %+v", docker)
	}
	joined := strings.Join(docker.Evidence, "\n")
	for _, name := range []string{"Dockerfile", "Dockerfile.ci", "Containerfile", ".gitpod.Dockerfile", "compliance_operator_content.Dockerfile"} {
		if !strings.Contains(joined, name) {
			t.Fatalf("missing %s in %s", name, joined)
		}
	}
}

func TestPathHasSkippedDir(t *testing.T) {
	if !PathHasSkippedDir("cli/testdata/README.md") || !PathHasSkippedDir(`cli\fixtures\a.md`) || PathHasSkippedDir("docs/README.md") {
		t.Fatal("skip detection")
	}
}

func tech(t *testing.T, res *DiscoveryResult, name string) TechnologyRecord {
	t.Helper()
	for _, item := range res.Technologies {
		if item.Technology == name {
			return item
		}
	}
	t.Fatalf("technology %s missing", name)
	return TechnologyRecord{}
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
