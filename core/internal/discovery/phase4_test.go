package discovery

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSecretsAndGenericYAMLDiscovery(t *testing.T) {
	repo := t.TempDir()
	files := map[string]string{
		"app.py":                       "print('x')\n",
		"config/settings.yml":          "key: value\n",
		"deploy/ansible.cfg":           "[defaults]\n",
		"deploy/site.yml":              "- hosts: all\n  tasks: []\n",
		"chart/templates/service.yaml": "name: {{ .Values.name }}\n",
		".gitlab-ci.yml":               "stages: [build]\n",
	}
	for name, body := range files {
		path := filepath.Join(repo, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	result, err := DiscoverAll(repo)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]TechnologyRecord{}
	for _, tech := range result.Technologies {
		byName[tech.Technology] = tech
	}
	secrets := byName["secrets"]
	if secrets.Status != "detected" || len(secrets.Roots) != 1 || secrets.Roots[0] != "." {
		t.Fatalf("secrets = %+v", secrets)
	}
	yaml := byName["yaml"]
	roots := map[string]bool{}
	for _, root := range yaml.Roots {
		roots[root] = true
	}
	if yaml.Status != "detected" || !roots["config"] || !roots["."] || roots["deploy"] || roots["chart/templates"] {
		t.Fatalf("yaml roots = %v (Ansible and templates must stay out)", yaml.Roots)
	}
}
