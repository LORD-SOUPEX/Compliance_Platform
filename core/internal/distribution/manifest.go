package distribution

// ToolEntry describes a tool artifact within the runtime manifest.
type ToolEntry struct {
	Name            string   `json:"name"`
	Version         string   `json:"version"`
	ArchiveURL      string   `json:"archive_url"`
	ArchiveSHA256   string   `json:"archive_sha256"`
	BinaryInArchive string   `json:"binary_in_archive"`
	BinarySHA256    string   `json:"binary_sha256"`
	VersionArgs     []string `json:"version_args,omitempty"`
}

// PlatformManifest maps tools for a specific OS-arch tuple.
type PlatformManifest struct {
	Status string               `json:"status"` // qualified, experimental, targeted
	Tools  map[string]ToolEntry `json:"tools"`
}

// RuntimeManifest represents the signed multi-platform distribution manifest.
type RuntimeManifest struct {
	SchemaVersion   int                         `json:"schema_version"`
	ManifestVersion string                      `json:"manifest_version"`
	Platforms       map[string]PlatformManifest `json:"platforms"`
}
