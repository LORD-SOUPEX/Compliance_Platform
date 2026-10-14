package distribution

import (
	"archive/tar"
	"bytes"
	"testing"

	"github.com/ulikunitz/xz"
)

func TestExtractBinaryTarXZ(t *testing.T) {
	var payload bytes.Buffer
	xw, err := xz.NewWriter(&payload)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(xw)
	body := []byte("shellcheck-binary")
	hdr := &tar.Header{
		Name: "shellcheck-v0.10.0/shellcheck",
		Mode: 0o755,
		Size: int64(len(body)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := xw.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := extractBinary(payload.Bytes(), "shellcheck", "https://example.invalid/shellcheck.tar.xz")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("extractBinary() = %q, want %q", got, body)
	}
}
