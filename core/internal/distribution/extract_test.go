package distribution

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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

func TestExtractTreeRejectsMaliciousSymlinks(t *testing.T) {
	// 1. Test relative symlink escaping destination
	var bufRelative bytes.Buffer
	gwRel := gzip.NewWriter(&bufRelative)
	twRel := tar.NewWriter(gwRel)

	hdrRel := &tar.Header{
		Typeflag: tar.TypeSymlink,
		Name:     "sub/bad_link",
		Linkname: "../../outside.txt",
		Mode:     0o777,
	}
	if err := twRel.WriteHeader(hdrRel); err != nil {
		t.Fatal(err)
	}
	_ = twRel.Close()
	_ = gwRel.Close()

	destDir := t.TempDir()
	err := extractTree(bufRelative.Bytes(), "https://example.invalid/test.tar.gz", destDir)
	if err == nil {
		t.Fatal("attendu une erreur sur un lien symbolique sortant du répertoire de destination, obtenu nil")
	}

	// 2. Test absolute symlink (/etc/passwd)
	var bufAbs bytes.Buffer
	gwAbs := gzip.NewWriter(&bufAbs)
	twAbs := tar.NewWriter(gwAbs)

	hdrAbs := &tar.Header{
		Typeflag: tar.TypeSymlink,
		Name:     "sub/abs_link",
		Linkname: "/etc/passwd",
		Mode:     0o777,
	}
	if err := twAbs.WriteHeader(hdrAbs); err != nil {
		t.Fatal(err)
	}
	_ = twAbs.Close()
	_ = gwAbs.Close()

	destDirAbs := t.TempDir()
	errAbs := extractTree(bufAbs.Bytes(), "https://example.invalid/test.tar.gz", destDirAbs)
	if errAbs == nil {
		t.Fatal("attendu une erreur sur un lien symbolique absolu, obtenu nil")
	}
}
