package securefile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateCredentialLifecycleAndBounds(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private keys")
	if err := MakePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := MakePrivateDir(dir); err == nil {
		t.Fatal("existing directory was silently reused")
	}
	path := filepath.Join(dir, "config.json")
	payload := []byte(`{"test":"non-secret fixture"}`)
	if err := WriteExclusive(path, payload); err != nil {
		t.Fatal(err)
	}
	if err := WriteExclusive(path, []byte("overwrite")); err == nil {
		t.Fatal("existing credential was overwritten")
	}
	data, err := Read(path, len(payload))
	if err != nil || !bytes.Equal(data, payload) {
		t.Fatalf("private file roundtrip failed: %v", err)
	}
	if _, err := Read(path, len(payload)-1); !errors.Is(err, ErrSize) {
		t.Fatal("oversized file did not fail before content use")
	}
	for _, max := range []int{0, -1, 65 << 20} {
		if _, err := Read(path, max); !errors.Is(err, ErrSize) {
			t.Fatal("invalid bound accepted")
		}
	}
	if _, err := Read(dir, 100); err == nil {
		t.Fatal("directory accepted as credential file")
	}
}

func TestSymlinkFileAndAncestorRejected(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "private")
	if err := MakePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	if err := WriteExclusive(path, []byte("fixture")); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "linked-file")
	if err := os.Symlink(path, link); err != nil {
		t.Skip("symlink creation unavailable on this platform/account")
	}
	if _, err := Read(link, 100); err == nil {
		t.Fatal("credential symlink accepted")
	}
	parentLink := filepath.Join(base, "linked-directory")
	if err := os.Symlink(dir, parentLink); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(filepath.Join(parentLink, "config.json"), 100); err == nil {
		t.Fatal("symlink ancestor accepted")
	}
	if err := WriteExclusive(filepath.Join(parentLink, "new.json"), []byte("fixture")); err == nil {
		t.Fatal("write through symlink ancestor accepted")
	}
}
