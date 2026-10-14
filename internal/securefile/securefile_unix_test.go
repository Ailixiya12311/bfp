//go:build unix

package securefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUnixRejectsGroupOtherPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := MakePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	if err := WriteExclusive(path, []byte("fixture")); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0640, 0604, 0666} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := Read(path, 100); err == nil {
			t.Fatalf("accepted insecure mode %o", mode)
		}
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path, 100); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := WriteExclusive(filepath.Join(dir, "other.json"), []byte("fixture")); err == nil {
		t.Fatal("credential creation in a public parent accepted")
	}
}
