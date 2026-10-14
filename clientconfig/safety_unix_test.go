//go:build unix

package clientconfig_test

import (
	"os"
	"path/filepath"
	"testing"
)

func makePubliclyReadable(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal("set unsafe fixture mode")
	}
}

func linkedParent(t *testing.T, path string) string {
	t.Helper()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(filepath.Dir(path), link); err != nil {
		t.Fatal("create fixture symlink")
	}
	t.Cleanup(func() { _ = os.Remove(link) })
	return filepath.Join(link, filepath.Base(path))
}
