//go:build windows

package clientconfig_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func makePubliclyReadable(t *testing.T, path string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal("read current fixture owner")
	}
	sid := user.User.Sid.String()
	descriptor, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;FA;;;" + sid + ")(A;;FR;;;WD)")
	if err != nil {
		t.Fatal("create unsafe fixture ACL")
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal("read unsafe fixture ACL")
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal("set unsafe fixture ACL")
	}
}

func linkedParent(t *testing.T, path string) string {
	t.Helper()
	junction := filepath.Join(t.TempDir(), "junction")
	// Directory junction creation does not need symlink privileges. The paths
	// are test-created temp paths; the command output is deliberately discarded.
	if err := exec.Command("cmd", "/c", "mklink", "/J", junction, filepath.Dir(path)).Run(); err != nil {
		t.Fatal("create fixture junction")
	}
	t.Cleanup(func() { _ = os.Remove(junction) })
	return filepath.Join(junction, filepath.Base(path))
}
