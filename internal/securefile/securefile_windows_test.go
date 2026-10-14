//go:build windows

package securefile

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsProtectedOwnerOnlyAndUnsafeACL(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := MakePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	if err := WriteExclusive(path, []byte("non-secret fixture")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{dir, path} {
		sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		control, _, err := sd.Control()
		if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
			t.Fatal("private native ACL inheritance was not disabled")
		}
		acl, _, err := sd.DACL()
		if err != nil || acl == nil || acl.AceCount != 1 {
			t.Fatal("generated ACL is not owner-only")
		}
	}
	current, err := currentSID()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("O:" + current.String() + "D:P(A;;FA;;;" + current.String() + ")(A;;FR;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path, 100); err == nil {
		t.Fatal("Everyone-readable credential accepted")
	}
	if err := WriteExclusive(filepath.Join(filepath.Dir(dir), "unsafe.json"), []byte("fixture")); err == nil {
		t.Fatal("unprotected ordinary parent used for key creation")
	}
}

func TestWindowsPrivateFileInOrdinaryParentCanReadAndADSRejected(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "private.json")
	f, err := createPrivateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write([]byte("fixture")); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
	if _, err := Read(path, 100); err != nil {
		t.Fatalf("secure file rejected merely for ordinary parent ACL: %v", err)
	}
	if _, err := Read(path+":extra", 100); err == nil {
		t.Fatal("alternate data stream accepted")
	}
	if _, err := Read(filepath.Join(base, "missing"), 100); !os.IsNotExist(err) {
		t.Fatalf("missing credential error: %v", err)
	}
}

func TestWindowsTrustedSystemAdminACLAndNullACL(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := MakePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	if err := WriteExclusive(path, []byte("fixture")); err != nil {
		t.Fatal(err)
	}
	current, err := currentSID()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("O:" + current.String() + "D:P(A;;FA;;;" + current.String() + ")(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path, 100); err != nil {
		t.Fatalf("current owner plus SYSTEM/Administrators ACL refused: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path, 100); err == nil {
		t.Fatal("fully permissive null DACL accepted")
	}
}
