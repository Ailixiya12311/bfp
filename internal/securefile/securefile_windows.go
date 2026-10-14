//go:build windows

package securefile

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func currentSID() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return user.User.Sid.Copy()
}

func privateAttributes(directory bool) (*windows.SecurityAttributes, error) {
	sid, err := currentSID()
	if err != nil {
		return nil, err
	}
	inherit := ""
	if directory {
		inherit = "OICI"
	}
	sd, err := windows.SecurityDescriptorFromString("O:" + sid.String() + "D:P(A;" + inherit + ";FA;;;" + sid.String() + ")")
	if err != nil {
		return nil, err
	}
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}, nil
}

func checkPlatformPath(path string) error {
	// An alternate data stream is not a separate credential file with its own
	// independently checked ACL, and device paths are not accepted here.
	if strings.HasPrefix(path, `\\?\`) || strings.HasPrefix(path, `\\.\`) {
		return ErrUnsafe
	}
	volume := filepath.VolumeName(path)
	if strings.Contains(strings.TrimPrefix(path, volume), ":") {
		return ErrUnsafe
	}
	return nil
}

func checkNoReparse(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attributes, err := windows.GetFileAttributes(p)
	if err != nil {
		return err
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrUnsafe
	}
	return nil
}

func makePrivateDir(path string) error {
	attrs, err := privateAttributes(true)
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	err = windows.CreateDirectory(p, attrs)
	runtime.KeepAlive(attrs)
	if err != nil {
		return err
	}
	return checkPrivateDirectory(path)
}

func checkPrivateDirectory(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(p, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(h, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return ErrUnsafe
	}
	return checkHandleSecurity(h, true)
}

func createPrivateFile(path string) (*os.File, error) {
	attrs, err := privateAttributes(false)
	if err != nil {
		return nil, err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_WRITE|windows.READ_CONTROL, 0, attrs, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	runtime.KeepAlive(attrs)
	if err != nil {
		return nil, err
	}
	if err = checkHandleSecurity(h, false); err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

func openPrivateFile(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(h, &info); err == nil && info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		err = ErrUnsafe
	}
	if err == nil {
		err = checkHandleSecurity(h, false)
	}
	if err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

func checkHandleSecurity(h windows.Handle, requireProtected bool) error {
	current, err := currentSID()
	if err != nil {
		return err
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	if !sd.IsValid() {
		return ErrUnsafe
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !windows.EqualSid(owner, current) {
		return ErrUnsafe
	}
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	if requireProtected && control&windows.SE_DACL_PROTECTED == 0 {
		return ErrUnsafe
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return ErrUnsafe
	}
	var ownerAccess bool
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err = windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		// Conditional/object/callback ACEs need full access-check evaluation;
		// this deliberately conservative profile refuses unsupported ACE types.
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return ErrUnsafe
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() {
			return ErrUnsafe
		}
		if windows.EqualSid(sid, current) {
			ownerAccess = ownerAccess || ace.Mask != 0
			continue
		}
		if sid.String() != "S-1-5-18" && sid.String() != "S-1-5-32-544" && ace.Mask != 0 {
			return ErrUnsafe
		}
	}
	if !ownerAccess {
		return ErrUnsafe
	}
	return nil
}
