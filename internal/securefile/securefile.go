// Package securefile creates private credential files and reads bounded,
// owner-controlled regular files. It does not log or interpret their contents.
package securefile

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

var ErrUnsafe = errors.New("securefile: unsafe credential path or permissions")
var ErrSize = errors.New("securefile: invalid or oversized credential file")

// MakePrivateDir creates a new directory with private native permissions. It
// deliberately refuses any existing path and does not modify its permissions.
func MakePrivateDir(path string) error {
	absolute, err := checkedPath(path, false)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(absolute); err == nil {
		return os.ErrExist
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return makePrivateDir(absolute)
}

// WriteExclusive creates a private file in an already private directory. The
// file never exists with a public ACL/mode before credential bytes are written.
// Existing files are not modified. The caller owns cleanup after a write error.
func WriteExclusive(path string, data []byte) error {
	absolute, err := checkedPath(path, false)
	if err != nil {
		return err
	}
	if err := checkPrivateDirectory(filepath.Dir(absolute)); err != nil {
		return err
	}
	f, err := createPrivateFile(absolute)
	if err != nil {
		return err
	}
	for len(data) > 0 {
		n, e := f.Write(data)
		if e != nil {
			f.Close()
			return e
		}
		if n <= 0 || n > len(data) {
			f.Close()
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Read verifies the opened regular file's native ownership/permissions before
// reading at most max+1 bytes. On Windows ordinary parent directory ACLs are
// permitted; this does not guarantee safety in an attacker-writable namespace.
// Existing symlinks/reparse points in every path component are rejected. File
// opening itself is no-follow, but callers must trust parents against concurrent
// replacement; the package does not promise a fully race-proof ancestor walk.
func Read(path string, max int) ([]byte, error) {
	if max <= 0 || max > 64<<20 {
		return nil, ErrSize
	}
	absolute, err := checkedPath(path, true)
	if err != nil {
		return nil, err
	}
	f, err := openPrivateFile(absolute)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, ErrUnsafe
	}
	if info.Size() > int64(max) {
		return nil, ErrSize
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > max {
		return nil, ErrSize
	}
	return data, nil
}

func checkedPath(path string, requireFile bool) (string, error) {
	if path == "" {
		return "", ErrUnsafe
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if err = checkPlatformPath(absolute); err != nil {
		return "", err
	}
	first := absolute
	if !requireFile {
		first = filepath.Dir(absolute)
	}
	for current := first; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", ErrUnsafe
		}
		if err = checkNoReparse(current); err != nil {
			return "", err
		}
		if current != absolute && !info.IsDir() {
			return "", ErrUnsafe
		}
		if parent := filepath.Dir(current); parent == current {
			break
		}
	}
	return absolute, nil
}
