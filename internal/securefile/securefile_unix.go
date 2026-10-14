//go:build unix

package securefile

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func checkPlatformPath(string) error { return nil }
func checkNoReparse(string) error    { return nil }

func checkUnixInfo(info os.FileInfo, directory bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 {
		return ErrUnsafe
	}
	if directory {
		if !info.IsDir() || info.Mode().Perm()&0700 != 0700 {
			return ErrUnsafe
		}
	} else if !info.Mode().IsRegular() {
		return ErrUnsafe
	}
	return nil
}

func makePrivateDir(path string) error {
	if err := os.Mkdir(path, 0700); err != nil {
		return err
	}
	return checkPrivateDirectory(path)
}

func checkPrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	return checkUnixInfo(info, true)
}

func createPrivateFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err == nil {
		err = checkUnixInfo(info, false)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func openPrivateFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err == nil {
		err = checkUnixInfo(info, false)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
