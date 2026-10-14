//go:build windows

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows launcher recovery is performed by nativeSupervise while holding the
// package mutex; keep the hidden command available for the cross-platform CLI
// dispatch and reject direct use rather than touching arbitrary state.
func nativeRecover([]string) (int, error) {
	return 1, errors.New("native-recover is managed by the Windows package launcher")
}

// nativeSupervise owns the native child independently of the PowerShell
// launcher. It watches the launcher's process handle, so closing or forcibly
// ending the launcher cannot leave Mihomo running with the package's port and
// TUN state.
func nativeSupervise(args []string) (status int, resultErr error) {
	f := flag.NewFlagSet("native-supervise", flag.ContinueOnError)
	runtimePath := f.String("runtime", "", "owned runtime directory")
	configPath := f.String("config", "", "native configuration")
	device := f.String("device", "", "owned TUN device")
	grace := f.Duration("grace", 5*time.Second, "native child shutdown grace")
	if err := f.Parse(args); err != nil {
		return 1, err
	}
	if f.NArg() != 0 || *grace < time.Second || *grace > time.Minute {
		return 1, errors.New("invalid native supervisor arguments")
	}
	root, runtimeDir, err := windowsNativePackagePaths(*runtimePath)
	if err != nil {
		return 1, err
	}
	config, err := filepath.Abs(*configPath)
	if err != nil || !windowsNativeInside(root, config) {
		return 1, errors.New("native configuration must remain inside the package")
	}
	if *device != "" && !regexp.MustCompile(`^bfp-tun-[0-9a-f]{8}$`).MatchString(*device) {
		return 1, errors.New("invalid owned TUN device")
	}
	supervisorLock, err := windowsNativeSupervisorAcquire(runtimeDir)
	if err != nil {
		return 1, fmt.Errorf("acquire native supervisor lock: %w", err)
	}
	defer windows.CloseHandle(supervisorLock)

	parent, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(os.Getppid()))
	if err != nil {
		return 1, fmt.Errorf("open launcher process: %w", err)
	}
	defer windows.CloseHandle(parent)
	job, err := windowsNativeChildJob()
	if err != nil {
		return 1, fmt.Errorf("create native child job: %w", err)
	}
	defer windows.CloseHandle(job)
	childPath := filepath.Join(root, "bin", "mihomo-bfp-windows-amd64.exe")
	child := exec.Command(childPath, "-d", runtimeDir, "-f", config)
	// The child cannot initialize TUN until it belongs to the job. Closing the
	// supervisor's job handle then kills it even if the supervisor is forced out.
	child.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_SUSPENDED}
	child.Dir = root
	child.Stdout, child.Stderr, child.Stdin = os.Stdout, os.Stderr, os.Stdin
	if err := child.Start(); err != nil {
		return 1, err
	}
	if err := windowsNativeJoinAndResume(job, uint32(child.Process.Pid)); err != nil {
		_ = child.Process.Kill()
		_ = child.Wait()
		return 1, fmt.Errorf("contain native child: %w", err)
	}
	emit(map[string]any{"event": "mihomo_started", "mode": map[bool]string{true: "tun", false: "proxy"}[*device != ""], "pid": child.Process.Pid, "device": *device, "supervised": true})

	childDone := make(chan error, 1)
	go func() { childDone <- child.Wait() }()
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt)
	defer signal.Stop(signals)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	stop := func() error { return stopWindowsNativeChild(child, childDone, *grace) }
	for {
		select {
		case err := <-childDone:
			cleanupErr := windowsNativeCleanup(root, runtimeDir, *device)
			if cleanupErr != nil {
				return 1, cleanupErr
			}
			return nativeWindowsExitCode(err), nil
		case <-signals:
			err := stop()
			return 130, errors.Join(err, windowsNativeCleanup(root, runtimeDir, *device))
		case <-tick.C:
			state, waitErr := windows.WaitForSingleObject(parent, 0)
			if waitErr != nil {
				err := stop()
				return 1, errors.Join(waitErr, err, windowsNativeCleanup(root, runtimeDir, *device))
			}
			if state == windows.WAIT_OBJECT_0 {
				err := stop()
				return 143, errors.Join(err, windowsNativeCleanup(root, runtimeDir, *device))
			}
		}
	}
}

func windowsNativeChildJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

func windowsNativeJoinAndResume(job windows.Handle, pid uint32) error {
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(process)
	if err := windows.AssignProcessToJobObject(job, process); err != nil {
		return err
	}
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	var threadID uint32
	for err = windows.Thread32First(snapshot, &entry); err == nil; err = windows.Thread32Next(snapshot, &entry) {
		if entry.OwnerProcessID != pid {
			continue
		}
		if threadID != 0 {
			return errors.New("suspended native child has more than one thread")
		}
		threadID = entry.ThreadID
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) || threadID == 0 {
		return fmt.Errorf("native child primary thread unavailable: %w", err)
	}
	thread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, threadID)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(thread)
	count, err := windows.ResumeThread(thread)
	if err != nil {
		return err
	}
	if count != 1 {
		return fmt.Errorf("unexpected native child suspend count: %d", count)
	}
	return nil
}

func windowsNativePackagePaths(runtimePath string) (string, string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", "", err
	}
	root := filepath.Dir(filepath.Dir(executable))
	runtimeDir, err := filepath.Abs(runtimePath)
	if err != nil || !windowsNativeInside(root, runtimeDir) || strings.EqualFold(runtimeDir, root) {
		return "", "", errors.New("runtime must remain inside the package directory")
	}
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		return "", "", err
	}
	return root, runtimeDir, nil
}

func windowsNativeInside(root, target string) bool {
	root = filepath.Clean(root)
	target = filepath.Clean(target)
	relative, err := filepath.Rel(root, target)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

func windowsNativeSupervisorAcquire(runtimeDir string) (windows.Handle, error) {
	path, err := windows.UTF16PtrFromString(filepath.Join(runtimeDir, "native-supervisor.lock"))
	if err != nil {
		return 0, err
	}
	handle, err := windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			return 0, errors.New("another BFP native supervisor is still stopping")
		}
		return 0, err
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		windows.CloseHandle(handle)
		return 0, errors.New("native supervisor lock may not be a reparse point")
	}
	return handle, nil
}

func stopWindowsNativeChild(child *exec.Cmd, done <-chan error, grace time.Duration) error {
	if child == nil || child.Process == nil {
		return nil
	}
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		if err := child.Process.Kill(); err != nil {
			return err
		}
		select {
		case err := <-done:
			return err
		case <-time.After(2 * time.Second):
			return errors.New("native process did not stop")
		}
	}
}

func nativeWindowsExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exited *exec.ExitError
	if errors.As(err, &exited) {
		return exited.ExitCode()
	}
	return 1
}

func windowsNativeCleanup(root, runtimeDir, device string) error {
	if device != "" {
		// Keep the journal if recovery fails; the next administrator start/stop
		// must still have the exact adapter identity needed to finish recovery.
		cleanup := filepath.Join(root, "windows-tun-cleanup.ps1")
		if _, err := os.Stat(cleanup); err != nil {
			return fmt.Errorf("native TUN recovery entry unavailable: %w", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", cleanup, "-Runtime", runtimeDir)
		command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if output, err := command.CombinedOutput(); err != nil {
			return fmt.Errorf("native TUN recovery failed; journal retained: %w: %s", err, strings.TrimSpace(string(output)))
		}
	}
	for _, name := range []string{"bfp-tun-supervisor.json", "native-tun.generated.yaml"} {
		_ = os.Remove(filepath.Join(runtimeDir, name))
	}
	return nil
}
