//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestWindowsNativeJobFixture(t *testing.T) {
	if os.Getenv("BFP_NATIVE_JOB_FIXTURE") != "1" {
		return
	}
	fmt.Println("job-child-ready")
	for {
		time.Sleep(time.Second)
	}
}

func TestWindowsNativeJobCloseKillsChild(t *testing.T) {
	job, err := windowsNativeChildJob()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if job != 0 {
			windows.CloseHandle(job)
		}
	}()
	child := exec.Command(os.Args[0], "-test.run=^TestWindowsNativeJobFixture$")
	child.Env = append(os.Environ(), "BFP_NATIVE_JOB_FIXTURE=1")
	child.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_SUSPENDED}
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer child.Process.Kill()
	if err := windowsNativeJoinAndResume(job, uint32(child.Process.Pid)); err != nil {
		_ = child.Process.Kill()
		_ = child.Wait()
		t.Fatal(err)
	}
	ready := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		ready <- line
	}()
	select {
	case line := <-ready:
		if line != "job-child-ready\n" {
			t.Fatalf("child failed to resume: %q", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("child did not resume")
	}
	if err := windows.CloseHandle(job); err != nil {
		t.Fatal(err)
	}
	job = 0
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	select {
	case <-done:
		// Job handle closure can terminate a process with exit code zero.
		// Completion proves the infinite-loop fixture has actually ended.
	case <-time.After(5 * time.Second):
		t.Fatal("job child survived job handle closure")
	}
}
