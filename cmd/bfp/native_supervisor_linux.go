//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"syscall"
	"time"
)

// nativeSupervise is the final exec target of the Linux package launcher.
// Keeping the launching thread alive is required: Linux associates Pdeathsig
// with the creating OS thread, rather than with the whole Go process.
func nativeSupervise(args []string) (status int, resultErr error) {
	f := flag.NewFlagSet("native-supervise", flag.ContinueOnError)
	runtimePath := f.String("runtime", "", "owned runtime directory")
	config := f.String("config", "", "packaged configuration")
	device := f.String("device", "", "owned TUN device; empty for proxy")
	if err := f.Parse(args); err != nil {
		return 1, err
	}
	if f.NArg() != 0 {
		return 1, errors.New("unexpected native supervisor arguments")
	}
	root, err := os.Getwd()
	if err != nil {
		return 1, err
	}
	if *runtimePath != filepath.Join(root, "runtime") {
		return 1, errors.New("native supervisor requires this package's runtime")
	}
	if *device != "" && !regexp.MustCompile(`^bfp-tun-[0-9a-f]{7}$`).MatchString(*device) {
		return 1, errors.New("invalid owned TUN device")
	}
	expectedConfig := filepath.Join(root, "configs", "native-proxy.yaml")
	marker := filepath.Join(*runtimePath, "bfp-tun-supervisor.env")
	generated := filepath.Join(*runtimePath, "native-tun.generated.yaml")
	if *device != "" {
		expectedConfig = generated
		record, readErr := os.ReadFile(marker)
		if readErr != nil || string(record) != "version=1\nmode=tun\ndevice="+*device+"\n" {
			return 1, errors.New("native supervisor TUN marker does not match")
		}
	}
	absConfig, err := filepath.Abs(*config)
	if err != nil || absConfig != expectedConfig {
		return 1, errors.New("native supervisor configuration does not match this package")
	}
	// fd 9 and its lock were acquired by the shell before creating any marker.
	// The native child receives a duplicate (fd 3) of the same locked file
	// description. After a supervisor SIGKILL, restart stays excluded until
	// that child has actually exited and closed its descriptors.
	lock, err := nativeInstanceLock(*runtimePath)
	if err != nil {
		return 1, err
	}
	defer lock.Close()
	var network *nativeNetworkLease
	cleanupAllowed := true
	defer func() {
		if *device == "" || !cleanupAllowed {
			return
		}
		if network != nil {
			if err := network.cleanup(); err != nil {
				status, resultErr = 1, errors.Join(resultErr, err)
				return
			}
		}
		// The instance lock excludes a new cooperating launcher. Only remove
		// this run's marker; an unexpected replacement is left untouched.
		record, readErr := os.ReadFile(marker)
		if readErr == nil && string(record) == "version=1\nmode=tun\ndevice="+*device+"\n" {
			_ = os.Remove(marker)
			_ = os.Remove(generated)
		}
	}()
	if *device != "" {
		network, err = prepareNativeNetwork(*runtimePath, absConfig, *device)
		if err != nil {
			return 1, err
		}
	}
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	child := exec.Command(filepath.Join(root, "bin", "mihomo-bfp-linux-amd64"), "-d", *runtimePath, "-f", absConfig)
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	readyReader, readyWriter, err := os.Pipe()
	if err != nil {
		return 1, err
	}
	defer readyReader.Close()
	defer readyWriter.Close()
	child.ExtraFiles = []*os.File{lock, readyWriter}
	child.Env = append(os.Environ(), "BFP_NATIVE_READY_FD=4")
	child.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	if err := child.Start(); err != nil {
		return 1, err
	}
	cleanupAllowed = false
	readyWriter.Close()
	runtimeReady := make(chan bool, 1)
	go func() {
		var token [6]byte
		_, err := io.ReadFull(readyReader, token[:])
		runtimeReady <- err == nil && string(token[:]) == "ready\n"
	}()
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	stop := func() error {
		_ = child.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
			cleanupAllowed = true
			return nil
		case <-time.After(5 * time.Second):
		}
		_ = child.Process.Kill()
		select {
		case <-done:
			cleanupAllowed = true
			return nil
		case <-time.After(2 * time.Second):
			return errors.New("native process did not stop; retaining its marker and lock ownership")
		}
	}
	var readyDeadline <-chan time.Time
	var readyTick <-chan time.Time
	initialized := false
	if *device != "" {
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		readyDeadline, readyTick = timer.C, ticker.C
	}
	for {
		select {
		case err := <-done:
			cleanupAllowed = true
			if readyDeadline != nil {
				fmt.Fprintln(os.Stderr, "BFP TUN interface failed to start; native process exited before readiness.")
				return 1, nil
			}
			return nativeExitCode(err), nil
		case sig := <-signals:
			if err := stop(); err != nil {
				return 1, err
			}
			if sig == os.Interrupt {
				return 130, nil
			}
			return 143, nil
		case ok := <-runtimeReady:
			initialized = ok
			runtimeReady = nil
		case <-readyTick:
			if !initialized {
				continue
			}
			probeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
			err := exec.CommandContext(probeCtx, "ip", "link", "show", "dev", *device).Run()
			cancel()
			if err == nil {
				if err := network.capture(); err != nil {
					stopErr := stop()
					return 1, errors.Join(err, stopErr)
				}
				fmt.Printf("BFP TUN interface ready: %s\n", *device)
				readyTick, readyDeadline = nil, nil
			}
		case <-readyDeadline:
			fmt.Fprintln(os.Stderr, "BFP TUN interface failed to start; stopping the native process.")
			if err := stop(); err != nil {
				return 1, err
			}
			return 1, nil
		}
	}
}

func nativeExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exited *exec.ExitError
	if errors.As(err, &exited) {
		if status, ok := exited.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return 128 + int(status.Signal())
		}
		return exited.ExitCode()
	}
	return 1
}
