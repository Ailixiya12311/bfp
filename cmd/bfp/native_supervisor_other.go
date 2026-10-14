//go:build !linux && !windows

package main

import "errors"

func nativeSupervise([]string) (int, error) {
	return 1, errors.New("native-supervise is a Linux package launcher command")
}

func nativeRecover([]string) (int, error) {
	return 1, errors.New("native-recover is a Linux package launcher command")
}
