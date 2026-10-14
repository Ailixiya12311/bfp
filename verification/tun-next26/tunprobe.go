// tunprobe is a bounded, self-contained Linux TUN capability probe.
// It creates one temporary TUN device and closes it immediately. It does not
// add addresses, routes, policy rules, sysctls, or persistent services.
package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	ifNameSize = 16
	iffTun     = 0x0001
	iffNoPI    = 0x1000
	tunSetIFF  = 0x400454ca
)

func main() {
	result := map[string]any{"uid": os.Geteuid(), "gid": os.Getegid()}
	if info, err := os.Stat("/dev/net/tun"); err != nil {
		result["device_error"] = err.Error()
	} else {
		result["device_mode"] = fmt.Sprintf("%o", info.Mode().Perm())
	}
	if status, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range splitLines(status) {
			if len(line) >= 7 && (string(line[:6]) == "CapEff" || string(line[:7]) == "CapBnd:") {
				result[string(line[:lenIndex(line, ':')])] = string(line[lenIndex(line, ':')+1:])
			}
		}
	}
	if ns, err := os.Stat("/proc/self/ns/net"); err == nil {
		result["netns_inode"] = ns.Sys().(*syscall.Stat_t).Ino
	}
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		result["tun_open_error"] = err.Error()
		result["pass"] = false
		write(result)
		return
	}
	defer syscall.Close(fd)
	var ifr [40]byte
	copy(ifr[:ifNameSize], []byte("bfp-tunprobe"))
	binary.LittleEndian.PutUint16(ifr[ifNameSize:], iffTun|iffNoPI)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), tunSetIFF, uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		result["tun_ioctl_error"] = errno.Error()
		result["pass"] = false
		write(result)
		return
	}
	name := ifr[:ifNameSize]
	for i, b := range name {
		if b == 0 {
			name = name[:i]
			break
		}
	}
	result["interface"] = string(name)
	result["pass"] = true
	write(result)
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	for len(b) > 0 {
		i := 0
		for i < len(b) && b[i] != '\n' { i++ }
		out = append(out, b[:i])
		if i == len(b) { break }
		b = b[i+1:]
	}
	return out
}

func lenIndex(b []byte, needle byte) int {
	for i, c := range b { if c == needle { return i } }
	return 0
}

func write(v map[string]any) {
	data, _ := json.Marshal(v)
	_, _ = os.Stdout.Write(append(data, '\n'))
}
