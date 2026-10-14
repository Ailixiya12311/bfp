module bfp-tun-next26-probe

go 1.26.0

// tunprobe.go is a Linux-only capability probe built inside the owned
// container. It is validation tooling, not part of the root Windows/Linux BFP
// product module; keeping this directory nested prevents root go test/vet
// from trying to type-check Linux syscall definitions on Windows.
