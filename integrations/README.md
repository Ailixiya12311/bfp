# Integration snapshots

This directory contains pinned Mihomo and sing-box source snapshots, patch
inputs, and validation evidence. It is not part of the root `bfp` Go module.

The nested `go.mod` is deliberate: running `go test ./...` from the project
root must test the BFP product packages only. Native integration snapshots are
compiled from the corresponding upstream checkout and its own dependency
lock, then their results are copied back as evidence. A snapshot passing a
source or parser check does not by itself mean that the root BFP release has
native TUN integration enabled.
