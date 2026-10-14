#!/bin/sh
set -eu
cd "$(dirname "$0")"
mode="${1:-proxy}"
case "$mode" in proxy|tun) ;; *) echo 'Usage: start-native.sh [proxy|tun]' >&2; exit 2 ;; esac
test -f ./credentials/client.json || { echo 'Generate credentials/client.json with bin/bfp-linux-amd64 keygen first.' >&2; exit 2; }
if test "$mode" = tun && test "$(id -u)" != 0; then
  echo 'TUN mode requires root privileges.' >&2
  exit 2
fi
umask 077
runtime="$(pwd)/runtime"
test ! -L "$runtime" || { echo 'The runtime directory must not be a symbolic link.' >&2; exit 2; }
mkdir -p "$runtime"
command -v flock >/dev/null 2>&1 || { echo 'The Linux launcher requires flock (util-linux).' >&2; exit 2; }
test ! -L "$runtime/native.lock" || { echo 'The instance lock must not be a symbolic link.' >&2; exit 2; }
# Keep the same lock for proxy and TUN: both modes share the mixed port and
# runtime. Acquire it before touching any marker or generated configuration.
exec 9>"$runtime/native.lock"
flock -n 9 || { echo 'BFP native is already running from this package.' >&2; exit 3; }
marker="$runtime/bfp-tun-supervisor.env"
device=""
test ! -L "$marker" || { echo 'The TUN marker must not be a symbolic link.' >&2; exit 2; }
test ! -L "$runtime/native-tun.generated.yaml" || { echo 'The generated configuration must not be a symbolic link.' >&2; exit 2; }
# Recovery precedes replacing any marker or configuration. The journal is
# bound to this boot and network namespace and deletes only owned resources.
test ! -L "$runtime/bfp-native-network.json" || { echo 'The network journal must not be a symbolic link.' >&2; exit 2; }
./bin/bfp-linux-amd64 native-recover -runtime "$runtime"
cleanup() {
  status=$?
  trap - EXIT INT TERM
  # This trap covers configuration preparation. After exec, the packaged
  # Go supervisor owns child termination and cleanup.
  if test "$mode" = tun; then
    if test -n "$device"; then ip link del "$device" 2>/dev/null || true; fi
    rm -f "$marker" "$runtime/native-tun.generated.yaml"
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
config="./configs/native-$mode.yaml"
# Recover an interrupted TUN instance even when switching back to proxy.
# The lock stays inherited by the native process until it actually exits.
if test -f "$marker"; then
  command -v ip >/dev/null 2>&1 || { echo 'Recovering the previous TUN requires ip (iproute2).' >&2; exit 2; }
  old_device=$(sed -n 's/^device=\(bfp-tun-[0-9a-f]\{7,8\}\)$/\1/p' "$marker" | head -n 1 || true)
  if test -n "${old_device:-}"; then ip link del "$old_device" 2>/dev/null || true; fi
  rm -f "$marker" "$runtime/native-tun.generated.yaml"
fi
if test "$mode" = tun; then
  command -v ip >/dev/null 2>&1 || { echo 'TUN cleanup requires ip (iproute2).' >&2; exit 2; }
  # Linux IFNAMSIZ includes the terminator, so a device name is at most
  # 15 bytes: the eight-byte prefix leaves seven hexadecimal characters.
  device="bfp-tun-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n' | cut -c 1-7)"
  awk -v d="$device" 'BEGIN{count=0} /^[[:space:]]*device:[[:space:]]*bfp-tun[[:space:]]*$/ {sub(/bfp-tun[[:space:]]*$/,d); count++} {print} END{if(count != 1) exit 1}' "$config" > "$runtime/native-tun.generated.yaml"
  printf 'version=1\nmode=tun\ndevice=%s\n' "$device" > "$marker"
  config="$runtime/native-tun.generated.yaml"
fi
# exec preserves the launcher's PID. The Linux supervisor starts Mihomo with
# a kernel parent-death SIGTERM and retains the instance lock until it stops.
exec ./bin/bfp-linux-amd64 native-supervise -runtime "$runtime" -config "$config" -device "$device"
