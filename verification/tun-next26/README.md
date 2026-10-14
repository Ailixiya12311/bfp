# next26 owned TUN runtime harness

The `go.mod` in this directory intentionally keeps the Linux-only `tunprobe.go`
outside the root BFP product module. Build the probe inside its Linux container
or use the recorded probe binary; it is not a production BFP package.

This directory contains the **container-side** fixtures and evidence parsers
for a real Mihomo TUN/BFP acceptance run. It is intentionally separate from
the frozen next25 source and does not contain credentials, a proxy
implementation, or a host/remote runner.

Run `generate_matrix.py` once to create `matrix.json`, `negative-matrix.json`,
and four Mihomo YAML templates under `configs/`. The templates contain the
literal placeholder `BFP_CLIENT_CONFIG`; the LA runner must replace it with an
owned authenticated `client.json`. The generated matrix contains 32 positive
rows and nine negative checks. A positive row is not a socket echo pass by
itself: route evidence, a packet seen on the real TUN, BFP/session evidence,
the numeric backend packet, and absence of carrier re-entry are all required.

All commands below are designed for the Linux container's own network
namespace. They use Python's standard library and ordinary kernel sockets.
The probe never speaks SOCKS and never imports BFP. Start it as UID 20001 so
the runner's UID policy routes it into TUN. Echo, DNS, Mihomo, and BFP may run
as UID 0 and must remain outside the probe UID route.

```sh
python3 /opt/tun-next26/generate_matrix.py --output /opt/tun-next26
python3 /opt/tun-next26/tun_harness.py preflight --require --output /evidence/preflight.json
python3 /opt/tun-next26/tun_harness.py dns --host 127.0.0.1 --port 15353 --log /evidence/dns.jsonl
python3 /opt/tun-next26/tun_harness.py echo --mode both --ipv4 192.0.2.10 --ipv6 fd77:25::10 --port 18080 --log /evidence/echo.jsonl
```

The runner then starts the real Linux Mihomo binary with one generated config,
the BFP server, the SOCKS5 detour fixture, and `tcpdump` captures on both the
TUN and the owned carrier/backend interfaces. For each matrix row it invokes,
for example:

```sh
docker exec --user 20001 "$NAME" \
  python3 /opt/tun-next26/tun_harness.py probe \
  --network udp --host 198.18.0.10 --port 18080 \
  --expect-source 198.18.0.10 --output /evidence/row.json
```

The target is always numeric. A fake A or AAAA value is obtained from the
Mihomo DNS response first and then passed to the ordinary probe. The DNS
fixture only supplies deterministic A/AAAA records for the owned backend,
carrier, and detour names; it does not access an upstream resolver.

## Route and namespace evidence

The runner owns all route mutations. Before any row, it records the namespace
inode, `ip -j rule`, links, and `ip -j route get ... uid 20001`:

```sh
python3 /opt/tun-next26/tun_harness.py route \
  --destination 198.18.0.10 --uid 20001 --require \
  --output /evidence/route-fake-a.json
```

The intended policy has an explicit probe UID rule before the fallback
`unreachable` rule. It moves the namespace's `local` lookup after that UID
rule, so a probe cannot reach a same-namespace echo socket through the normal
`pref 0 lookup local` rule. If the TUN route is removed, the probe must fail
and the echo fixture's counters must remain unchanged. This policy must be
installed and removed inside the owned container only; do not use host-network,
`--privileged`, or a host route table.

## Packet capture evidence

`tun_harness.py pcap` parses classic libpcap files without Scapy or pyshark. It
supports Ethernet, Linux cooked v1/v2, and raw-IP/TUN captures, and emits
normalised IPv4/IPv6 TCP/UDP flows:

```sh
python3 /opt/tun-next26/tun_harness.py pcap --pcap /evidence/tun.pcap \
  --require-destination 198.18.0.10 --minimum 1 \
  --output /evidence/tun-summary.json
python3 /opt/tun-next26/tun_harness.py pcap --pcap /evidence/backend.pcap \
  --require-destination 192.0.2.10 --minimum 1
```

Unsupported pcapng files and missing files are reported as unavailable and are
never interpreted as zero packets. Use `tcpdump -w` (classic pcap) for these
captures. Capture the carrier endpoint separately; a carrier packet that also
appears as a business TUN destination is a recursion failure.

## Container preflight and capability boundary

The preflight records `ip`, `tcpdump`, and `ss` availability, `/dev/net/tun`,
the effective capability bits (`CAP_NET_ADMIN`, `CAP_NET_RAW`), IPv6 sysctls,
and the network namespace inode. The known cached image record only proves Go
and GCC; it does not prove these tools or TUN access. A missing tool or device
must be recorded as incomplete. Do not replace a missing TUN or capture tool
with a loopback-only test.

The intended container flags are `--network none`, an explicit
`--device /dev/net/tun`, `CAP_NET_ADMIN` (and `CAP_NET_RAW` for capture),
`--cap-drop ALL` followed by only those additions, `no-new-privileges`,
read-only root plus an owned writable evidence tmpfs/bind, resource limits,
and no host network, published ports, Docker socket, or host network mounts.

## Negative checks

`negative-matrix.json` includes unknown fake A/AAAA, BFP down, TUN route
removed, SOCKS detour down, wrong pinned key, and missing/self/cyclic
`dialer-proxy` references. The latter three config checks are explicitly marked
“not countable until BFP `ProxyInfo().DialerProxy` is wired”: Mihomo's existing
graph validator only sees fields exposed through `ProxyInfo`, while current BFP
inherits `Base.ProxyInfo` without that field. They must not be silently
reported as passed.

After the run, terminate every owned process, remove the owned container, and
compare the host's pre/post snapshots. The expected outcome is no host route,
rule, interface, listener, or unrelated Docker/Tailscale change. This harness
does not perform that host snapshot itself and has no remote execution path.

## Bounded smoke evidence (2026-10-10)

The current LA receiver smoke is recorded in
`mihomo-tun-smoke-d95073f5300fb1906da470ab7aee911c.json`. It uses an owned
`--network none` container, an explicit `/dev/net/tun`, `CAP_NET_ADMIN`/
`CAP_NET_RAW` plus the bounded UID transition capabilities, the Mihomo
`with_gvisor`/`no_tailscale` Linux candidate, and the next25 BFP binary. The
unprivileged UID 20001 probe obtained `198.18.0.4` from Mihomo fake-IP DNS and
completed both TCP and UDP echo through the `bfp` outbound. Mihomo logs show
both flows selecting `proxy[bfp]`; the BFP server recorded one UDP Session with
one flow, two opens, ACK progress, and zero drops. The fixture recorded one
target open. Owned processes, containers, and run directory were removed, and
the receiver snapshot stayed unchanged after the documented dynamic UDP
listener churn classification. This is a bounded integration proof for TUN,
fake-IP, BFP, and local TCP/UDP forwarding; AAAA/IPv6, fallback fault
injection, detour matrices, and long-run/WAN acceptance remain separate gates.
