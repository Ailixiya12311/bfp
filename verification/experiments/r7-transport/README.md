# r7 transport 本地回归证据

本目录保存受控本地实验，不属于 Go 源码 manifest，也不是完整发行版验收报告。

`before-fix.log` 是只增加回归测试、尚未修复核心时的真实失败输出：UDP deadline 被实际 TCP framed write 的 gate 阻塞绕过；满 incoming 时完整 TCP record 被丢弃。`after-fix.log` 是修复后同组及补充回归的通过输出。没有覆盖或重新判定 r6 WAN FAIL。

执行命令：

```powershell
go test -timeout 20s ./session -run '^TestTransport(UDPDeadline|TCPReader|TCPAdmission|UDPFull)' -count=1 -v
go test -timeout 30s ./session -run '^TestTransport' -count=1 -v
go test -timeout 30s ./session -run '^TestTransport' -count=10
go vet ./session
```

前一命令是修复前失败复现；后面 8 个 Transport 顶级测试通过，10 次重复通过，vet 通过。本代理未在此运行 race、全包或 WAN，由主验收独立运行。

固定源码 SHA256：

| 文件 | SHA256 |
|---|---|
| `session/flow.go` | `24f7b853ad54334281f2dce1806e550a416fe284cf72097d2bbf1d6203cf4384` |
| `session/session.go` | `a9562fe841beaff3b395d0733ae8a3091e5cdcd0e73c1eac396468fa52110451` |
| `session/carrier.go` | `7db408dcb7896a2e31a0bf7cc14f47a42db1bbca875c982734676d53bcf90251` |
| `session/transport_admission_test.go` | `b671e81950782a9c015736fe90fdb8eaa17a41fc08cf00cb34a219628f94ac24` |

修复只覆盖固定 write deadline 的 UDP actor admission 以及 TCP reader 到 actor 的有界背压/直接取消退出。动态改变 deadline、并发 writer 等 writeMu、TCP HOL、target 延迟和 UDP 完成消息队列丢弃仍有各自边界。r6 WAN 首次 timeout 的根因没有因此得到确认。

详细设计、未覆盖范围和分阶段 telemetry 方案见 `docs/TCP承载下UDP时限与排队审查.md` 第 9 节。
