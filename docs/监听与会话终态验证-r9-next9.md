# 监听与会话终态验证：r9-next9

日期：2026-10-09。next9 从冻结 next8 的 106 个 Go/module 文件逐项复制并核对 SHA256 后开始，实现生产双协议临时端口分配，移除三处测试夹具的端口预检／释放／再构造窗口，并增加三个真实加密业务 DNS 终态用例。

**本轮已冻结 111 个 Go/module 文件，单次完整本地 gate、vet、Windows/Linux 构建通过。** 洛杉矶独立 Linux race 测试程序退出 0、16 packages PASS；严格环境门禁因 host listener 快照变化仍为 FAIL，原始 overall 失败没有覆盖。next9 WAN 未执行。本轮不是有界关闭协议实现，也不是完整短时网络验收。

```text
source_freeze=frozen
full_local_gate=pass
builds=pass
independent_linux_race_test_program=pass
strict_environment_gate=fail_listener_snapshot_changed
independent_linux_race_overall=fail
next9_wan=not_run
bounded_close_control=planned_not_implemented
acceptance_complete=false
production_ready=false
released=false
goal_status=active
```

## 1. 源码边界与历史失败

[parent-source-manifest.json](C:/Users/developer/Desktop/bfp/.staging/r9-next9/verification/parent-source-manifest.json) 记录 parent 为 next8、106 个文件、`all_copied_hashes_match=true`。parent manifest SHA256 为 `37d58148659691a82618222dbcd1da88bf525714fdf12471d14b71b9360c5fd0`。这是开发开始时的复制证明，不能表示 next9 仍与 next8 二进制相同。

next9 修改了生产 `session/server.go`，新增 listener 实现／平台错误分类／测试，并修改三个 fixture、增加实际 DNS 终态测试。[source-diff.json](C:/Users/developer/Desktop/bfp/.staging/r9-next9/verification/r9-next9/source-diff.json) 记录新增 5 文件、修改 4 文件、无删除，并核对 next8 parent 与 next9 当前 frozen source 都未变。后续验证必须绑定 next9 当前的 manifest 和二进制；next8 PASS、race 失败或 WAN 未运行状态均不继承成 next9 结果。

next8 的独立 Linux race 原失败保留：run `c0d872535db2d5bc4515e8720cfc4410`，15 packages PASS、Session package FAIL；`TestClassAnnouncementRuntimeFINTerminalDoesNotAllocate/tcp` 在夹具创建时 TCP `42884` address already in use，业务断言尚未执行。原非 verbose 日志无法区分失败是在 TCP 预检，还是释放预留后再次构造的窗口；也未查明 owner／TIME_WAIT。不能把本轮修复方案写成已证实该失败的精确根因。原日志没有 DATA RACE 报告，但原 race gate 仍为 FAIL，未重跑原不变源码筛选通过。

原证据见 [next8 race-binding.json](C:/Users/developer/Desktop/bfp/.staging/r9-next8/verification/r9-next8/race-binding.json) 与 [next8 交接](C:/Users/developer/Desktop/bfp/.staging/r9-next8/verification/r9-next8/handoff.md)。next6 的正常 UDP 47/50、35 秒业务超时及 UDP→TCP idle restore 失败也保留，本轮不提供它们的根因修复结论。

## 2. 生产双协议 listener

实现见 [server_listen.go](C:/Users/developer/Desktop/bfp/.staging/r9-next9/session/server_listen.go)、[server_listen_windows.go](C:/Users/developer/Desktop/bfp/.staging/r9-next9/session/server_listen_windows.go)、[server_listen_nonwindows.go](C:/Users/developer/Desktop/bfp/.staging/r9-next9/session/server_listen_nonwindows.go)，由 [NewServer](C:/Users/developer/Desktop/bfp/.staging/r9-next9/session/server.go:93) 调用。

构造先创建 TCP listener，在其持续持有实际分配地址期间绑定同地址 UDP；成功时这两个原 socket 直接移交给 Server，直到 Server.Close。没有成功前释放、再预检或重新绑定的窗口。

仅当调用者请求 ephemeral port，例如 `127.0.0.1:0`、省略 port 或等价数值零，才允许最多 16 个候选。每个候选 TCP bind 成功但 UDP 冲突时，先关闭被拒绝的 TCP listener，再选择下一个临时地址。最终失败保留原错误 cause；没有无限重试、sleep 或系统端口设置修改。

| 条件 | 行为 |
|---|---|
| 固定端口 | 只构造一次；UDP bind 失败关闭 TCP，直接返回，不擅自更换端口 |
| TCP listen 失败 | 立即返回；即使之前已经拒绝某个 UDP 候选，也不重试本次 TCP 错误 |
| TCP 地址不能转换成 UDP 地址 | 关闭 TCP，直接返回；不调用 UDP bind、不继续候选 |
| Linux／非 Windows UDP EADDRINUSE | 仅 ephemeral 请求可继续选择下一候选 |
| Windows UDP Winsock 10048 或 WSAEACCES | 仅 ephemeral 请求可作有界候选拒绝 |
| 文件描述符、其他非冲突 UDP 错误 | 关闭 TCP，立即返回 |
| 16 个候选全部失败 | 错误中明确数量并保留底层 cause，全部候选资源已关闭 |

Windows 的 WSAEACCES 可来自端口排除、exclusive socket 或权限限制，本轮只将其用于临时候选拒绝，不诊断其具体原因。TCP 错误不因同样 errno 被重试；Linux 的普通 EACCES 不列入冲突候选。固定地址不隐藏权限失败。

这是服务器管理 socket 的生产变更，不改动业务 frame、wireVersion 3、UDP→TCP 恢复策略、padding、15 秒 UDP watchdog、30 秒 RetainTimeout 或原 8 秒业务期限。

## 3. 三处 fixture 接线

以下 helper 均改为一次 `NewServer(Listen: "127.0.0.1:0")`，由生产构造连续拥有 TCP／UDP socket。fixture 不再自行预留 UDP、预检 TCP、释放后又调用 NewServer；测试失败不被 helper 自动重试或跳过。

| 文件／helper | 本轮变化 | 验证归属 |
|---|---|---|
| [server_security_test.go](C:/Users/developer/Desktop/bfp/.staging/r9-next9/session/server_security_test.go:13)，`newSecurityTestServer` | 使用生产有界临时端口分配 | listener 定向用例实际调用；完整 gate 还执行其 security／ticket／capability 等调用方 |
| [class_recovery_fault_test.go](C:/Users/developer/Desktop/bfp/.staging/r9-next9/session/class_recovery_fault_test.go:305)，`newClassRecoveryFixture` | 移除预检释放；真实 recovery relay 及其原 deadlines 保留 | 它不在 `^TestServerListen` 定向选集内，实际分类恢复用例由本轮 full gate 覆盖 |
| [session_dns_runtime_test.go](C:/Users/developer/Desktop/bfp/.staging/r9-next9/gateway/session_dns_runtime_test.go:118)，`sessionDNSRuntimeServer` | 两 fresh Session 既有 DNS runtime 夹具改用生产 allocator | 它不在新增三个终态用例的定向选集内，原 fresh-isolation 测试由本轮 full gate 覆盖 |

生产 allocator 允许在一次构造内部拒绝临时 UDP 候选，这与“fixture 重跑一个失败测试”不同。测试次数、业务工作量、目标拨号和关闭观察时限没有因此增加。

## 4. listener 单次定向结果

命令：`go test -json ./session -run ^TestServerListen -count=1 -timeout=60s`。Windows 单次退出 0，9 个顶层测试与 8 个子测试 PASS，wall 3.467 秒，package 0.921 秒；无失败、skip 或 JSON parse error。

测试覆盖：冲突候选顺序／旧候选 Close 恰好一次；成功 socket 直接转交；固定端口不搜索；非冲突 UDP 失败立即返回；首候选及前次 UDP 冲突后的 TCP 失败都立即返回；16 候选硬上限；地址转换错误不搜索；平台错误分类；只有请求 ephemeral 的地址启用搜索；真实 Server 构造保持同 IP／port 且 Server.Close 关闭两 socket。

证据：[targeted-summary-attempt-01.json](C:/Users/developer/Desktop/bfp/.staging/r9-next9/verification/listener-allocation/targeted-summary-attempt-01.json)、[原始 JSONL](C:/Users/developer/Desktop/bfp/.staging/r9-next9/verification/listener-allocation/targeted-go-test-attempt-01.jsonl)。summary 保存八个关联源文件 SHA256，并证明对应 owned source 在本次定向运行中 unchanged。原日志 SHA256 为 `76e64f7acc3689aca87aee053adc766e2833f56004b1e6034bd4ca592c87e4a0`。

该定向记录当时其他 next9 开发可能继续，不是全阶段 freeze，也不是 Linux runtime、race 或 WAN 结果；正式全量记录见第 6 节。

## 5. 三个实际 DNS 终态用例

新增 [session_dns_termination_test.go](C:/Users/developer/Desktop/bfp/.staging/r9-next9/gateway/session_dns_termination_test.go)。每个场景均从真实 NewServer／Serve、Noise 建连、加密 UDP Flow 开始，通过 gateway SessionFactory 私有 DNS scope、受控域名解析与实际 numeric TCP echo 完成关闭前业务。这里使用受控 loopback 答案，未查询外部 DNS，也没有远程传输。

关闭前证明：一个 fresh Session、一个 scope、一次 lookup、一个真实目标 socket；cache 有一个 positive entry，scope 尚未 closed，UDP carrier 活动，目标尚未关闭。随后不调用 Client.Close 强迫产生测试结果，分别触发以下终态：

| 顶层测试 | 实际触发 | 单次定向时间／结论 |
|---|---|---|
| `TestSessionDNSRuntimeRevocationClearsCacheAndTarget` | 服务端 Go 进程内 `RevokeDevice` | 1.06 秒，PASS；scope 和目标资源清理证据成立 |
| `TestSessionDNSRuntimeImmutableExpiryClearsCacheAndTarget` | 构造时固定 `MaxSessionLifetime=250ms` 自然到期 | 0.25 秒，PASS；资源清理与客户端原 Flow 返回 `session.ErrClosed` 均成立 |
| `TestSessionDNSRuntimeParentCancellationClearsCacheAndTarget` | 取消父 Serve context | 1.06 秒，PASS；服务端资源清理证据成立 |

各用例总业务 context 固定 5 秒，终态后资源观察固定 1 秒；expiry 仅缩短该测试的授权 lifetime，仍沿用生产 `UDPFailureBudget=15s` 和 `RetainTimeout=30s`。目标 echo 的原始 socket deadline 为总 5 秒，无法替代终态后的 1 秒清理观察；成功条件在调用最后的 owner cleanup 之前已经满足。

每个测试在原终态触发加观察的总 1 秒内核对：目标 echo worker 因 socket 关闭结束；scope context 已取消，cache closed 且 entries=0；scope generation 恰好增加 1；cleanup callback 恰好一次。此后分别对原 cached 域名和新 uncached 域名调用旧 scoped backend，要求返回 `ErrSessionBackendClosed`，无 conn、无新 lookup、无新目标或替换 scope。后续显式 Client.Close／Server.Close 不再次 invalidation、不回填、不重复 callback。

**撤销与父 Serve cancel 的客户端读超时不能当作客户端终态证明。** 这两个 UDP 场景尚没有可靠终态通知，原 Flow 的 post-write read 在固定 1 秒内无 echo只是辅助证据。远端目标和 DNS 已清理的结论来自独立 server scope 与 target socket 观察，不来自读超时。expiry 用例另有客户端固定 lifetime，明确拒绝 timeout，必须得到 `session.ErrClosed`。

定向命令：`go test -json ./gateway -run ^TestSessionDNSRuntime(Revocation|ImmutableExpiry|ParentCancellation) -count=1 -timeout=30s`。三个用例各运行一次、各有一个 terminal PASS；退出 0，wall 4.965 秒，package 3.156 秒，stderr 为空。

证据：[targeted-summary-attempt-01.json](C:/Users/developer/Desktop/bfp/.staging/r9-next9/verification/dns-termination/targeted-summary-attempt-01.json)、[run-metadata](C:/Users/developer/Desktop/bfp/.staging/r9-next9/verification/dns-termination/run-metadata-attempt-01.json)、[原始 JSONL](C:/Users/developer/Desktop/bfp/.staging/r9-next9/verification/dns-termination/targeted-go-test-attempt-01.jsonl)。测试源码 SHA256 为 `ae108c8af6788ff649859c6e0328b2078819efc486fb0f93b69b96cec50294b9`，原日志 SHA256 为 `2d4129ee3a1712e681b10915a7d6246a9e13e3f92add3bb572b42ae32a9c19ad`。

它补充 actual DNS runtime 的终态证据，不等于网络中的全部资源与适配器销毁验收。无外部 authoritative DNS TTL／OS 全局缓存清除保证，无 WAN／active carrier switch／有界 close control 故障矩阵结论。

## 6. 正式本地 gate 与构建绑定

源码停止写入后，root 单次执行正式 gate：`go test -json -p 1 ./... -count=1 -timeout=180s`，随后 vet 与 Windows/Linux 构建。16 个有测试 package、363 个顶层测试 PASS；全部命令退出 0，`source_unchanged=true`，总 wall 66.47 秒。保留 Windows symlink 权限 skip 1 个，`internal/backend` 无测试文件；不能将这些记成实际用例 PASS。

| 绑定项 | next9 值 |
|---|---|
| Go/module 文件数 | 111 |
| manifest SHA256 | `2bd5e6e7cc8e9f95ed794b9e6561052a0e409b52e98951ad6baa8cc791c1190a` |
| Windows binary SHA256 | `9db50cc9fb9ebaad308268b9c618f361dd1f3613c9852c9271e063c29a6f49ed` |
| Linux amd64 binary SHA256 | `2c496b389fc7155811dd038e74f70a423d90d0ca418b269667893e08359f0cde` |

记录：[source-manifest.json](C:/Users/developer/Desktop/bfp/.staging/r9-next9/verification/r9-next9/local-gate/source-manifest.json)、[local-summary.json](C:/Users/developer/Desktop/bfp/.staging/r9-next9/verification/r9-next9/local-gate/local-summary.json)、[完整 Go JSONL](C:/Users/developer/Desktop/bfp/.staging/r9-next9/verification/r9-next9/local-gate/go_test.log)、[vet](C:/Users/developer/Desktop/bfp/.staging/r9-next9/verification/r9-next9/local-gate/go_vet.log)、[Windows build](C:/Users/developer/Desktop/bfp/.staging/r9-next9/verification/r9-next9/local-gate/build_windows.log)、[Linux build](C:/Users/developer/Desktop/bfp/.staging/r9-next9/verification/r9-next9/local-gate/build_linux.log)。

原始 local summary 创建时 `pass=false`、`independent_linux_race=not_run`、WAN not_run；其中 `local_checks_pass=true` 表示本地检查通过，不能把其总 pass 字段解释为本地测试失败，也不应覆盖它来伪造后续竞态或实网结果。

## 7. 独立 Linux race 与 WAN

洛杉矶单次 run `63f9747669ffb30743736296cd72cf5c` 已结束，wall 182.76 秒，沿用原 360 秒运行 cap。隔离、离线容器内命令为 `go test -race -p 1 ./... -count=1 -timeout=180s`，测试程序 execution exit 0、16 packages PASS，原日志没有 DATA RACE 报告。111 个 remote source 与 next9 冻结 manifest 逐项相符；当前 frozen source、106 文件 parent frozen source 均未变，关联 Linux build hash match。

race 是重新编译冻结源码运行测试，关联 Linux CLI binary 的 SHA 是 metadata 绑定，不表示 race 执行了该 CLI binary。owned container 与 owned directory 均已删除。原始 `race-result.pass=false`、`snapshot_comparison.unchanged=false`、binding 的 `binding_and_cleanup_pass=false` 保持原样；这不表示 owned cleanup 失败，而是严格组合门禁包含环境快照一致性。

独立 [host-listener-drift-audit.json](C:/Users/developer/Desktop/bfp/.staging/r9-next9/verification/r9-next9/host-listener-drift-audit.json) 只从同 run 原始 before／after 快照审查变化，没有远端刷新或业务重跑。它证明：

- 原比较仅 listener 项变化；before 消失 16 行、after 新增 9 行，全部是 UDP。
- 原始含 owner 的行中，全部变化对应 `xray` PID `17883`；固定 TCP listeners 未变。
- containers、routes、firewall 和 nft 的原始比较未变；owned container／directory 清理成立。
- 测试 socket 位于隔离 container network namespace，容器网络为 none。

这些证据仅证明两个观察时刻的 socket owner 归属，不能证明同 PID 的启动时间、可执行文件或配置持续一致，也不能确定 UDP 集合变化的根因；原快照没有 service config hash。不能将审查结论升级成“整个系统 baseline unchanged”或覆盖严格环境 FAIL。该项与竞态测试程序 PASS 分开报告，没有为取得 overall PASS 重跑同一实验。

绑定及原始记录：[race-binding.json](C:/Users/developer/Desktop/bfp/.staging/r9-next9/verification/r9-next9/race-binding.json)、[race-result.json](C:/Users/developer/Desktop/bfp/.staging/r9-next9/lab/runs/63f9747669ffb30743736296cd72cf5c/race-result.json)、[race-log.json](C:/Users/developer/Desktop/bfp/.staging/r9-next9/lab/runs/63f9747669ffb30743736296cd72cf5c/race-log.json)、[evidence-index.json](C:/Users/developer/Desktop/bfp/.staging/r9-next9/verification/r9-next9/evidence-index.json)。审查记录绑定的原始 race result SHA256 为 `1254db96ffab8cb7c5fa0fe7c559ecdffdaacf672b5720eb2b2b5fdd9e0ce754`。

metadata finalizer 首次用 Windows 默认 GBK 读取 UTF-8 Go JSONL，产生 UnicodeDecodeError；[finalization-initial-error.txt](C:/Users/developer/Desktop/bfp/.staging/r9-next9/verification/r9-next9/finalization-initial-error.txt) 保留。修复为显式 UTF-8 读取并按内容相等复用已写不可变 binding，只补索引；源码、业务测试、race、raw summary 和原结果均未改或重测。

next9 WAN 未执行。本轮实际 DNS 测试是本地 loopback 业务；本轮没有给新加坡增加业务负载。后续实网实验继续新加坡发送、洛杉矶接收／出口，压缩且有截止的管理上传、同 run baseline 先落盘、业务串行，不反复重跑 unchanged 场景筛选通过，不扩大原业务期限。

## 8. 有界关闭仍待完整实现

[会话有界关闭实施方案](C:/Users/developer/Desktop/bfp/docs/会话有界关闭实施方案.md) 已根据 next9 当前 Session.Close、Client.Close、UDP ledger、控制调度与 Server ticket／router 路径写出可审阅方案。

当前 Session.Close 仍为一次 enqueue／flush 后立即 cancel；接收方同样尝试一次 ACK 后退出。next9 没有新增 canonical 校验、Close publication／ACK 关联、控制 reserve、通知或 ACK 重传、有限 drain actor、完整原子终态门禁和同 record Close 后业务拒绝。上述 DNS 三终态测试不应被记为这些功能通过。

下一轮需在独立源码边界完整接线，利用现有 19／20 全零帧而不静默改变 wire3 字段合同。方案中的 3 秒 CloseTimeout、固定 publication／字节预算是待实现默认建议，不能写成当前代码行为。两类失败须区分：Close 已到且 ACK 全丢，远端资源可能已经清理；所有 Close 完全黑洞，远端不知道意图，仍由原 15 秒检测和固定 30 秒 retain 收束。不能以本端关闭返回或无 echo 推断远端及时销毁。

其他原目标继续保留：默认／原 8 秒操作窗内稳定 UDP→TCP 恢复、分类 WAN 收敛与混合负载公平性、可靠性／纠错策略、TUN／fake-IP／客户端 DNS／IPv6 适配、完整资源销毁与安全审查。没有 release ZIP，整体 acceptance／production／released 仍为 false。
