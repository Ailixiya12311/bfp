# 会话 DNS 与传输诊断实现：r9-next8

记录日期：2026-10-09。本阶段从冻结 r9-next7 复制源码后，接入按 Session 隔离的出口目标域名缓存，补充 UDP 发送预算与 CLI 操作阶段诊断，并修复测试夹具的 TCP／UDP 端口预选。这里存在生产代码变更，尚不能沿用 next7 的二进制或验收结果。

106 个 Go/module 文件已冻结，完整本地 gate、vet 和两平台构建通过；独立 Linux race 因分类测试 TCP 端口 setup 失败，next8 WAN 未运行。next6／next7 冻结源码与失败证据保持原样，整个协议目标仍 active。

```text
source_freeze=frozen
full_local_gate=pass
builds=pass
independent_linux_race=fail
next8_wan=not_run
acceptance_complete=false
production_ready=false
released=false
```

## 实现范围

| 项目 | 本次实现与边界 |
|---|---|
| 出口目标 DNS | 同一 Session 的出口 Dialer 复用私有目标解析缓存；不同 Session 分别持有缓存；保留同 Session 的 resume／carrier replacement 复用原 scope |
| Session 终态 | ctx、不可续期的 Session lifetime 与原子 revoked guard 参与缓存命中、解析完成和实际拨号的检查；终态清空本协议持有的 scope |
| UDP 诊断 | 完整提交 record 的字节／次数、反馈与非反馈拆分、cwnd／pacer 拒绝、重叠阻塞 episode、当前路径和既有 RTT estimator 的只读快照 |
| CLI 诊断 | 每次 TCP echo 操作的接纳／读取字节、失败阶段、固定期限与耗时；区分业务、idle restore、evidence settle；成功最终 Stats 在关闭 Flow 前采样 |
| 测试端口 | `newSecurityTestServer` 先持有 UDP 临时端口，再验证同端口 TCP；单次真实构造，释放预留到构造之间仍有 TOCTOU 窗口 |
| 尚未完成 | 客户端 DNS query 的完整代理、DoH、fake-IP、TUN 接线、IPv6 验收矩阵以及整个短时网络资源销毁验收 |

这次的 DNS scope 是出口连接目标域名的解析缓存。它不等于客户端 DNS 适配器已经完成。`net.DefaultResolver`、操作系统或外部 DNS 服务可能另有全局缓存，本协议不能承诺清空这些缓存。

## Backend 合约与 Session 接线

[internal/backend/backend.go](C:/Users/developer/Desktop/bfp/.staging/r9-next8/internal/backend/backend.go) 提供不依赖 Session 实现的 `Dialer` 与可选 `SessionFactory` 合约：

```go
type Dialer interface {
    DialContext(context.Context, string, string) (net.Conn, error)
}
type SessionFactory interface {
    ForSession(context.Context, func() error) (Dialer, func())
}
```

`session.Backend` 与 `session.SessionBackendFactory` 是这两个接口的公开 alias，既有仅实现 `DialContext` 的自定义 Backend 保持兼容；它们不会被强制转换为 gateway 缓存实现。自定义 factory 的创建和 cleanup 合约要求短、幂等、无网络等待；gateway 的 `ForSession` 只创建空 scope，不发 DNS、不创建出口 socket。

实际接线位于 [backend_scope.go](C:/Users/developer/Desktop/bfp/.staging/r9-next8/session/backend_scope.go)、[newSession](C:/Users/developer/Desktop/bfp/.staging/r9-next8/session/session.go) 和 [Server.confirm](C:/Users/developer/Desktop/bfp/.staging/r9-next8/session/server.go)。INIT 或未通过认证／授权的 confirmation 不创建 scope。新的 fresh confirmation 在创建真正的新 Session 时才调用 factory；重复 confirmation、同 initial attempt 的另一 fresh Noise candidate、已有 Session 的 TCP resume 都继续复用原 scope。

guard 在构造时复制不可续期的 lifetime，并保存原 atomic revocation authority，解析 goroutine 不读取可变 actor 字段。检查包括 Session context、revoked bit 与原 lifetime 是否到期。actor 内字段后来变化不能延长这个 guard 的原截止时间。父 context watcher、Session 显式 cancel 与 actor terminal shutdown 共用 once cleanup；显式终态同步调用 cleanup，actor 退出在关闭 `done` 前完成同一个清理。

真实业务联动首次揭示 `Client.Close` 的关闭通知顺序问题：原先先取消 Client context，直接取消派生 Session，随后 `Session.Close` 才尝试发送关闭帧，服务端 UDP scope 在固定 1 秒内仍未被关闭。next8 将建连／恢复操作 context 与 Session 生命周期 context 分开；Close 先取消操作，再让当前 Session 尝试发送已认证的关闭通知并终止，最后取消 Session 父 context。成功建连和恢复返回后还检查关闭状态，拒绝关闭期间迟到成功的 carrier。这没有新增关闭 ACK 等待／重传，也未改变既有 cwnd／pacer；通知丢失、预算阻塞或暂停路径的远端回收仍受原终态／保留期限约束，不能以本地无故障通过宣称完整关闭故障矩阵完成。

`internal/backend.IsNil` 同时拒绝普通 nil 和包装在接口中的 typed nil。Server 构造入口在 listen 前拒绝 typed nil Backend；factory 返回 typed nil scope 时取消新 Session、清理一次、拒绝 usable confirmation，不退回未分域的 base Backend。已经分配的 canceled Session 可暂存于 server registry 等待正常维护，不能成为可用的 cached INIT／confirmation。

## DNS 缓存、策略与预算

实现见 [gateway/session_dns.go](C:/Users/developer/Desktop/bfp/.staging/r9-next8/gateway/session_dns.go) 与 [gateway/dialer.go](C:/Users/developer/Desktop/bfp/.staging/r9-next8/gateway/dialer.go)。

| 限额或规则 | 当前值与行为 |
|---|---|
| 每 Session 缓存 entry | 最多 64 个；清除过期项后，容量满时淘汰最早 expiry，字典序处理并列 |
| 每解析结果地址 | 最多 16 个；超限拒绝，不截断成可能改变策略的部分答案 |
| host 长度 | 最多 253 字节 |
| 本地 max-age | 固定 30 秒；命中不续期；它不是 authoritative DNS TTL，`LookupIPAddr` 不提供该 TTL |
| DNS 执行并发 | 同一个 gateway factory 在所有 Session scope 之间共享最多 32 个执行 slot |
| 出口操作并发 | 同 factory 共享原 `MaxConcurrent` slots，默认 32；不按 Session clone 新建预算 |
| 错误缓存 | 不缓存 resolver 错误、空答案、超限、无效地址或策略拒绝；无负缓存 |
| 并发同域名请求 | 不做 coalesce／singleflight；各次 miss 仍使用共享执行预算 |

缓存仅保存已验证的 numeric 地址，并在插入及读取时复制地址 slice，外部 resolver 内存或调用者的修改不能更改缓存。一次解析中的所有地址先通过现有目标 ACL；混合 public／private 或其他不允许地址时整组拒绝，不能通过只挑其中允许的地址绕过策略。缓存命中也重新验证策略。最终拨号使用固定 numeric 地址，避免第二次 hostname resolution；IP literal 不需要 DNS 缓存。

每次 lookup 前后、cache hit 与 put、以及 socket dial 前后都执行 context／scope guard。scope 被关闭、撤销或到期后清空缓存、改变 generation，迟到的 resolver 不能凭旧 token 回填，也不能产生新的可用 socket。若已经开始的实际 dial 在终态后返回 conn，会关闭该迟到 conn。单个 Flow 的 caller context 取消不销毁仍然有效的 Session 缓存。

共享 slot 在真实 resolver 执行返回前持续持有。即使测试 resolver 忽略取消，也不会通过提前释放 permit 放大真实并发。`ForSession` clone 共享 immutable policy 与执行 slots，但单独持有 cache／ctx／generation；因此创建更多 Session 不增加同 factory 的 DNS 或出口执行并发预算。独立创建多个 gateway factory 不属于同一个预算，不能把该限制解释成任意 factory 之间的进程总限额。

新增 DNS 内部实现不把 query names、answers 或 secret 放入诊断字段；scope close 清除的是此实现持有的 entries。系统 resolver 或上游服务缓存不在这个所有权范围。

## UDP 标量诊断的含义

实现见 [Stats 定义](C:/Users/developer/Desktop/bfp/.staging/r9-next8/session/config.go)、[UDP 发送与观察](C:/Users/developer/Desktop/bfp/.staging/r9-next8/session/udp_transport.go)、[RTT 快照](C:/Users/developer/Desktop/bfp/.staging/r9-next8/internal/udptransport/rtt.go)。新增字段为固定数量的 scalar，没有为每次发送追加历史数组，也没有改动线上 frame。

| 字段组 | 可解释的事实与限制 |
|---|---|
| `udp_committed_*`／`udp_max_committed_record_bytes` | Session 累计的成功完整 record 次数、字节与最大 record。只有完整认证 write、publication 与 ledger commit 均成功才计数；短写／失败不计入 |
| `udp_feedback_*`／`udp_non_feedback_*` | feedback 指走独立 reserve 的 PacketAck；其他 record 包括业务、控制与 probe 均属 non-feedback。wire bytes 包含内层 record header、AEAD 和 padding，排除 IP／UDP header |
| `udp_*_admission_denied` | 真实编码普通 record 的 cwnd／pacer 准入拒绝观察；不是 packet loss 数，同次观察可能同时记两项 |
| `udp_flush_*_gate_denied` | 原 1200-byte／full-cwnd 预选 gate 在已知 scheduler 或 logical-retry 工作存在时的拒绝；与 exact admission 分开，class-only 控制在 exact admission 计量 |
| `udp_budget_blocked_*` | 第一项普通预算拒绝到成功 non-feedback、观察到工作为空、suspend、close 或 rebind 之间的合并 episode；cwnd 与 pacer 重叠、原因变化不重复累加时间 |
| `udp_path_*`／cwnd／flight／tokens | 当前 UDP path 与 generation 的 gauge；suspend 后可保留 path，attach reset 当前路径数据，Session 累计计数仍保留 |
| `udp_rtt_*` | 复制已有 estimator，单位微秒；raw Latest／Min 与 Smoothed 区分。samples=0 时 Smoothed／Variance 是默认估计，不能宣称实测 RTT |

所有累计计数和时长采用 saturating 运算。Stats 由 Session owner 生成同一观察下的副本；读取活跃阻塞 episode 时包含尚未结束的时长，但不关闭 episode、扣 token、发送 probe 或改变 transport policy。该阻塞时间是观察窗口，不是逐包等待或端到端业务耗时。

本次只增加观察点与只读 RTT snapshot；wireVersion 3、padding、admission、cwnd／pacer、feedback reserve、watchdog 和 retry 策略保持原有行为。原生产默认 UDP watchdog 15 秒、既有 8 秒业务操作与 WAN 35 秒绝对 probe 期限均未扩大。

## CLI 阶段、操作期限与最终采样

[class_probe.go](C:/Users/developer/Desktop/bfp/.staging/r9-next8/cmd/bfp/class_probe.go) 新增每次操作的 `start_ms`、`end_ms`、`remaining_start_ms`、`deadline_budget_ms`、`write_ms`、`read_ms`、`total_ms`、`accepted_bytes`、`echo_bytes`、`failure_stage` 和 `error_kind`。每次 socket 期限仍为 `min(操作开始+8s, 原 probe 绝对期限)`，没有按阶段续期。

`accepted_bytes` 表示 Flow 的 `Write` 接纳了多少字节，不能当作已送到 peer 或已发出 socket 的字节；partial write／partial echo 与失败阶段原样记录。读和写并发，其耗时可能重叠，不应相加作为 RTT。阶段记录标明 connect、dial、initial classification、business、idle restore、evidence settle 与 gates，并记录 idle 开始时原剩余时间。操作记录有界，使用既有 probe count 上限。

成功完成时，最终分类与 `Stats` 在 `conn.Close` 前捕获，`final_stats_phase=before_flow_close`，deferred cleanup 不覆盖这个有效 live Flow 样本。未走到成功采样的失败保留 `deferred_cleanup` 标记，该样本可能已经经过 Flow 清理，不能冒充关闭前 nonterminal proof。这项变更修正诊断采样语义，本身不证明 next6 WAN 的传输或 idle restore 根因已经解决。

## 定向验证与原记录

| 范围 | 已记录结果 | 证据边界 |
|---|---|---|
| 测试端口／capability／server security／ticket | 单次定向 PASS；33 顶层、64 子项；4.214 秒 | 完整 JSONL 保留；不把 next7 原 socket 失败改成 PASS；预留释放到构造的窗口仍存在 |
| gateway Session DNS module | `go test ./gateway ./internal/backend -count=1 -timeout=60s` 退出 0；gateway PASS 0.647 秒，internal/backend 无 test files | 保存的是 package-level tool capture，未保存逐测试 verbose 流；不编造逐测试运行记录 |
| Session Backend scope | `^TestBackendScope` 单次 PASS；7 顶层、3 子项；3.197 秒 | fresh Noise confirmation 与实际 TCP resume 接线；受控 actor 延迟／immutable deadline／atomic revoked；使用 guarded fake Dialer，没有外部 DNS／WAN 业务 |
| Session DNS 真实业务联动 | 原 `^TestSessionDNSRuntime` 首次 FAIL，修改 Client 关闭接线后第二次单次 PASS；1 顶层 | 真实 NewServer.Serve／NewClient、UDP 加密流和数值 TCP echo；2 fresh scopes、2 DNS lookups、3 目标 socket，两终态缓存清空。仅 DNS 答案为受控 loopback；原 5 秒业务与 1 秒清理观察保持 |
| UDP diagnostics | `^TestTransportDiagnostics` PASS；7 顶层、11 叶场景；0.863 秒 | 完整文本日志；包括完整／失败／短写、合并 episode、attach／suspend／close、并发 Stats 副本、saturation |
| CLI ClassProbe | 8 顶层 PASS，其中两个新增 exchange 诊断测试；退出 0 | 原工具输出部分截断，最终 exit 0 单独 poll 确认；待冻结 full gate 保存完整 JSONL |

证据目录与源码：

- [fixture-port/targeted-summary.json](C:/Users/developer/Desktop/bfp/.staging/r9-next8/verification/fixture-port/targeted-summary.json) 与 [targeted-go-test.jsonl](C:/Users/developer/Desktop/bfp/.staging/r9-next8/verification/fixture-port/targeted-go-test.jsonl)。
- [session-dns/gateway-summary.json](C:/Users/developer/Desktop/bfp/.staging/r9-next8/verification/session-dns/gateway-summary.json) 与 [gateway-go-test-tool-capture.txt](C:/Users/developer/Desktop/bfp/.staging/r9-next8/verification/session-dns/gateway-go-test-tool-capture.txt)；测试源码 [session_dns_test.go](C:/Users/developer/Desktop/bfp/.staging/r9-next8/gateway/session_dns_test.go)。
- [backend-scope/scoped-tests/targeted-summary-attempt-01.json](C:/Users/developer/Desktop/bfp/.staging/r9-next8/verification/backend-scope/scoped-tests/targeted-summary-attempt-01.json) 与 [targeted-go-test-attempt-01.jsonl](C:/Users/developer/Desktop/bfp/.staging/r9-next8/verification/backend-scope/scoped-tests/targeted-go-test-attempt-01.jsonl)。
- 真实业务联动 [首次失败摘要](C:/Users/developer/Desktop/bfp/.staging/r9-next8/verification/backend-scope/runtime-dns/targeted-summary-attempt-01.json)、[首次原日志](C:/Users/developer/Desktop/bfp/.staging/r9-next8/verification/backend-scope/runtime-dns/targeted-go-test-attempt-01.jsonl)、[关闭接线变更后摘要](C:/Users/developer/Desktop/bfp/.staging/r9-next8/verification/backend-scope/runtime-dns/targeted-summary-attempt-02.json)、[变更后原日志](C:/Users/developer/Desktop/bfp/.staging/r9-next8/verification/backend-scope/runtime-dns/targeted-go-test-attempt-02.jsonl)。
- [transport-diagnostics/attempt-01.log](C:/Users/developer/Desktop/bfp/.staging/r9-next8/verification/transport-diagnostics/attempt-01.log)；测试源码 [transport_diagnostics_test.go](C:/Users/developer/Desktop/bfp/.staging/r9-next8/session/transport_diagnostics_test.go)。
- [cli-diagnostics/targeted-summary.json](C:/Users/developer/Desktop/bfp/.staging/r9-next8/verification/cli-diagnostics/targeted-summary.json)；测试源码 [class_probe_test.go](C:/Users/developer/Desktop/bfp/.staging/r9-next8/cmd/bfp/class_probe_test.go)。

集成中出现过 `session/config.go` unused `context` import 的编译失败，已在冻结前删除该 unused import；[integration-compile-initial-failure.log](C:/Users/developer/Desktop/bfp/.staging/r9-next8/verification/backend-scope/integration-compile-initial-failure.log) 保留。没有扩大 deadline 或重跑不变失败直到通过。定向运行期间其他源码 agent 仍有工作，现有 targeted summary 不能替代停写后冻结的 full gate。

## 整体门槛与后续证据

源代码 agent 全部停写后，root 单次执行正式完整本地验证：16 个有测试的 package、351 个顶层 PASS，vet 和 Windows/Linux 构建均通过；Windows symlink 测试因权限限制保留 1 个 skip，新增 internal/backend 包无测试文件。正式 [local-summary.json](C:/Users/developer/Desktop/bfp/.staging/r9-next8/verification/r9-next8/local-gate/local-summary.json) 的 `local_checks_pass=true`、`source_unchanged=true`，但整体 `pass=false` 保留，因为全协议验收未完成。完整运行耗时 66.101 秒，原活动 UDP 黑洞测试此次 3.38 秒通过；这一次通过不能证明原 8 秒恢复契约已稳定修复。

冻结清单为 106 文件，SHA256 `37d58148659691a82618222dbcd1da88bf525714fdf12471d14b71b9360c5fd0`。Windows 二进制 SHA256 `f70cc05090df99117339d1777432edac5c6093d49ba8d7c5188a95b1def2c3f9`，Linux amd64 SHA256 `94ac0f1730218e62bfea189147629661540c665dda28f36b86ce9e3fa9ab6ecc`。next8 WAN 未运行。当前和历史原始 summary 均不被后续结果改写，追加绑定与 [evidence-index.json](C:/Users/developer/Desktop/bfp/.staging/r9-next8/verification/r9-next8/evidence-index.json) 汇总实际边界。

独立 Linux race 单次 run `c0d872535db2d5bc4515e8720cfc4410` 在洛杉矶执行，15 个 package 通过，Session package 因 `TestClassAnnouncementRuntimeFINTerminalDoesNotAllocate/tcp` 创建夹具时报 `listen tcp 127.0.0.1:42884: bind: address already in use` 而失败。该 TCP 子场景尚未执行 FIN/class 业务断言；非 verbose 原日志不能区分 common helper 的 TCP 预检失败还是释放预留后 NewServer 构造失败，不能凭这条错误确认 socket owner 或 TIME_WAIT 根因。日志没有 DATA RACE 报告，但整个 race gate 为 FAIL，不能写成竞态验收通过。源码 106 文件逐项绑定一致、冻结 parent 未变、关联 Linux build hash 一致；owned container 和目录已删除，洛杉矶 before/after snapshot 一致，总计 178.349 秒。见 [race 原结果](C:/Users/developer/Desktop/bfp/.staging/r9-next8/lab/runs/c0d872535db2d5bc4515e8720cfc4410/race-result.json)、[原日志](C:/Users/developer/Desktop/bfp/.staging/r9-next8/lab/runs/c0d872535db2d5bc4515e8720cfc4410/race-log.json) 和 [独立绑定](C:/Users/developer/Desktop/bfp/.staging/r9-next8/verification/r9-next8/race-binding.json)。未重复同源码 race 筛选通过，后续须在新的明确源码边界解决夹具分配问题。

next6 WAN 已保留正常 UDP 47／50、原 35 秒期限内 UDP→TCP idle restore 失败，以及初始 UDP blocked 的通过样本；本次新增诊断提供更准确的后续测量，不宣称那些原失败已经修复。用户指出新加坡链路较慢，后续业务串行、管理传输有界压缩，沿原 deadline 保留失败，不用改变期限或反复重跑筛选通过。

完整短时网络销毁、真实 DNS 迟到／revocation／expiry WAN、客户端 DNS／DoH／fake-IP／TUN、IPv6 矩阵、混合类别性能、retry 耗尽、原 8 秒恢复契约和独立安全评审仍待完成。无 release ZIP，`acceptance_complete=false`、`production_ready=false`、`released=false`。
