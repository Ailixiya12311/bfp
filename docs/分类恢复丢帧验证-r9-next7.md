# 分类恢复与丢帧验证：r9-next7

记录日期：2026-10-09。r9-next7 在冻结 r9-next6 的基础上，仅新增 `session/class_recovery_fault_test.go`。本阶段补充真实 Client 的分类恢复与加密公告／ACK 丢失证据，没有修改生产协议、定时参数或原有集成测试。

五个新增顶层测试、七个叶场景均通过；完整本地门槛仍为 FAIL：324 个顶层测试 PASS，另一个顶层测试因其 `missing-offer` 子项在 Windows UDP socket 构造阶段失败而 FAIL。`go vet` 和两平台构建 PASS。后续独立 Linux race 16 包 PASS，清单绑定、owned cleanup 与接收机 baseline 比对均通过；整体协议目标仍在进行。

```text
local_checks_pass=false
acceptance_complete=false
production_ready=false
released=false
```

## 冻结源码与运行时边界

| 项目 | 证据 |
|---|---|
| Go/module 文件数 | 99；next6 为 98 |
| next7 canonical manifest SHA256 | `e8219a19721e5c0c1d1429a2472856c36a41c8950ca9f492b66feab1cfee1daf` |
| 唯一新增文件 | `session/class_recovery_fault_test.go` |
| 新增文件 SHA256 | `4c837899cd9c0b0f666dee0051f6d3ba934e1ae80dff5d53ef335f5b64990e2a` |
| next6 的 98 个文件 | manifest 逐项对比一致；无修改、无删除 |
| Linux amd64 构建 SHA256 | `2583677700803cbabbbdf986454844a38fcd1512ba1e9a15e780c14e4de5df86`；与 next6 相同 |
| Windows amd64 构建 SHA256 | `8f772287553dabe15cd9e7eca0c10c6330051ea0ba935f12962dfd4458349331`；与 next6 相同 |

冻结清单见 [source-manifest.json](C:/Users/developer/Desktop/bfp/.staging/r9-next7/verification/r9-next7/local-gate/source-manifest.json)，完整结果见 [local-summary.json](C:/Users/developer/Desktop/bfp/.staging/r9-next7/verification/r9-next7/local-gate/local-summary.json)。两平台可执行文件相同，说明本次测试补充没有改变构建出的运行时程序；不能据此宣称修复了 next6 的 WAN 失败或原 8 秒恢复失败。

生产默认 `UDPFailureBudget=15s` 保持原样。原 `TestRunningUDPBlackholeRecoversSameExitAndBytes` 的 8 秒操作期限也保持原样。新增主动黑洞夹具明确使用 `UDPFailureBudget=600ms`，用于有界触发实际 Client watchdog；普通公告／ACK 丢失夹具沿用生产默认 15 秒。两者需要分别解释，600 ms 夹具不能证明生产默认在 8 秒内完成恢复。

## 新增场景及其断言

所有场景使用 `NewClient.Connect`、真实端点握手及实际加密记录。双向指 client→server 和 server→client，两侧各自的本地 TX 分类独立变化。

| 新增顶层测试 | 叶场景数 | 证明的行为 |
|---|---:|---|
| `TestClassRecoveryRealClientInitialUDPFailureFallsBackToTCP` | 1 | 初始 UDP 黑洞使真实 Client 选择 TCP；分类初始 v1 与 Bulk v2 双向收敛；generation=1、switches=0，保留同一个 Client Session，后端仅拨号一次 |
| `TestClassRecoveryEncryptedAnnouncementThenACKLossWithObservedLossSignal` | 2：UDP／TCP | 双向先丢公告再丢精确 ACK；恢复传递后走实际 logical-ref retry 路径，ACK 才能完成待确认项；不制造 publication、ACK 或新的 retry lifetime |
| `TestClassRecoveryEncryptedAnnouncementThenACKLossNaturalBackoff` | 2：UDP／TCP | 同样的公告／ACK 丢失顺序，保持自然 retry 定时器；在单个固定 20 秒预算内完成双向精确 ACK 收敛 |
| `TestClassRecoveryRealClientUDPToTCPPendingVersionsSurviveFrozenSnapshotWithObservedLossSignal` | 1 | 实际 UDP watchdog→`Client.recover`→TCP；冻结 v2 快照后产生 v3，双方 ResumeDone 完成前禁止公告；使用显式丢失信号使最新 v3 再次具备发送资格 |
| `TestClassRecoveryRealClientUDPToTCPPendingVersionsSurviveFrozenSnapshotNaturalBackoff` | 1 | 同样的真实恢复与冻结快照情形，最新 v3 在自然定时重发后完成双向精确 ACK；使用固定 20 秒共享预算 |

公告丢失时，本地 v2 已发布但精确 ACK 仍为 v1，peer view 仍为 v1；公告放行、ACK 继续丢失时，只更新 peer view，不能清除 pending 或刷新原始 `Started`。每侧已接纳业务字节维持 4500，控制帧重发不计入业务分类字节，后端拨号数维持 1。

主动 UDP→TCP 场景先让双方 v2 公告处于待确认状态，再黑洞实际 UDP。夹具阻止双方真实 ResumeDone，核对线上 `ResumeState` 中的冻结 v2 与端点冻结快照一致，并核对快照及操作 receipt 已通过加密承载。此时 receipt 只完成同步操作，不能替代精确 Class ACK。

快照冻结后，普通本地空闲分类行为产生 Normal v3。分类行为时钟由测试夹具受控推进，分类控制重发仍使用实际定时器。断言检查 v3 在恢复门槛完成前尚未发布，冻结快照仍为 v2；原 classifier、Flow、目标连接、class origin、业务字节、`Started` 和 retry 生命周期均保留。双方 ResumeDone 完成后，最新 v3 公告与精确 ACK 收敛。随后沿原连接上传 37 字节、下载 29 字节，两侧累计 TX 分别为 4537／4529，后端仍只拨号一次、switches=1。

UDP relay 转发原始 datagram。TCP relay 仅终止并重新封装外层认证 Framer，端点的内层加密 record 原样转发。独立 shadow cipher 仅解读副本以选择确定的丢失事件；实际端点仍负责认证、重放检查、解码与安装。该测试依赖夹具持有测试端点密钥，不代表线上中间人可以选择性识别加密分类帧。

## 自然退避与显式丢失信号的期限

`NaturalBackoff` 在每个叶场景开始时创建单个固定 20 秒 deadline。场景内所有自然等待共享该期限；每个阶段不重新获取 20 秒，且该预算小于 class table 的 30 秒 no-progress 生命周期。真实 retry 的最大间隔为 8 秒，日志中保留了约 3.198 秒和约 7.99 秒的下一次发送等待，不能把自然收敛描述为 2 秒保证。

`WithObservedLossSignal` 保持既有 `runtimeWait` 的每次 2 秒有界观察。夹具在开启丢失门时，对 shadow 已观察到的丢失 publication 调用真实 `queueRetry(makeRef(...))`，仅改变发送资格，立即前后核对 table state 不变。它验证明确丢失信号驱动的重发路径，不能作为自然定时器在 2 秒内收敛的证据。

这些是分别命名的测试契约。最早 2 秒自然观察失败记录仍保留，后来创建的 20 秒自然场景没有改写该失败，也没有延长原生产或集成操作期限。

## 原始运行与完整本地门槛

| 记录 | 结果及保留边界 |
|---|---|
| [attempt-01.log](C:/Users/developer/Desktop/bfp/.staging/r9-next7/verification/class-recovery/attempt-01.log) | FAIL；公告损失的 UDP 叶场景与恢复后最新 ACK 收敛未在原 2 秒观察内完成；保留原断言和总结果 |
| [attempt-02-logical-loss.log](C:/Users/developer/Desktop/bfp/.staging/r9-next7/verification/class-recovery/attempt-02-logical-loss.log) | 前身显式丢失信号场景 PASS；测试名称尚未拆分，不能替代最终五个顶层测试的冻结证据 |
| [attempt-03-separated-contracts.log](C:/Users/developer/Desktop/bfp/.staging/r9-next7/verification/class-recovery/attempt-03-separated-contracts.log) | 整体 FAIL；UDP 夹具构造在 `127.0.0.1:50299` 遭遇 Windows WSAEACCES；自然场景通过，并记录了约 8 秒退避。随后仅在新增夹具中改为 UDP 先选端口、TCP 同端口预检，未修改原测试 |
| [attempt-04-bounded-publication-boundary.log](C:/Users/developer/Desktop/bfp/.staging/r9-next7/verification/class-recovery/attempt-04-bounded-publication-boundary.log) | 最终新增五个顶层、七个叶场景 PASS；session 子集总耗时 10.389 秒 |
| [完整 go_test.log](C:/Users/developer/Desktop/bfp/.staging/r9-next7/verification/r9-next7/local-gate/go_test.log) | 15 包 PASS，324 顶层 PASS；`TestCapabilityAuthenticatedMalformedOffersRejected/missing-offer` 与其顶层父测试 FAIL；Windows symlink 测试 1 个 SKIP |

完整门槛的原始错误为：

```text
capability_test.go:152: listen udp 127.0.0.1:55479: bind:
An attempt was made to access a socket in a way forbidden by its access permissions.
```

此错误发生在 socket 构造阶段，`missing-offer` 的认证拒绝断言尚未执行。当前证据支持“Windows 端口绑定导致本次完整运行失败”，不支持“missing-offer 协议拒绝存在漏洞”或“完整测试已通过”。记录未改成 SKIP，也未重跑原完整场景以筛选绿色结果。`go vet`、Windows/Linux build 均退出 0；冻结源码检查为 unchanged。

[只读端口诊断](C:/Users/developer/Desktop/bfp/verification/next7-port-diagnosis.json) 现场发现 `0.0.0.0:55479` 的 UDP endpoint 属于 PID 8832、`GameViewerServer.exe`，endpoint 报告创建时间 00:43:31，早于测试失败 00:44:25。当前 UDP excluded range 只有 50000–50059，与 55479 不匹配。结合 `NewServer` 先用 TCP `:0` 选临时端口、再绑定同号 UDP 的构造顺序，这些证据支持跨 TCP／UDP 的端口冲突解释；没有捕获失败时刻 socket exclusive 选项或执行 bind 实验，不能宣称 exclusive-bind 根因完全证实。18 个其他 malformed-offer 子项通过，不能代替未进入认证断言的 `missing-offer` 子项。

后继未冻结版本可仅修复测试 helper 的端口预选：UDP 先选端口并持有，再用同地址 TCP 预检；释放预检 socket 后仅尝试一次真实构造，任何失败仍显式报告。现有构造接口需要释放预检 socket，因此仍存在短暂 TOCTOU 窗口。此次没有停止无关游戏进程、改动 excluded range 或改写 next7 冻结源码。

## WAN、race 与剩余门槛

r9-next7 自身尚无 WAN 运行。独立 Linux race run `8143bae4f4ba07196d51f1e2652e6172` 使用 `go test -race -p 1 ./... -count=1 -timeout=180s`，16 包 PASS、退出 0；99 个 source manifest 项与冻结 next7 清单逐项匹配，绑定 Linux 二进制 SHA 与 next6 相同。运行结束后 owned container／目录清理通过，接收机 before／after snapshot 比较 unchanged；总运行耗时 177.16 秒。证据见 [race-result.json](C:/Users/developer/Desktop/bfp/.staging/r9-next7/lab/runs/8143bae4f4ba07196d51f1e2652e6172/race-result.json)、[race-log.json](C:/Users/developer/Desktop/bfp/.staging/r9-next7/lab/runs/8143bae4f4ba07196d51f1e2652e6172/race-log.json) 和 [独立绑定复核](C:/Users/developer/Desktop/bfp/.staging/r9-next7/verification/r9-next7/race-binding.json)。复核确认当前源码 unchanged、`binding_and_cleanup_pass=true`。本地冻结 summary 在创建时记录的 `not_run` 保留原样，最新 race 状态由独立记录与 evidence-index 给出；Linux PASS 不覆盖 Windows 完整 gate 的原失败。

分类 WAN 使用 next6 冻结二进制与原运行 `387c7e9fd1f9ff07c43cc1ead2ca355a`。两端上传完成后，正常 UDP 在原定 35 秒业务期限内仅完成 47／50 次，`failure=tcp_exchange`、`pass=false`。主采集进程因终态之后持续卡在证据收集而被核对 owner 后停止。独立恢复流程保留原正常场景失败，只执行此前尚未启动的两个场景：UDP→TCP 完成 50／50，但在原 35 秒期限未完成 idle restore，`failure=idle_restore`、`pass=false`；初始 UDP blocked 完成 50／50，原始 probe PASS。

运行已终态，两端 owned 进程／目录清理通过。独立审计的输入问题为 0，保留原结果不变；初始 UDP blocked 的初始／Bulk／restored／final 四检查点通过，另外两场景失败，整体 `pass=false`、`acceptance_complete=false`。主程序丢失的当次 before snapshot 没有持久化，因此 `missing_current_baseline=true`；owned cleanup 通过不能替代当次双端完整 baseline 比对。详见 [恢复结果](C:/Users/developer/Desktop/bfp/.staging/r9-next6/lab/runs/387c7e9fd1f9ff07c43cc1ead2ca355a/class-wan-result.json) 与 [独立审计](C:/Users/developer/Desktop/bfp/.staging/r9-next6/lab/runs/387c7e9fd1f9ff07c43cc1ead2ca355a/class-wan-independent-audit.json)。本地与 Linux race 通过结果不能掩盖 WAN 47／50 和 idle restore 的失败。

下一步需沿保留的固定期限失败诊断 WAN 业务传输与 idle restore，并处理后继测试夹具的 Windows 端口预选问题。用户已指出新加坡链路网速不快；后续远端业务场景串行执行，管理上传采用有界压缩传输，保留每次失败，不扩大原业务 deadline，也不重跑不变场景筛选绿色结果。选择性 Class ACK 丢失与 retry 耗尽、长期混合类别公平性、原 8 秒恢复契约、adapter／DNS／IPv6 与独立安全评审仍有门槛。

后续结果应追加独立运行记录，并更新 [evidence-index.json](C:/Users/developer/Desktop/bfp/.staging/r9-next7/verification/r9-next7/evidence-index.json) 的对应状态与本交接摘要；不要覆盖本次 `local-gate` 原始日志或把其 `local_checks_pass=false` 改成 true。没有 release ZIP，整个协议目标仍 active。
