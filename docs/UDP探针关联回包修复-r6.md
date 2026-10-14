# BFP UDP 探针关联回包修复 r6

日期：2026-10-07。状态：r6 源码审阅、本地验证、Linux 竞态和双机 WAN 已完成；**r6 WAN 严格 FAIL，未发布 ZIP**。本文记录关联修复的本地与实网证据，保留首次 1s 超时，不将 r5/r6 失败改写为通过，也不宣布协议整体验收完成。

## 1. 修复的具体问题

r5 `probe` 在同一 UDP 业务 flow 上依次发送 `message-0`、`message-1` 等消息，每次发送后只调用一次 Read，并把读到的整报与当前消息比较。如果第 N 次请求超时，而其回声随后进入接收队列，第 N+1 次可能读到第 N 次回声并立即报告 mismatch；之后多个请求会继续读到前一次的回声，形成连续即时失败。

旧实现冻结副本见 [r5 race/source/cmd/bfp/main.go](../lab/runs/f7f613dfa8fa034ba9d83609f5af1b61/source/cmd/bfp/main.go)。r5 WAN run `0387f1ac577e411ad6b1d3edbb4e643c` 的原始场结果必须保留：

| 场景 | TCP 成功 | UDP 成功/失败 | 原始结果 |
|---|---:|---|---|
| 正常 UDP | 50/50 | 50/50；失败 0 | PASS |
| 运行中 UDP 黑洞后 TCP | 50/50 | 24/50；失败 26 | FAIL |
| 启动前 UDP 黑洞、初始 TCP | 50/50 | 20/50；失败 30 | FAIL |

[udp_to_tcp.probe-log.json](../lab/runs/0387f1ac577e411ad6b1d3edbb4e643c/udp_to_tcp.probe-log.json) 的 iteration 24 在已经稳定的 TCP gen2 上达到 1s 截止，iteration 25–49 多次为 0ms 非 timeout 失败。源码和新本地回归能证明旧测量方式存在串位问题，但旧日志没有记录收到的回包编号/错误类别，不能逐份还原所有失败的内容，更不能解释首次延迟的具体网络或调度原因。

因此 r6 修复的是**当前请求与回包关联**。最初未在 1s 内成功的请求仍失败；不能把上述 26 或 30 个失败直接称为协议丢包数，也不能将它们全部推定为探针问题后删除。

## 2. 修改范围与新行为

r5/r6 的 Go/模块 source manifest 对比仅有一个既有文件改变：[cmd/bfp/main.go:339](../cmd/bfp/main.go)；新增 [cmd/bfp/probe_udp_test.go:86](../cmd/bfp/probe_udp_test.go)。握手、会话、carrier、记录、流、调度、分类和 Ticket 的 Go 源码摘要没有变化。此结论只对应两个 manifest 的代码范围，不包含文档或运行产物。

本文源码行号按 r6 冻结快照核对；后续工作区源码改变时，原实现可在 [r6 冻结 main.go](../lab/runs/769db964bf6f61137ad130fe4d9092ba/source/cmd/bfp/main.go) 与 [r6 冻结 probe_udp_test.go](../lab/runs/769db964bf6f61137ad130fe4d9092ba/source/cmd/bfp/probe_udp_test.go) 复核。

| 合同 | r6 实际行为与位置 |
|---|---|
| 每次至多发送一次 | `exchangeUDP` 至多调用一次 Write，检查错误和短写；发送前已到期可直接失败，不做业务重传。 |
| 一个绝对截止，不滚动续期 | 调用方在 [main.go:457](../cmd/bfp/main.go) 使用 `udpStarted + 1s`，若整次 probe 的 context 截止更早则缩短；helper 只设置一次 SetDeadline。读到无关回包后不会重新设定截止。 |
| 缓冲数据也服从截止 | [main.go:339](../cmd/bfp/main.go) 在发送前、每次 Read 前后检查当前时间。`session.Flow.Read` 可能先返回队列整报再检查 read deadline，因此 helper 的时间检查防止连续缓冲回包绕过期限。 |
| 精确当前消息才成功 | 使用完整 payload `bytes.Equal`；只看编号或收到任意回包均不足以成功。 |
| 无关回包丢弃后继续等待 | 迟到、重复、未来编号或非规范回包不完成当前请求；统计后丢弃，在同一绝对截止内继续 Read。 |
| 截止和失败不回填 | 当前请求失败立即增加 `udp_failed`；后续迟到回包只能丢弃，不能回填原 `udp_completed`。 |
| 总 PASS 标准保持严格 | [main.go:483](../cmd/bfp/main.go) 仍要求所有 UDP 请求完成且 `udp_failed=0`。TCP 完成不覆盖 UDP 失败，也不因后续请求成功而变更首次失败。 |

r6 的 1s 预算从 `udpStarted` 起算，包含调用前的 Session 状态读取；r5 在该读取后才设置 `now + 1s`。新起点不会放宽旧预算。总 probe 截止可以使某次预算更短，不能更长。

下表是本地回归控制的事件序列示例，不是尚未取得的 WAN 结果：

| 操作 | 收到的事件 | 结果 |
|---|---|---|
| message-0 | 原截止前无回声 | timeout，累计 failed=1 |
| message-1 | 先读到迟到 message-0，再在原截止前读到 message-1 | 丢弃旧回声；当前操作成功，failed 仍为 1 |
| message-2 | 读到重复 message-1、非规范短报，再读到 message-2 | 两个无关报丢弃；当前操作成功，failed 仍为 1 |
| 整场结束 | message-0 仍未在其原截止内成功 | 整场 FAIL |

也验证当前回声先到、旧回声后到的顺序：旧回声留到下一请求读取时仍不能完成下一请求。

## 3. 遥测的含义与安全边界

新增 UDP 遥测在 [main.go:470](../cmd/bfp/main.go)。输出固定错误分类和计数，不输出原始回包内容、网络错误字符串、凭证或密钥。

| 字段 | 含义 |
|---|---|
| `success` | 当前完整消息在本次绝对截止内匹配。 |
| `timeout` | 本次因期限错误失败；即使曾读到无关回包仍为 true。 |
| `error_kind` | `timeout`：无无关回包的期限失败；`mismatch`：读到无关回包后到期；`closed`：连接/会话关闭或 EOF；`io`：其他 I/O 错误/短写；成功时为空。 |
| `unmatched_count` | helper 已读到但未匹配当前消息的整报数量。 |
| `late_count` | 可解析且编号小于当前编号的无关回包数量；这是探针观察分类。 |
| `unexpected_count` | 其他无关回包数量，包括未来编号或非规范 payload。 |
| `expected_iteration` | 当前请求的规范编号；无法解析时 null。 |
| `received_iteration` | 最近一份被检查回包的规范编号；无法解析时 null；成功时与当前请求相符。 |
| `last_unmatched_iteration` | 最后一份无关回包的规范编号；该份无法解析时 null。 |
| `elapsed_ms`、carrier/generation 前后 | 整次 UDP 操作边界观察，包含前后状态读取等开销；不是纯 RTT、包 ACK、切换暂停或目标消费时间。 |

[main.go:297](../cmd/bfp/main.go) 的 `probeMessageIteration` 仅接受 `message-0` 至 `message-9999` 的规范 ASCII 形式：最多四位数字，不接受负数、多余前导零、尾部内容、NUL 或超长数字。任意回包文本不会进入日志，也不会通过宽松整数解析变成任意元数据。只有完整内容相等才决定成功；编号仅用于有限诊断。

`late_count` 与 `unmatched_count` 是业务整报读取观察，不能换算成线上记录的丢失/重传/乱序比例。探针编号不是设备授权或协议 ACK，r6 没有改变目标权限、AEAD、防重放或 UDP 交付语义。helper 使用固定 16KiB 读缓冲，不累计保存无关 payload；它仍不能为任意忽略 deadline 的自定义 net.Conn 提供硬中断，也不构成 CPU 抗洪泛证明。

截止检查保持原绝对期限；实际函数返回时间仍受线程调度影响，不能从本地测试宣称所有主机上严格在第 1000ms 返回。

## 4. 独立本地回归与验证结果

本轮 [verification/v0.1-r6/validation.json](../verification/v0.1-r6/validation.json) 关联 55 个 Go/模块文件，构建前后摘要相同，`source_unchanged=true`。本地批次总耗时 30.563s。

| 新回归 | 已验证的路径 | r6 记录 |
|---|---|---|
| [TestExchangeUDPDelayedFirstReplyCannotPoisonFollowingOperations:86](../cmd/bfp/probe_udp_test.go) | 真正 loopback UDP socket；第一次 80ms 超时后发送迟到回声；两种回包先后顺序；重复/短报不完成下一请求；每次一次发送/一次设置截止；第一次失败不变 | 两个子场与顶层 PASS。后续操作使用 500ms 测试截止，不把它当成 WAN 1s 实测。 |
| [TestExchangeUDPUnmatchedRepliesDoNotExtendDeadline:171](../cmd/bfp/probe_udp_test.go) | 连续未来编号回包，固定 100ms 绝对截止；记录 mismatch 且 timeout=true，单次写入/单次 deadline | PASS；测试容许调度抖动，检查运行耗时 80–350ms，不能称为精确 100ms 返回。 |
| [TestExchangeUDPShortWriteClosedAndBufferedDeadline:245](../cmd/bfp/probe_udp_test.go) | 短写、写关闭、读 EOF、一般读错；stub 连续立即返回旧整报仍会到期 | 五个子场与顶层 PASS。stub 的 deadline 设置失败/任意不合作阻塞连接未在本测试中构造。 |
| [TestProbeMessageIterationRejectsUnboundedOrPrivatePayloads:270](../cmd/bfp/probe_udp_test.go) | 规范边界；超长/负数/前导零/尾部私密文本/NUL 拒绝为元数据 | PASS；不记录原始回包文本。 |

以上四个新增顶层、七个子测试通过事件可在 [unit.log](../verification/v0.1-r6/unit.log) 中核对。真 UDP fixture 证明的是 helper 读取/相关性行为，不经过 BFP carrier，不能代替 r6 协议端到端或 WAN 验收。

| 检查 | 本轮结果 | 证据 |
|---|---|---|
| 全包测试 | 11 包 PASS；144 个顶层、258 个含子测试 pass 事件 | [unit.log](../verification/v0.1-r6/unit.log)，`go test -json ./... -count=1 -timeout=45s`；Windows `TestSymlinkFileAndAncestorRejected` 权限 skip 保留。 |
| 凭证/确认专项重复 5 轮 | 90 个顶层、140 个含子测试 pass 事件 | [ticket_repeat.log](../verification/v0.1-r6/ticket_repeat.log)；选择表达式与 r5 同样限定到 `TicketAdversarial\|RuntimeTicket\|UDPHandshakeConfirmation`，不是新增 probe 四项的重复测试。 |
| vet / modules | 两项退出码 0 | [vet.log](../verification/v0.1-r6/vet.log)、[modules.log](../verification/v0.1-r6/modules.log)。 |
| lab 工具测试 | 8 项 PASS | [lab.log](../verification/v0.1-r6/lab.log)。 |
| Windows/Linux 构建 | 两项退出码 0 | [build_windows.log](../verification/v0.1-r6/build_windows.log)、[build_linux.log](../verification/v0.1-r6/build_linux.log)。 |
| r6 Linux race | 本轮冻结 55 个文件，11 包 PASS、exit 0，无 race 报告 | run `769db964bf6f61137ad130fe4d9092ba`；[race-log.json](../lab/runs/769db964bf6f61137ad130fe4d9092ba/race-log.json) 与 [source-manifest.json](../lab/runs/769db964bf6f61137ad130fe4d9092ba/source-manifest.json)。与本地冻结摘要逐项一致，不沿用 r5。 |
| race 宿主/清理 | 原严格 `pass=false` 保留；补充服务/配置稳定核验通过；owned 清理完成 | [race-result.json](../lab/runs/769db964bf6f61137ad130fe4d9092ba/race-result.json)、[supplemental-baseline-review.json](../lab/runs/769db964bf6f61137ad130fe4d9092ba/supplemental-baseline-review.json)。变化均为已有 Xray PID 17883 动态公有 UDP 高端口，固定 TCP/UDP、容器、路由、防火墙稳定；补充 `code_checks_pass=true`、`exact_owned_cleanup_complete=true`，不改原总体 false。 |
| r6 双机 WAN | 严格 FAIL；正常与初始 TCP 场 TCP/UDP 各 50/50，运行中切换 TCP 50/50、UDP 49/50、failed=1 | run `97e1e70f41907588de12dcfdc038cf9f`，[wan-result.json](../lab/runs/97e1e70f41907588de12dcfdc038cf9f/wan-result.json) 与 [release-evidence.json](../verification/v0.1-r6/release-evidence.json)，状态 `WAN_STRICT_FAIL_NO_ZIP`。 |

| 产物 | 大小 | SHA256 |
|---|---:|---|
| [bfp-v0.1-r6.exe](../bin/bfp-v0.1-r6.exe) | 6,721,536 B | `cfeb8adb95c9c9657be8af46824c5a91c35665b65ed0f8b16a97e93a099c6ae1` |
| [bfp-v0.1-r6-linux-amd64](../bin/bfp-v0.1-r6-linux-amd64) | 6,499,621 B | `02221e867147da7c7f949c84752834452a316da68942f469ce9873349c7e4f8a` |

### 4.1 实网迟到回包关联证据

r6 WAN 使用本稿新 ELF，沿用每次 1s UDP 截止及严格零失败标准。三场业务时间为正常 50.690s、切换 39.318s、初始 TCP 36.088s；客户端安装刷新分别 12/8/9 次，均跨原 12s Ticket TTL、同 Session/地址且各保持唯一原目标 TCP 连接。

[probe-correlation-analysis.json](../lab/runs/97e1e70f41907588de12dcfdc038cf9f/probe-correlation-analysis.json) 与 [udp_to_tcp.probe-log.json](../lab/runs/97e1e70f41907588de12dcfdc038cf9f/udp_to_tcp.probe-log.json) 显示：

| 操作 | 原始遥测 | 保留的结论 |
|---|---|---|
| iteration 46 | 前后均 TCP gen2，elapsed=1000ms、error_kind=timeout、success=false、unmatched=0 | 该请求超过原截止，仍计 failed=1；原因未确定。 |
| iteration 47 | 同一 TCP gen2，elapsed=170ms；last_unmatched_iteration=46、late=1、unmatched=1；received_iteration=47、success=true | 先丢弃迟到 message-46，再匹配当前 message-47，未被旧回包持续串位；不能回填 46。 |
| 切换整场 | TCP 50/50、UDP 49/50、udp_failed=1、pass=false | 关联恢复的实网证据成立，整场严格 FAIL 继续保留。 |

三场原值和探测/清理详见[r6 验收记录](验收记录-v0.1-r6.md)。[同 run 宿主补充核验](../lab/runs/97e1e70f41907588de12dcfdc038cf9f/supplemental-baseline-review.json) 确认固定服务/配置稳定，但 `code_checks_pass=false`，不能覆盖本次业务失败。

## 5. 可作出的结论与下一项验收

源码审阅与本轮本地回归支持以下结论：r6 消除了 helper 因只读一份回包而让迟到前一回复持续错配后续请求的测量机制；采用完整消息关联和不续期的绝对截止；首次超时、无关回包后仍超时及整场严格失败都会保留；新增遥测不包含原始回包文本或秘密。

实网 iteration 47 跳过迟到 46 并成功，进一步支持关联修复的效果；iteration 46 的首次 1s 超时仍保留。这不解释首次延迟原因，也不证明网络、目标、调度或所有 BFP UDP 场景已没有迟延/丢失。r6 WAN 为严格 FAIL，候选留档、无 ZIP。

后续应定位稳定 TCP 承载上的首次 1s 超时，区分入队、实际发送、远端收到、目标写读和本端交付等证据；新修订继续沿用原截止、严格每场标准和跨 TTL 刷新门禁独立复验。逐次 timeout/error_kind、carrier/generation、原目标 accept、探测/清理及宿主核验继续记录，不延长截止或重发掩盖首次失败。

下一修订可增加发送尝试、完整 Write 返回、deadline 设置/写前/写入/读前/读阶段及状态读取耗时，帮助区分观测开销、发送前预算耗尽、写阶段等待和回包等待。完整 Write 返回只是 net.Conn API 接受结果，不是 Session 入队、wire 交付或目标执行证明；读阶段耗时包含检查和关联处理，不是纯 RTT。各阶段毫秒值独立取整，也不要求精确相加等于总耗时。此处是后续诊断合同，不引用未取得的新修订验证结果；r6 首次超时与严格 FAIL 保持原值。

完整 R1–R9 的剩余工作仍见[r5 阶段需求清单](需求验收清单-v0.1-r5.md)；其 r5 验证事实不随此次 probe 修复而回填。分类器接线、ACK ranges/PTO/可靠控制合同、系统预算、profile 协商、真实接入/长期稳定性、向量与独立审查也不会因测量工具修复自动完成。
