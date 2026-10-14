# UDP 确认与可靠控制实现方案

日期：2026-10-08，随 `r9-next4` 更新说明。本文最初是基于 r7 的实现合同；表内行号仍是审查时定位，不代表后续分类修订的当前行号。ACK ranges、RTT/PTO、latest-control receipt 和统一 operation table 已在 r9/r9-next3 候选中接线；r9-next4 又加入承载代次 operation 淘汰、TCP operation deadline 调度、有证明条件的旧 epoch drain，以及 Session-level ResumeDone v1 对齐、重复请求重新回执和单调 barrier supersede。当前 ResumeDone 定向测试、vet、双平台构建、独立 Linux race 和基础双机 WAN 通过；最新完整本地测试仍有活动 UDP blackhole 切换时序失败，最新 Ticket WAN 因 UDP→TCP 的 UDP 19/20 严格失败。所有原始失败保留。`production_ready=false`、`released=false`；完整 fault matrix、资源预算和跨实现验证仍未完成。

本文落实[协议技术设计 v0.1](协议技术设计-v0.1.md)第 7.2、8.2、8.3、9.1 节的 mandatory 缺口：有界 ACK ranges/delay、RTT/rttvar、Karn 与 PTO、ACK-only 发送机会，以及最新 StreamAck/信用状态和操作结果的可靠恢复。采用自有活动帧、记录和 Session owner，载体仍是直接 UDP/TCP，不引入 QUIC 载体。

本文是后续修订的实现合同，不能解释为 r7 已拥有这些能力，也不能解释为 r6 首次 WAN timeout 已找到原因。新字段和帧需要提升实验 wire revision、更新 prologue/能力绑定和测试向量；r7 与该修订不得静默混用。

## r9-next6 分类公告控制

next6 在独立 wireVersion 3 中增加认证 profile/capability 固定和有界 class-control 表。类别可以从 Bulk 降回 Normal/Interactive，因此它不复用要求 Value 单调的信用表；只有 TX version 单调。`ClassUpdate` 使用 flags 0 请求 / 1 ACK、非零版本、完整 u64 类别 0–2、空 Data，完整写入认证承载后才提交精确 `{flow, version, class}` 发布证明。旧 ACK 不清新 pending；恢复快照只 merge peer-view，不替代分类公告 ACK。

分类控制独立于同 flow 的业务 FIFO 选择，但最多共享原 4 个发送机会中的 2 个，并支付真实 UDP record/cwnd/pacer/flight 成本，不使用 PacketAck 的反馈 reserve。UDP loss 只请求当前最新 pending 状态，ACK 无独立 retry；双方 ResumeDone 完成后再发送。更新版本、换承载和旧 ACK 不刷新原 pending 预算，最多 8 次实际 retry / 30 s no-progress；耗尽以既有有界 RESET 终止该 Flow。完整 FIN 或 RESET 清理 class TX、peer 与 ACK slot。

本地冻结检查通过，但首轮原 8 秒活动 UDP 黑洞失败仍保留，时限策略未改。当前 source/binary、独立 race/WAN 状态和完整分类验收缺口见 [next6 实现与验收边界](C:/Users/developer/Desktop/bfp/docs/分类协商StageB实现-r9-next6.md)。该实现不能推导生产成熟或发布状态。

2026-10-09 后续分类 WAN run `387c7e9fd1f9ff07c43cc1ead2ca355a` 保持原 35 秒期限：normal 47/50 `tcp_exchange` FAIL；UDP→TCP 50/50 `idle_restore` FAIL；initial UDP blocked 转 TCP 50/50 CLI PASS。原采集中断后仅补执行尚未启动的两场，完整有界日志取回，两端 owned cleanup 完成；本次 before 快照未落盘，不能宣称前后 baseline 一致。next7 只增加真实加密恢复/丢帧测试，选定 5 顶层/7 叶子场景通过，Windows 完整 gate 因旧 fixture UDP 端口 setup 碰撞失败。自然退避和显式 loss signal 的期限分别解释，详见 [next7 验证边界](C:/Users/developer/Desktop/bfp/docs/分类恢复丢帧验证-r9-next7.md)。用户已说明新加坡网速较慢，后续控制上传与实验并发，不能以放宽原 deadline 或反复重跑消除失败。

## r9-next5 恢复诊断候选

next5 从 next4 冻结的 88 文件源码复制，只增加固定大小、owner 内采样的诊断和确定性回归。新增 `udp_no_response_deadlines` 与 `udp_pto_rounds` 分开记录连续无响应次数和 PTO 退避轮次，并输出路径存在/suspect、base PTO、剩余截止时间、无进展年龄及 TCP 恢复候选 attempts/failures/in-flight。计数饱和，时长非负，不记录凭证、候选 token 或原始错误；TCP 候选 attach/merge 完成不等于 ResumeDone 完成。

虚拟时钟回归证明：2 秒 base PTO 与 1 秒认证非进展 Pong 可以在 2/6/14 秒三次 PTO 后仍只有两次连续无响应；默认 15 秒 watchdog 随后暂停 UDP，并保留同一 Flow、目标连接和待确认数据。生产默认、原有 8 秒集成测试期限及业务交付合同未改；此阶段不能宣称修复 next4 的偶发超时。

本次本地完整测试、vet、双平台构建、独立 Linux race 和基础 WAN 通过；基础 WAN run `e1e6980e72887aa4cabae40714f866f5` 三场 TCP/UDP 均为 50/50，原始周期日志实际出现 PTO 3 次但连续无响应 2 次。该诊断证据不证明旧失败的精确根因；Ticket lifecycle WAN run `cb7508814cd7c798b6dc8f83778df153` 本次通过：三场 TCP/UDP 均为 20/20，均安装 3 次刷新并跨过 12 s TTL；initial UDP blocked 的 elapsed 为 12005 ms，仅超过 gate 5 ms，只证明该有限样本。随机探测、清理及快照比较通过。canonical 清单为 `d0bc24b48c9f9d15d4b099a1bd6d85ce39de269182f9a1ec4e226e173e821f9f`；准确构建哈希、日志和后续 WAN 状态见 [next5 阶段交接](C:/Users/developer/Desktop/bfp/.staging/r9-next5/verification/r9-next5/handoff.md)。next4 的失败不因 next5 一次通过而改写。`production_ready=false`、`released=false`。

## r9-next4 增量合同

- Carrier attach 后，旧 generation 的 `ResumeState/ResumeDone` operation 不再进入新 Carrier 的 retry 表；旧 Carrier 的 `KeyUpdate` operation 同样淘汰。Flow 的 OPEN/FIN/RESET 与 Ticket 等跨承载逻辑状态仍保留。
- 稳定 TCP 的 OPEN、FIN、RESET 调度读取 owner-confined operation 的 `NextSend/Resend` 状态，不再叠加固定 500 ms 重发时钟；TCP 业务 StreamData 仍由字节偏移和 StreamAck 合同负责。
- KeyUpdate 接收端在新 epoch 出现实际认证 record 前，不得用固定计时器退役旧 epoch。新 epoch 使用证明出现后，旧 RX ACK scope 继续保留到 pending ACK 写出；UDP TX ledger 还有旧 epoch live metadata 时不能强制销毁。`KeyDrainTimeout` 默认 10 s，耗尽则挂起当前 Carrier 并走 Session 恢复。
- `RecordCipher` 的 current-record 计数自动清理旧 epoch 只作为底层有界保护；Session key lifecycle 仍以新 epoch 使用证明和 drain 条件为准。
- ResumeDone v1 在认证 payload 内携带 generation、snapshot ID/count、Session credit revision/value 和快照建立后变化的 dirty latest-control；flags=1 receipt 必须回显同一状态，dirty 最多 128 项、payload 最多 8 KiB，超限直接 fail-closed。
- 完全相同的 ResumeDone 请求重试必须重新发出完整 receipt；相同 generation、snapshot ID/count 的更高 barrier 只在 Session credit 和既有 dirty-control revision/value 单调覆盖旧状态时 supersede，先应用再回执，旧 receipt 不得清除更高 revision 的 pending。

## r9-next4 terminal receipt 验证

本轮把 operation receipt 的提交顺序固定为：先验证完整帧结构、方向、generation/epoch/serial/Flow 作用域和语义内容，再确认 owner 中的 pending operation。验证失败不能先清除 pending，也不能通过重复或未来 ACK 改变资源状态。

| 操作 | 当前先校验的条件 | 已覆盖的反例 |
|---|---|---|
| `FIN_ACK` | Flow、flags、value、data 与当前 `localFinal` 完全匹配 | 错误 final offset 关闭 Session，不能完成 FIN |
| `RESET_ACK` | 结构字段与 `resetPending` 匹配；重复 ACK 幂等 | malformed ACK、无 pending ACK 不清 pending |
| `KEY_UPDATE_ACK` | 方向、结构和 epoch 匹配当前 `keyPending` | future/stale ACK 不能完成 operation 或回退 epoch |
| `TicketRefreshAck` | serial 与当前 `ticketPending` 匹配 | future/stale serial 保持 pending，不延长凭证 |
| `OpenResult` | 仅客户端接收；Flow 已存在；flags/value/revision/结果一致 | unknown Flow 或结果冲突不能完成 OPEN |
| `ResumeState/ResumeDone` | generation、Flags、snapshot 成员、数量和 ACK 集合完整 | unknown snapshot、错误数量、错误 Done 不能开放业务 |

这些测试是当前 next4 的定向 terminal validation，不等于所有丢请求、丢响应、丢 receipt、重复消息和资源耗尽组合都已经证明。ResumeDone v1 的 Session revision、snapshot receipt 与 dirty latest-control 已完成定向对齐，但仍需完整 fault matrix、长期 soak 和跨实现验证。

当前证据对应同一个 88 文件源码清单（canonical SHA256 `82dea0429520342eab7099020527849406bd70604add4a265634605d4dc657df`）、Linux 二进制（SHA256 `e6a3e3a84e1435efb6831a4ed88e7bb5e64d9e72059bde1c39db0837e6098016`）和 Windows 构建（SHA256 `88f5af88828e24d0d9dd50894035b25b7acd7ca8e44cf718b73cfeeaef9b9662`）：独立 Linux race run `2b0740497fdd21fb4608fe5f61bc580b`、基础 WAN run `9922a59b0ae25b39f216220989e9e805` 均通过。Linux race 使用 Go 1.27.0/GCC 12.2，15 个包通过，run-owned 容器已清理、洛杉矶快照未变化；基础 WAN 三场 TCP/UDP 均为 50/50，正常 UDP 保持 UDP、活动 UDP→TCP 完成 generation 1→2 和 1 次切换、首次 UDP 阻断直接使用 TCP，Session 和目标连接保持，随机未认证探测静默，两端清理和快照比较通过。双机角色固定为新加坡 `198.51.100.20` 发送、洛杉矶 `192.0.2.10` 接收/出口/测试。

最新完整本地命令 `go test -p 1 ./... -count=1 -timeout=180s` 为 FAIL：`TestRunningUDPBlackholeRecoversSameExitAndBytes` 在 8 秒 deadline 内没有完成切换，截止时 `Carrier=udp`、`Generation=1`、`Switches=0`、`UDPPTODue=3`、`UDPProbeSent=3`。随后 blackhole 定向三次运行为 1 次失败、2 次通过，单独重复活动 blackhole 场景同样为 1 次失败、2 次通过；该时序波动仍待定位，不能用重跑通过回填完整套件 PASS，没有放宽 deadline。`go test -p 1 ./session -run "TestResumeDone" -count=1 -v`、`go vet ./...` 和双平台构建通过。Windows 本地 race 因 `CGO_ENABLED=0` 且无 gcc 未能运行，与协议测试失败分别记录。

策略审查另发现时间预算不匹配：独立 UDP watchdog 当前为 15 秒，有界 PTO 在 2 秒基准与连续退避条件下允许累计约 2/6/14 秒的探针截止序列，而本地测试只给出 8 秒。应核对路径无进展到候选启动的合同与预算；这只是策略分析，不证明单个失败的实际原因，不能代替运行时 PTO 遥测，也没有修改测试 deadline。

最新 Ticket lifecycle WAN run `a8dffd05d5bb86469e148f7ddbbaea22` 整体严格 FAIL，使用 `count=20`、`size=4096`、`interval=200ms`、`timeout=35s`、`ticket_ttl=12s`、`ticket_refresh_lead=8s`、`ticket_overlap=6s`、`max_session_lifetime=5m`。三场 TCP 均为 20/20；normal UDP 与 initial UDP blocked 的 UDP 均为 20/20 并通过，UDP→TCP 的 UDP 为 19/20 并严格失败。三场 lifecycle gate 均为 true、Ticket refresh 均为 3 次，随机探测、两端清理和快照比较通过；生命周期通过不能消除业务样本失败，该单个 Datagram 未回包原因仍未定位。

阶段分析见 [udp-operation-phase-analysis.json](C:/Users/developer/Desktop/bfp/.staging/r9-next4/lab/runs/a8dffd05d5bb86469e148f7ddbbaea22/udp-operation-phase-analysis.json)：iteration 7 的 `write_accepted=true`，在原始 1000 ms 的 read 阶段 timeout，操作前后均为 UDP/generation 1；[udp_to_tcp.probe-log.json](C:/Users/developer/Desktop/bfp/.staging/r9-next4/lab/runs/a8dffd05d5bb86469e148f7ddbbaea22/udp_to_tcp.probe-log.json) 记录下一次 iteration 8 在 TCP/generation 2 成功，交换耗时 177 ms。发送端阶段遥测不能证明 relay 黑洞的精确发生瞬间或具体丢失链路段，因此没有根因结论；既定严格 FAIL 和原始 1 秒操作 deadline 均保持。

旧边界成功 run `6ae1a0a1f0dba2f6293986569c22a9fb`（race）、`e604558042ef8f575f822e8d9f97f2ba`（基础 WAN）、`27cba672eb6813a093a5bc46e78f20e5`（Ticket）只覆盖原 canonical manifest `c02964bf97bdd09b5f193ef146c54790e3f9fb041c017e2704371965fcb50cb4` 和 Linux SHA256 `e36a4271fdb67deba5b0c724de0b3f7f62f376899d492abba08acbfa688f51ce`，继续作为历史证据保留，不覆盖当前 supersede 代码。此前基础 WAN run `d1972af391309e251aa3dd57c1d89572` 的业务场景通过但因发送机非 run-owned UDP listener 的前后快照差异而严格失败，原始记录保留。短 Ticket run `77eb5ff83504460b87839660d9ee04f6` 的严格失败继续保留，因为 `count=20` 没有跨过 12 秒 lifecycle gate；正式重跑不能覆盖历史失败。

## 1. r7 审查基线的合同和具体缺口

| r7 审查事实 | 审查时源码定位 | 本方案改变 |
|---|---|---|
| PacketAck 只包含一个 epoch/record number | `session/session.go:463-487`；`protocol/frame.go` 的 kind 1 | 增加 bounded ranges 和 ACK delay，仍只确认当前 carrier generation 的反方向记录 |
| 只保存平滑 rtt，初值 200 ms；ACK 样本直接以 7:1 更新 | `session.go:97`、123、486-487 | 增加 latest/min/smoothed RTT 与 rttvar，过滤有歧义样本 |
| 每包超过 `clamp(2*rtt,200ms,2s)` 即重排，整批减窗 | `session.go:724-741` | 区分有后继 ACK 证据的 loss 与无 ACK 的 PTO，增加指数退避与每 recovery epoch 一次减窗 |
| ACK 免 cwnd，但在 Pop 之前先受到普通 paceTokens 门限 | `session.go:378-396` | 独立有界 ACK 待发槽与发送预算，先服务到期 ACK，避免 ACK 被业务 pacing/FIFO 卡住 |
| PacketAck 不释放可靠流 retained chunks | `session.go:814-827` | 保持：仅 StreamAck 的连续偏移或经过验证的 resume 进度释放 chunks |
| 最后的 StreamAck 和消费产生的 MaxFlow/MaxSession 多为事件触发 | `session.go:855-887`；`flow.go:133-144` | 保存最新状态，重试直到明确的 state receipt；没有后续业务也可完成 |
| OPEN、FIN 有固定重复；RESET ACK 为空处理；KeyUpdate 无完整 operation retry 状态 | `session.go:604-662`、775-790、896-935（r7 审查行号） | r9-next3 的 `internal/operation` 已接入 OPEN/FIN/RESET/KeyUpdate/Ticket/Resume 写路径；每类 operation 仍需完整 fault matrix 和 terminal receipt 证明 |
| TCP retained chunks 也每隔至少 500 ms 再入队 | `session.go:779-785` | 稳定 TCP 不跑 packet loss loop；保留流进度确认和逻辑状态恢复，必要补传限定于新 carrier 的恢复进度 |
| Ticket 已有独立 serial/安装 ACK 和固定 expiry | `session/ticket.go:167-220` | 保留现有资格/expiry 合同，接入统一控制调度，不拿 PacketAck 替代安装 ACK |
| resume 已有逐流快照与 Done 的逻辑门槛 | `session.go:227-301`、492-591、750-812 | 增加最新控制 revision/receipt 和终止操作状态的对齐，业务开放门槛保持严格 |

三层确认始终独立：

1. **PacketAck**：经过认证和解码的 UDP record 已到达该 Session owner。释放该 carrier 的 bytes-in-flight、服务 RTT/拥塞；不释放 stream retained bytes，不表示目标执行。
2. **StreamAck(rx_next)**：字节已连续接收、由存活 Session 保存。发送端据此释放对应 retained bytes；不表示目标业务已处理。
3. **逻辑完成/状态 receipt**：明确表示 OPEN 结果已安装、FIN/RESET 已按合同接受、key epoch 已安装、Ticket 已安装，或最新信用/StreamAck 已应用。PacketAck 不替代这些条件。

## 2. 选定的最小实现结构

新增一个 owner-confined UDP transport 模块和一个 owner-confined latest-control 表。packet 表保存记录元数据与逻辑引用，不把每次重试当成新的业务操作；可靠流数据仍保存一次应用字节副本。

| 对象 | 作用域与上限 |
|---|---|
| RX ACK history | 每 carrier、反方向 epoch；当前与一个过渡 epoch，各 4096 位 bitmap，输出最多 32 ranges |
| sent ledger | 每 carrier、发送 epoch；当前与一个过渡 epoch，各有界 4096 位提交历史，验证 ACK 不确认未发送记录 |
| in-flight packet metadata | 每 carrier 最多 256 条 ack-eliciting records，其中普通发送最多占248条、8条预留probe；到上限施加发送背压，不能先发第257包再suspend |
| ACK pending slot | 每 RX epoch 一份最新 snapshot，最多两份；覆盖合并，不在业务 DRR 中累积每包 ACK |
| latest controls | 每流的 StreamAck、MaxFlow，Session 的 MaxSession，以及有界 OPEN/FIN/RESET/key/ticket/resume 操作槽 |
| logical retry | 每 key 至多一个待发送引用；最新 revision 替代旧 revision，不追加无限队列副本 |
| retired packet metadata | fixed-size tombstone，用于 late ACK 幂等与统计；不持 payload，过期后忽略已退役旧 ACK |

活动流上限仍为默认 32，生命周期 OPEN/tombstone 上限仍为 4096；可靠控制表占用另计 Session metadata 预算。活跃控制先服务，终止记录惰性保存；历史终止槽没有未完成操作时不应每轮扫描重发。

## 3. 冻结的 ACK ranges 编码

新 revision 保留 `PacketAck` kind 1 的名称，修改其加密内部字段；不增加明文可识别字段。

```text
PacketAck:
  flags  = 1                       // ranges 格式，flags=0 不在本 revision 接受
  flow   = 0
  offset = largest_acked_record_no
  value  = acked_key_epoch          // 高 32 位必须为零
  data   = ack_delay_us:u32
           range_count:u8
           reserved:3B (=0)
           { first:u64, last:u64 }[range_count]
```

规则：

- `range_count` 在 1..32；data 长度恰好为 `8 + 16*range_count`，最多 520 B。
- range 是 inclusive `[first,last]`，按 last 严格降序，不交叠、不相邻；相邻必须合并。首 range 的 last 等于 offset，每个 first≤last，不能超过该 epoch 的最大记录号。
- ACK history 只登记成功通过 AEAD、LIGHT 和全部帧结构解码的 **ack-eliciting record**。以 record 为单位登记一次，不能每帧添加一次 PacketAck。
- ACK ranges 只表达当前 generation；它确认反方向的 `acked_key_epoch`，不能把 ACK 自身外层的发送 epoch 当作被确认 epoch。
- `ack_delay_us` 表示接收 offset 指向的最大 ack-eliciting record 到建立 ACK snapshot 的本机时间。发出前重新计算，量化为微秒并 clamp 到 0..25000。接收方把超过 25000 的字段视为协议错误；实际 actor/预算排队超出 25 ms 时只报 25 ms，保留原始延迟指标，不用夸大 subtraction 伪造低 RTT。
- 两个 epoch 分别建立帧，不用一个 range 跨 epoch。history 早于 bitmap 的下界可以遗忘，发送端未获 ACK 的可靠状态由其保留表重新封装，不依赖无限接收历史。

发送端处理一份 ACK 前，先完整验证所有字段、范围、scope 和 sent ledger，再统一 mutation。范围声明未成功提交给 carrier 的记录，或大于该 epoch 的最大实际提交号，属于经认证的协议错误。过渡 epoch 的有效 late ACK 可完成尚保留的旧 metadata；已退役 scope 的旧 ACK 忽略并计数，不能影响新 generation/epoch 的 flight、RTT 或 control receipt。

提交历史的下界随有界窗口推进。早于该下界且已无 live metadata 的号按退役状态忽略，不能因本地已遗忘其历史而把正常延迟 ACK 判为未发送；仍有 live metadata 的号保留独立的提交证据，不因 bitmap 推进失去可确认性。验证每个范围时仅检查与提交窗口相交的至多 4096 位，以及有界 live metadata；不展开已退役的大整数区间。

重复 ACK、重叠 ACK 消息和对已经 ACK/lost 的记录的 late ACK 不重复释放 flight，不重复扩窗，不再次完成逻辑操作。查找和释放只遍历最多 256 条 metadata，不按攻击者提供的超长 `[0,2^32)` 区间循环展开。

ACK-only 记录是仅含 PacketAck 和可选 LIGHT padding 的 record；后文新增 ControlReceipt 单独成 record 时同样不 ack-eliciting。空帧 record 和仅 padding 不生成包 ACK。其他现有业务/命令/逻辑响应 record 都 ack-eliciting；PacketAck 本身不被重传，不形成 ACK-of-ACK。

## 4. ACK 生成与绕过业务 pacing 的有限机会

默认延迟 ACK 目标为 25 ms，累计两个新的 ack-eliciting records、出现乱序/填洞或进入恢复控制时，尽早发最新 snapshot。每 RX epoch 仅保留一份 ACK 意图；发送后出现新包可建立下一份。ACK 丢失不独立重传；后续包或 PTO probe 引发新的 ranges，包含仍在 history 中的旧记录。

flush 先检查 ACK/ControlReceipt 待发槽，再检查业务队列、普通 pacer 和 cwnd。纯 ACK 不占 cwnd、flight 或可靠 packet retry 表，但所有真实 wire bytes、padding、CPU 和发送次数进入统计及独立 ACK 预算。

选定初值：ACK reserve burst 2400 B、refill 上限 64 KiB/s，每次 owner flush 最多两个 ACK-only records，单 record 仍≤1200 B。纯 ACK 使用 LIGHT 的加密长度封装，但额外 padding 上限 64 B，避免高随机 padding 挤占反馈预算；该 profile 差异需要纳入长度分布测试，不宣称不可识别。

这个 reserve 不读取普通 paceTokens，不与 Flow 0 或业务 flow 的 FIFO 共享 pending slot，所以“业务 tokens=0/cwnd 已满”仍有机会发送 ACK。reserve 用完则合并最新 snapshot 等待补充；不能无限旁路。过载时 25 ms 只是计划时限，不是保证，实际 delay、reserve shortage 和 snapshot coalescing 必须可观测。

PTO probe 有另一个最多两 MTU 的一次性预算，可有限越过 cwnd，记入 flight 和 packet ledger。它在业务 DRR 之前获得发送机会；业务 pacer 不足时最多形成两 MTU 的有界 token debt，后续 refill 先偿还该 debt，不能因普通队列持续取走 tokens 而饿死到期 probe，也不能每次 flush 重新取得 probe 预算。不要把 FIN、OPEN_RESULT、KeyUpdate、TicketRefresh 等命令统统伪装成 ACK-only 来逃避拥塞；它们使用有界 Interactive 控制发送机会。

## 5. RTT、Karn、loss 与 PTO

### 5.1 RTT 估计

以 carrier write 成功完成时记录 `sentAt`，ACK 被 owner 实际处理时记录 `ackAt`。本地 actor 等待会计入样本，不能按旧 tick 时间计算，也不能用对端 wall clock。

只取每份 ACK 中 **offset 对应、此次新确认、可采样的 ack-eliciting record** 一个样本。若 offset 对应的是已退役/不可采样记录，不从另一个 range 随意减同一 delay。初始 `srtt=200ms`、`rttvar=100ms`，首个真实样本替换初始值；维护 raw `latest_rtt` 与 `min_rtt`。

```text
raw_sample = ackAt - sentAt
min_rtt = min(min_rtt, raw_sample)
adjusted = raw_sample
if raw_sample >= min_rtt + bounded_ack_delay:
    adjusted = raw_sample - bounded_ack_delay

first valid sample:
    srtt = adjusted
    rttvar = adjusted / 2
later valid sample:
    rttvar = 3/4*rttvar + 1/4*abs(old_srtt - adjusted)
    srtt   = 7/8*old_srtt + 1/8*adjusted
```

Karn 采用保守规则：包含任何重新发送的 StreamData、logical operation 或 latest-state retry 的 record 不用于 RTT 更新；其 PacketAck 仍正常释放 flight。重试都使用新 record number，元数据标注 retry lineage。PTO 使用新 Ping/探测编号，可建立无重传歧义的 RTT 样本。忽略零/负 sample 和退役 scope，不允许 ACK delay 将 adjusted 压到 min_rtt 以下。

### 5.2 loss 与 flight

packet metadata 保存 carrier-local 的 ack-eliciting send ordinal，独立于每 epoch 会归零的 record number。loss 证据选为：

- packet threshold：至少三个后发的 ack-eliciting ordinals 已得到确认；
- time threshold：已确认后发记录，且候选 send age 超过 `9/8 * max(latest_rtt,srtt)`，下界 10 ms。

没有后继确认时，不能因为经过一个固定 rto 就把所有 outstanding 宣告丢失；该情况由 PTO 处理。loss/ACK 对每条 metadata 至多减 flight 一次。late ACK 的 packet size 不能再次减 flight；同一 recovery epoch 至多减 cwnd 一次。

数据丢失重新请求原 retained chunk 的范围；Datagram 不业务重传，metadata 丢失仅释放 flight 和更新统计。latest-state loss 标记对应 key 为待发送，实际发送时取 **最新 revision/value**，不重发过期信用或旧 StreamAck。重复 packet 引用不能同时堆入多个 retry 项。

最小 congestion 合同沿用 NewReno 形式：初始 cwnd=10 MTU，最小=2 MTU，最大=256 MTU；slow start 按此次新 ACK 的 flight bytes 增长，avoidance 每个 ACK 的整数除法余数要累计，避免大量小 ACK 造成意外偏置。进入 loss recovery 时 `ssthresh=max(2MTU,cwnd/2)`，cwnd降到ssthresh，记录 recovery end ordinal；在该 end 之前的旧 ACK 不再扩窗。必要 persistent-congestion 规则先按连续有证据的 loss 跨多个 PTO 区间降到2MTU，不能把 PTO 本身当丢包。

### 5.3 PTO 和路径故障

```text
base_pto = clamp(srtt + max(4*rttvar,10ms) + 25ms,200ms,2s)
pto(n)  = min(base_pto * 2^n,8s)       // 饱和运算，n 上限由状态机限制
```

outstanding ack-eliciting packet 从 0→1 时 arm PTO；普通新业务发送不能延后已有 deadline，避免持续写入使无反馈路径永远不探测。有效新 PacketAck 进度或当前 fresh token 匹配的 Pong 可清零 backoff 并重设期限；单次 PTO 到期只授予最多两个 probe，实际 probe 成功提交后才按增长后的 backoff rearm。没有发送预算或预留槽时必须明确报告 stalled，不能静默续期。优先携带最新未完成控制或一个最早未确认 StreamData 范围，没有可用项则新 Ping。此次 probe 重新封装且有新记录号；Datagram 不因 PTO 重发。PTO 不删除所有 outstanding、不直接减 cwnd。首次合法 late ACK 若仍有当前 generation/未退役 epoch 的有界 lost metadata，可以提供一次新 transport progress，但不释放 flight、不采 RTT或扩窗；重复、忘却和退役 ACK 不产生进展。

只有新 PacketAck 进度或与当前探测编号匹配的新 Pong 才清零 PTO backoff；普通认证响应更新 path health，但不能让一个未进展 operation 的重试计数清零。普通发送最多占248个packet槽，保留8槽供有界probe；三轮无响应回退前最多新增6个probe槽。若持续认证Pong却长期没有packetACK进度，预留槽也耗尽，直接按transport-stalled暂停/恢复，不能覆盖尚未确认metadata、假装PTO是loss或发第257包；原逻辑状态保留到新carrier恢复。已确认/明确loss的槽可以复用。

在第三个 PTO 截止仍没有新的认证响应时进入 UDP_SUSPECT，客户端立即启动同服务器 TCP 候选；不再等待第三组 probe 的完整响应间隔。base PTO=2s 的理想截止为 t=2/6/14s，而等待第三组 probe 的间隔会到 t=22s，两者不能混称三轮等待。默认独立 `UDPFailureBudget=15s` 是无进展区间的硬 watchdog，受 Session 剩余寿命约束；actor 延迟时可以由 watchdog 先触发，不能宣称所有调度下必执行满三个 PTO 截止。旧 `FailureTimeout=3s` 不能继续先截断 UDP 而声称采用新 PTO 策略。认证响应健康时间与 transport progress 时间分别维护，普通认证帧不能把 backoff 或逻辑重试计数清零；有认证响应但 operation 不推进仍受其总期限约束。TCP 的 socket/保活截止和固定 RetainTimeout 保持各自语义。

每次有效 carrier 替换重置 UDP RTT/packet/ACK/PTO 状态，以初值启动；不继承旧路径的样本或 flight。TCP不运行这些 packet loss/PTO/cwnd状态，但仍运行下一节的逻辑状态确认。

## 6. 最新单调控制的明确 receipt

增加 `ControlReceipt` kind 24，专用于 StreamAck、MaxFlowData、MaxSessionData、OpenResult 的安装/应用确认；不作为万能“所有操作完成”消息。既有 `TicketRefreshAck` 为 kind 23，ControlReceipt 追加在末尾。

```text
ControlReceipt:
  flags  = 0
  flow   = 原状态的 flow_id（MaxSessionData 为0）
  offset = 已应用 state_revision
  value  = 原状态 kind（仅7/8/21/5）
  data   = 空
```

原状态增加 revision：StreamAck 的 value=revision（offset仍为rx_next）；MaxFlowData/MaxSessionData 的 offset=revision（value仍为绝对信用）；OpenResult 的 offset=revision（初次结果为1），value=0，data保持原结果。每个 `(kind,flow,direction)` 的 revision 初值1、严格递增、不回绕；新的单调 value合并成新的revision。direction仍由frame发送方向隐含，ControlReceipt明确确认其反方向状态。

接收端先验证 scope、revision、value/结果与已有状态一致，**完成应用后**发送 receipt。同 revision 不同value/结果是冲突；较低revision不回退状态，可以回应该旧revision的receipt或当前已应用revision。对未来revision或从未实际发送的revision的 receipt不能清除 pending。

发送端只让 receipt 清除≤已确认 revision 的 pending；本地如果已有更高revision，旧receipt不能完成新状态。对于未来 receipt，按经认证的协议错误处理；低/重复receipt保持幂等。sent revision 的发布记录在 packet成功提交后建立，排队并非已发送。

ControlReceipt 单独发出时不诱发 PacketAck、不保存需要 receipt 的状态、不主动无限重复。原状态未获得 receipt时重发，接收端每次可重新生成 receipt；不存在 receipt-of-receipt。

latest-control表存语义值，不存固定密文。一次新值更新覆盖旧待发项；发送时重新取最新值、使用新record number。已排队的引用如果revision过旧则刷新/跳过，不让旧的信用帧堆积。每个key最多一条队列引用。

逻辑 retry 采用当前 base PTO、独立backoff，最多8次实际重试，operation无进展总预算为 `min(30s,Session剩余寿命)`；恢复或消息新revision不能延长原始无进展deadline。健康会话中收到其他数据也不能替某个丢失最终信用完成逻辑确认。耗尽时暂停 carrier并恢复；恢复也无法推进且RetainTimeout到期则显式失败，不无限retrans。

这保证最后一份 StreamAck 或信用即使没有后续业务触发也会再次发送。发送端释放stream retained bytes只看StreamAck内容；ControlReceipt只让接收端知道其StreamAck已被对方应用，不产生第二次业务释放。

## 7. 操作类控制的重试和完成证据

| 操作 | 未完成方保存 | 真正完成条件与丢失处理 |
|---|---|---|
| OPEN | 客户端 flow_id+不可变Target；服务端原拨号操作和结果 | 客户端收到并安装匹配OpenResult才结束OPEN等待；OpenResult发布方收到ControlReceipt才结束结果重试。PacketAck不能代替，重复OPEN回原结果不redial |
| FIN | final offset、pending/accepted状态 | 匹配FinAck证明对端按冻结FIN合同接受该方向最终偏移；只有全部前序字节已保存/消费到半关闭条件才发送。Fin丢失重试同final，FinAck丢失由重复Fin重发响应 |
| RESET | reset操作、不可变终止原因（初版无原因则固定默认值）、pendingACK | ResetAck明确结束发送方pending reset。reset后的Flow不允许maintain整体skip导致RESET永不重试；终止tombstone仍服务重复Reset和Ack，不复活target |
| KEY_UPDATE | 提议的next epoch、old发送epoch、pending install ACK | 匹配KeyUpdateAck后才更新TX epoch；PacketAck仅表示提议record到达，不能换钥。Ack丢失重复旧epoch提议，RX返回相同Ack |
| TICKET_REFRESH | 当前serial/locator/固定绝对expiry、pending安装ACK | 仅匹配TicketRefreshAck安装serial完成；PacketAck不替代。重试重新算剩余ttl，不延长原issue，不增alias；到期和最大寿命保持原合同 |
| ResumeState/Done | 当前generation固定快照集合、逐项确认与Done确认 | next4 先校验 generation、快照成员、数量和 ACK 集合；ResumeDone v1 还校验 Session revision、snapshot ID/count 与 dirty latest-control，并由 flags=1 receipt 回显完整 barrier；PacketAck不开放业务。预算超限 fail-closed，完整 fault matrix 仍待完成 |
| SESSION_CLOSE | 终止意图、固定短排空deadline | ACK丢失不无限保活；在短有界关闭窗口内服务重复请求，随后destroy与撤销恢复资格。无需普遍保证对方收到最后ACK |

FIN合同需同步纠正当前“接收连续即FinAck”与目标半关闭的关系。RX保存final后，等待 `receiveNext==final`，本地Flow仍先读完缓冲再给EOF。`consumed`在Flow.Read取走字节时增长，**它不等于bridge已写完target**。服务器另维护owner接收的bridge写入完成偏移和半关闭完成结果，只有前序字节全部成功写入target、相应CloseWrite已经完成才发FinAck；不能仅用 `consumed==final` 提前确认。桥接结果回owner，owner不等待target socket。用户直接读取Flow的客户端侧，以其本地方向已消费到final并接受EOF为完成条件。target错误导致RESET，不能用FinAck把失败尾部当作交付完成。

FIN/RESET等响应可被普通PacketAck解除其carrier记录flight/retry，但对操作发起者而言只有对应逻辑Ack结束操作。响应方无需另设计逻辑Ack-of-Ack；命令重试时重合成响应，tombstone有界保存到Session终止/生命周期记录限额。没有匹配final/operation的FinAck、ResetAck不改变资源状态。

KEY_UPDATE必须同时修复旧RX epoch退役：提议接收后保留当前+一个旧epoch，不能仅因5秒计时就退掉仍等待发送方确认消费的旧epoch。收到新epoch首个认证record证明发送方已消费安装ACK，再进入有界drain（选max(3*basePTO,5s)，上限10s）；期间旧packetACKscope保留。当前 `RecordCipher.Open` 接收4096条current记录自动清previous也必须服从这个生命周期门槛，不能独立提前清掉仍要使用的旧scope。尚未看到新epoch且keyoperation总预算到期则carrier失败/恢复，不无限保留，也不接受第二次重叠update把尚需旧epoch挤掉。不得要求两方向keyepoch同时更新。

Ticket保留现有special deadline：issue到期可以在仍健康、认证carrier上签发下一serial，但不拿该操作重发延长Ticket或Session寿命。最终Ticket已覆盖剩余Session寿命且安装完成后不再次轮换。KEY/Ticket的ACK都在不同的发送方向封装，不以ACK外层epoch替代提议epoch/serial。

## 8. TCP 稳态与恢复同步

稳定 TCP不做协议record丢包检测、PacketAck、cwnd或PTO探测循环，stream chunks在该generation第一次成功写入后不因固定500ms重复。retained byte buffers仍保存到StreamAck，不能因为TCP write成功或内核ACK就释放。最新StreamAck/信用和操作类控制仍有逻辑receipt/超时/重试，这是会话合同，不因carrier是TCP而关闭。

当一份逻辑控制在TCP上已提交且未收到receipt，可有限重发最新语义值；这不等于重传所有TCP业务。若TCP停顿或逻辑无进展到期限，触发carrier失败/恢复。不能用“TCP可靠所以清空控制表”替代恢复状态，也不能无限循环重复所有StreamData掩盖最终StreamAck丢失。

carrier attach后清除旧packet metadata、RTT、ACKhistory、flight、queue引用和路径timer，**保留**流offset/chunks、latest单调value/revision、operation结果/完成状态、classifier/baseline/计数和Session寿命。

新revision的ResumeState/ResumeDone至少增加：

- 本端该方向的receiveNext、consumed和MaxFlow value/revision；
- 最新StreamAck revision及已知receipt下界；
- OPEN不可变结果与结果revision/安装状态；
- 两方向FIN final/accepted状态，RESET操作与确认状态；
- Session信用value/revision在Done或独立snapshot中对齐；
- 本端当前Ticketserial/固定remainingTTL安装状态按现有merge合同对齐。

ResumeDone v1 的最小状态为：`version=1`、carrier generation、单调 snapshot ID、固定 snapshot count、Session-level credit revision/value，以及按 `(kind,flow)` 排序的 dirty latest-control。接收端先应用 Session credit 和 dirty 控制，再写出带同一状态的 flags=1 receipt；发送端只在 receipt 与当前完整 barrier 相等时结束 Done operation。旧 receipt 若只覆盖冻结快照，则保留 pending 并重新发布当前更高 revision；未知 kind、乱序/重复项、revision rollback、future receipt 或 payload/dirty budget 超限都 fail-closed。

dirty 允许 `StreamAck`、`MaxFlowData`、`MaxSessionData` 和服务端到客户端的 `OpenResult`，最多 128 项；ResumeDone JSON payload 最多 8 KiB，且只在认证记录内部传输。相同完整请求重试时，接收方必须重新发送完整 flags=1 receipt，不能因为第一次已应用而丢弃重试。相同 generation、snapshot ID/count 的更高请求只有在 Session credit 与既有 dirty-control revision/value 单调覆盖旧 barrier、相同 revision 的值/结果一致时才允许 supersede；接收方应用更新后重新回显完整升级状态。发送方的旧 receipt 不能清除当前更高 revision，也不能提前开放业务。

key update是carrier-local操作：新carrier重新握手有新key，旧carrier的pending update不能在新key上继续同epoch提议；不清除Ticket/Flow状态。UDP packetACK也不能跨generation迁移。

snapshot按当前generation冻结，逐项应用后flags=1 receipt绑定该generation和固定snapshot版本。state revision/value不一致、对端低于已释放进度、声称收到未发送字节都明确失败。快照建立后到业务开放前产生的目标消费/控制更新记录在独立dirtylatest槽，并纳入当前ResumeDone barrier；若等待receipt时又有更新，重新发布单调升级barrier并等待覆盖当前完整状态的receipt。业务开放后的新revision继续使用正常latest-control/ControlReceipt合同，不能把旧snapshot receipt当作新state receipt。

只有双方固定集合收齐且本端Done获得逻辑确认才开放业务。经验证resume接收偏移可释放已确认chunks；仍保留范围从新generation补齐。相应最新状态若在snapshot中被逻辑确认应用，可以清除≤快照revision的pending；新revision继续等待自己的receipt。单次恢复总预算和固定RetainTimeout不被重复candidate/ACK延长。

## 9. 发送调度、预算与分类衔接

每份wire成本包括frame、LIGHT padding、record overhead，进入真实发送统计；UDP ack-eliciting records进入pacer/cwnd/flight，纯ACK使用独立有限reserve。只有应用Write的成功新字节推进分类器；控制重试、PTO、recovery、重复data和padding都不重复计数。

控制表使用独立有界发送key，避免把control frame的Flow字段直接等同业务FIFO key。例如ResumeDone.flow为集合数量，不能因此排到该数字对应的Bulk业务Flow后。每轮最多两个独立control机会和两个业务DRR机会，持续control还受budget，不无限挤占业务。

logical控制分类始终Interactive；业务StreamData/Datagram使用本地TXeffective。分类阶段A的 `classForFrame` 应在congestion/pre-sync/retrans路径统一使用，控制与类别/交付语义分离。因为控制表记录最新semanticstate，不能通过ReclassifyFlow把旧control降级；更不能用类别改变FIN/RESET/UDP尽力交付合同。

## 10. 实现边界与最小分阶段提交

1. **线格式/纯模块**：ranges parser/codec、ACK history、sent ledger、RTT/loss/PTO状态；使用虚拟monotonic clock，冻结序列测试向量。新增ControlReceipt以及state revision字段，提升wire revision，拒绝旧格式混用。
2. **Session UDP接线**：receive整record一次登记ACK；actualwrite成功后登记ledger/pending；先发ACKreserve；统一ACK验证和flight/loss mutation。接入控制key引用而非裸frame无限副本。
3. **最新控制与操作**：StreamAck/MaxFlow/MaxSession receipt与合并，OpenResult receipt，Reset pendingAck；Key/Ticket/FIN逻辑deadline和确认条件。response丢失会由commandretry重新合成。
4. **TCP与resume**：稳定TCP sent-generation标记、去掉固定无条件stream再入队，同时保留latest/operation逻辑retry；升级snapshots/dirtystate对齐，真实切换保留target和classifier。
5. **本地/race/WAN严格验收**：只有全部mandatory路径通过才报告完成。失败前保留原日志，不通过延长probe 1秒deadline或重判迟到业务回复使场景通过。

这一方案冻结的是最小可实现语义。ACKdelay/pacerreserve/初始RTT等候选常数以后可以有经认证协商或配置，但第一次实现用同一修订两端固定值，避免同时引入参数协商、FEC、COVER、多路径和自动TCP→UDP回切。

## 11. 必须完成的测试矩阵

| 层 | 核心回归 |
|---|---|
| codec/scope | 32ranges上限、排序/相邻合并/交叠/长度/保留位、epoch高位、ACK未发送号、future/retiredscope、原子失败不改flight |
| ACKhistory | 乱序/填洞、4096位窗口跃迁、两个epoch、同record多frame只确认一次、纯ACK不诱发ACK、ACKdelay累积与clamp |
| RTT | 首样本、minfloor、delay超限、srtt/rttvar公式、Karn不采样retry、AckOnly/lateAck不采样、actor实时时刻、epoch/gen替换重置 |
| loss/PTO | 3后继packet证据、time证据、无ACK只probe不batchloss、指数退避/饱和、max2probe、同recoveryepoch只减窗一次、lateACK不doubleflight |
| ACK机会 | paceTokens=0、cwnd满、业务FIFO/Flow0拥挤时ACK仍可发；reserve耗尽保持有界合并；auth flood不会无限控制旁路 |
| finalstate | 最后StreamAck/MaxFlow/MaxSession和其receipt分别丢一次或连续几次，没有后续业务仍恢复；旧receipt不完成新revision；latestvalue不回退 |
| operations | 丢OPEN/结果/结果receipt不redial；丢FIN/FinAck不改final与半关闭顺序；丢RESET/ResetAck终止tombstone继续retry；PacketAck不能完成逻辑操作 |
| key/ticket | KeyUpdate或Ack丢失仍安全重发旧epoch；5秒后Ack丢失不误退旧key；不重叠update；新epoch证明后有界drain；Ticketissue不延寿、不增alias |
| TCP | 无网络packetloop、一次成功streamwrite不500ms盲重发；逻辑最后state/response仍有限可靠；write失败/switch保留chunks并正确补齐 |
| resume | 一项state/receipt/Done丢失不早开放；snapshotdirty更高revision不被旧receipt清掉；旧genACK不改新flight；target不redial，分类计数不重复 |
| budgets/exit | metadata≤256，latestkey单槽，pendingretry有界，所有timer/cancel退出；信用0时不误判应用idle为pathloss；operation耗尽显式失败 |

真实loss实验用透明本地UDP中继按frame/record元数据有控制地丢包，握手与目标权限不放宽；TCP场景用受控wrapper过滤逻辑帧或真实断连，不假设内核会随机丢完整TCP字节而继续正常framing。两端时钟差不影响算法，metrics不记录key、Ticket或业务payload。

最终证据应同时展示transport ACK进度、logical pending/receipt、flow offset/credit、PTO轮次/退避、cwnd/flight、queue/ACKreserve和resume门槛。通过这些指标区分业务超时、carrier无响应、ACK反馈停顿与最终控制丢失，不能把其中一个指标当作全链路成功。
