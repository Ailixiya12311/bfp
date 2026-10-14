# TCP 承载下 UDP 时限与排队审查

日期：2026-10-07。审查基线：r6 冻结源码。性质：源码边界审查、验收结果解释和后续测试设计。

**当前 WAN 首次 UDP 超时的现场根因尚未确认。本文确认的是代码中的时限、排队和背压边界，并列出可能来源与可复现实验；没有把这些边界直接认定为现场故障原因。**

初次只读审查仅新增本文。r6 已独立留档为 FAIL 后，另行授权实施 r7 的两处边界修复及本地回归；具体已完成范围见第 9 节。没有修改 r6 留档结果或 `lab` 文件，r6 的原始失败判定仍然成立。

## 1. 已知验收现象与结论边界

主验收提供的 r6 WAN 运行标识为 `97e1e70f41907588de12dcfdc038cf9f`。其中：

- `normal_udp`：TCP 50/50、UDP 50/50，场景通过。
- 运行中切换场景：严格验收失败，出现一次 UDP 失败。
- UDP iteration 46：操作前后为 TCP carrier、generation 2，约 1000 ms 超时，`received_iteration=null`。
- UDP iteration 47：约 170 ms 成功，`last_unmatched_iteration=46`、`late_count=1`、`unmatched_count=1`，随后正确匹配当前 iteration 47。

这些信息由主验收核对并提供，本次源码审查没有独立重新运行 WAN。它们支持以下结论：

1. iteration 46 的请求或回复没有在该次 1 秒预算内完成，仍计为一次失败。
2. iteration 46 的迟到回复在 iteration 47 中被识别和跳过，没有污染 iteration 47 的匹配结果；r6 的关联修复有实际证据。
3. 前后都是 TCP/gen2，不能单独证明操作期间没有 actor 停顿、排队、socket 背压、同步状态变化或 target 延迟。
4. iteration 47 收到迟到回复，不能反向将 iteration 46 改判成功，也不能定位迟延发生在哪个阶段。
5. r5 的连续错配现象与 r6 的迟到回复证据应分别记录，不能用 r6 的 payload 关联结果补写 r5 未采集的内容。

## 2. 操作路径与真正的 deadline 边界

一次小 UDP echo 在稳定 TCP carrier 上，大致经过以下路径：

```text
probe 开始计时
  -> sender Stats 前观测
  -> Flow.Write 等待 sender actor
  -> Datagram 进入 scheduler
  -> actor flush -> TCP Framer.Write -> socket
  -> peer TCP Framer.Read -> incoming channel -> peer actor
  -> 入站重组完成 -> peer Flow 消息队列
  -> bridge Flow.Read -> UDP target.Write
  -> target 回复 -> bridge target.Read -> peer Flow.Write
  -> scheduler -> TCP carrier -> sender actor
  -> sender Flow 消息队列 -> probe Flow.Read / payload 匹配
  -> sender Stats 后观测 -> 输出 elapsed
```

`Write` 返回完整长度表示数据报被接纳或经过当前的丢弃分支，不表示 peer 已收到，更不表示 target 已处理。1 秒 probe 预算覆盖的是一次请求/回复交换，不是单次载体 write 的独立超时。

以下源码行号对应审查时的 r6 源码，后续改动后应按符号重新定位。

| 行为 | 源码位置 | 可以确认的影响 |
|---|---|---|
| UDP Write 使用 `s.call(context.Background())` | `session/flow.go:163-209`，尤其 169 | UDP 分支没有读取 `writeDeadline`，等待 actor 的时间不受该 deadline 限制 |
| TCP Write 为 actor admission 使用 deadline context | `session/flow.go:214-227` | TCP 分支已有处理固定 deadline 的路径，与 UDP 不同 |
| `call` 的排队取消与提交状态 | `session/session.go:139-178` | 尚未执行的命令可被标为 canceled；开始执行后的调用会等待 closure 完成，防止返回失败后仍不明地提交 |
| 同步写载体 | `session/session.go:391-394` | 一次 TCP socket 写未完成时，actor 不能处理其他命令、收包或 tick |
| 单次 TCP write 的 socket deadline 为 2 秒 | `session/carrier.go:48-53` | 载体 write 可持续超过 probe 的 1 秒预算，然后成功或到 2 秒失败；这是不同层的时限 |
| 完整 envelope 写入与读取 | `security/bootstrap.go:190-225`、`security/common.go:45-59`；完整读取在 `security/bootstrap.go:127-144` | Framer 写完才返回、读完才交付；TCP 字节顺序仍约束后续 record |

### 2.1 probe 的 Stats 也占用预算

`cmd/bfp/main.go:454-470` 的实际顺序为：先记录 `udpStarted`，再调用 `s.Stats()`，随后形成 `udpStarted + 1s` 的 deadline，执行 exchange，最后再调用 Stats 和计算 elapsed。

`Stats()` 在 `session/session.go:186-197` 使用 `s.call(context.Background())`。因此：

- `udpBefore` Stats 等待 actor 的时间计入 1 秒预算。如果它阻塞到 deadline 之后，`exchangeUDP` 可在 `cmd/bfp/main.go:344-345` 的 Write 前检查直接超时。
- UDP Write 自身也可能在 actor admission 阶段超过 deadline。exchange 在 Write 返回后、Read 前再次检查时间，见 `main.go:356-359`。
- `udpAfter` Stats 在 `main.go:468` 执行；elapsed 在 470 才取值。后观测可增加所报 elapsed，但不能改变已经完成的 exchange 判定。
- 当前日志的 elapsed 不是纯网络 RTT，且没有区分前后 Stats 与实际 exchange 耗时。

不能通过简单重设或延长 deadline 让原来的失败通过。r7 可以增加分阶段计时，既保留整体预算语义，也单独显示观测开销；若调整计时起点，必须明确记录验收口径变化，不能拿新口径覆盖 r6。

## 3. flush、优先级和排队

### 3.1 10 ms tick 不是固定的发包间隔

`session/session.go:315-342` 在处理每个 command、incoming 或 10 ms tick 之后调用 flush。`flush` 每次最多取 4 帧，见 356；每帧独立编码为一条 record，见 372。

只有当没有额外命令和收包事件、完全由 tick 驱动时，才可估算约 400 records/s 的 drain 速率。这不是全局固定上限；持续事件可让 flush 更频繁。相反，同步 TCP write 阻塞也可以让 drain 更慢。

UDP pacing token、cwnd 和 flight 门限只用于 UDP carrier，见 `session.go:351-365`、396-407。稳定 TCP carrier 不经过这些门限。不能把 TCP 下的首个超时归因于 UDP pacing。

UDP payload 每 900 字节分片，最大 16 KiB，见 `flow.go:164-165`、179-201。最大数据报产生 19 帧；队列空且仅 tick 驱动时，首批及后续四个 tick 即可写完，量级约 40-50 ms。小 `message-i` 为单帧，这一机制自身不足以解释约 1 秒迟延。

### 3.2 同 Flow FIFO 是控制帧优先级的实际边界

`enqueue` 使用 `f.Flow` 作为 scheduler 的 flow key，见 `session.go:344-345`。scheduler 按类别分配总字节权重 4:2:1，但每个 Flow 保持 FIFO，头项类别决定其所在类别：

- 约定与入队：`scheduler/queue.go:1-5`、96-130。
- 取头项与类别迁移：`queue.go:371-408`。

同一业务 Flow 上后来加入的 Interactive 控制帧不能越过先前的 Normal/Bulk 数据帧。Flow 0 控制帧有其自己的 FIFO。调度器也不能重排已经提交到 TCP socket 的字节。

同步期间的 `ResumeDone` 使用 `Flow=len(syncFrames)`，见 `session.go:737` 和 784。此数字可能碰到业务 Flow 的 key。未完成双向同步时，flush 还会把大多数数据帧重新入队并返回，见 368-370。稳定且双方已完成同步时，这不是持续发生的路径；必须采集 `peerDone` 和 `localDoneAck` 才能排除同步因素，单独采集 carrier 字符串不够。

### 3.3 TCP retained chunks 也会再次入队

`session.go:752-758` 对未被 StreamAck 覆盖的 chunks 每隔至少 500 ms 再次入队；该循环也适用于 TCP carrier。`ack` 在 787-800 释放 retained chunks，但不清理已经入 scheduler 的 StreamData 副本。

若 ACK 处理或 carrier 写长期停顿，副本可能增加 backlog。这是可能扩大迟延的实现机制，并非此次 WAN 已确认的原因。本文不提议在冻结期间重写重传或调度策略。

## 4. 接收、重组和 target bridge

`session.go:123` 的 incoming channel 容量为 128。`deliver` 在 293-299 使用带 default 的非阻塞发送，channel 满时丢弃整个 record，未增加 `Stats.Dropped`。该方法既由每个 carrier reader 使用，也由服务端共享 UDP reader 使用。

因此，TCP carrier 的 socket 可靠传输不能阻止应用在 reader 到 actor 之间丢 record。TCP StreamData 有其 retained chunk/ACK 机制，UDP Datagram 没有等价的补发路径。`Stats.Dropped == 0` 不能排除 incoming 饱和导致的 UDP 丢弃。是否在本次 WAN 发生，仍需证据。

入站数据报的其他边界如下：

- `flow.go:55-63`：每个 UDP Flow 最多缓存 32 个完成消息；达到上限会拒绝新消息。
- `flow.go:419-484`：重组、重复检测和完成消息入队；每 Flow 最多 8 个在重组消息、Session 最多 64 个，受总内存预算约束。
- `session.go:673` 和 765：1 秒清理只针对未完成的入站重组。它不是出站数据报队列 deadline，也不是完成消息的过期时间。
- `flow.go:117-155`：Read 先取已缓存消息，再处理 read deadline。probe 在 Read 前后检查绝对时间，避免旧消息或忙队列延长该次 exchange。
- `flow.go:338-418`：target→Flow 与 Flow→target 各有一个桥接 goroutine。target socket 没有设置 read/write deadline；UDP 一次 `conn.Write` 的错误会关闭 Flow，短写长度未单独检查。实际 UDPConn 通常整包成功或返回错误，不能据此认定发生短写。

Ticket 相关的 1 秒也不是阻塞等待：`ticket.go:188-192` 到时入队 TicketRefresh，不 sleep；仅服务端 issuer 执行，见 167-169；最终 Ticket 覆盖剩余会话寿命后返回，见 176-181。当前代码没有“每次刷新固有停顿 1 秒”的证据。

## 5. r7 split telemetry 的最小方案

先采集阶段，不先根据猜测改验收阈值。所有事件使用进程内 monotonic duration；跨主机时钟不能直接相减。跨端只按 direction、carrier generation、flow id 和 datagram id 关联，并分别报告各端局部耗时。

### 5.1 CLI 必要字段

每次 UDP operation 增加下列独立 duration，保留原 elapsed 和 timeout 判定：

| 字段 | 边界 |
|---|---|
| `stats_before_ms` | 前 Stats 的调用到返回 |
| `exchange_ms` | exchange 进入到返回 |
| `udp_write_ms` | UDP Write 进入到返回；失败前是否调用 Write 要另有布尔字段 |
| `udp_read_wait_ms` | Read 累计等待时间 |
| `stats_after_ms` | 后 Stats 的调用到返回 |
| `operation_elapsed_ms` | 原 udpStarted 到完成后观测，维持可追溯性 |
| `deadline_remaining_before_write_ms` | Write 前剩余绝对预算，可为零或负值 |
| `failure_stage` | `pre_write_deadline`、`write`、`read`、`post_read_deadline` 等固定枚举 |

继续保留 expected/received iteration、unmatched/late/unexpected、carrier/generation 前后值。不得因迟到回复修改上一 operation 的结果。若前 Stats 没返回，受阻期间不能依赖再调用 Stats 来定位 actor。

### 5.2 会话内部必要事件

诊断开关默认关闭，仅在受控实验或指定验收启用。事件至少记录：

1. UDP admission 请求、actor 开始执行、接纳/取消，包含 datagram id、分片数、scheduler 长度和字节数。
2. Datagram enqueue、pop，以及对应 carrier write 进入/返回、错误分类。
3. Framer 完成读取、incoming admission 开始/完成、actor 开始处理该 record。
4. Datagram 重组完成、pushDatagram 成功/拒绝、Flow.Read 取出。
5. 在受控 target fixture 中记录 bridge target.Write、target 收到/发出、bridge target.Read。
6. 在各 operation 边界通过正常 actor 命令保存 `active`、`peerDone`、`localDoneAck`，区分载体已选定和双向同步已完成。

内部事件按帧元数据关联，不记录业务 payload、会话凭证、Admission key、Ticket 或私有配置。CLI iteration 只描述已知的 probe 测试 payload。不要为诊断新增线上协议字段。

事件投递使用有界、非阻塞通道，异步写日志；不能在 actor、Flow lock 或 carrier writer 中同步等待日志消费者。记录 `telemetry_events_dropped`，一旦发生事件缺失，应把对应阶段结论标为不完整。未能观测 target 的真实业务流只能定位到 bridge 边界，不能把其余时间强行归因于 target 应用。

## 6. 真实 TCP 写阻塞回归方案

在 r7 的测试文件中复用 `session/rekey_runtime_test.go:59-140` 的真实握手 fixture 模式。`runtimeReady` 在 142-145 检查 `active && peerDone && localDoneAck`。另建 loopback UDP echo target，并先验证一包正常 echo。

为确定性故障注入，在并发 reader/writer 启动前为 TCP Conn 安装透明 `gateConn`，确保 Framer 实际使用它；只替换 `carrier.conn` 而让 Framer 保留旧 Conn 不会拦住写入。gate 通过原子状态和 channel 触发，初始透明，握手、同步和 Flow 打开完成后才 arm。等待必须在 test wrapper 内，不能放入 actor closure 代替真实 carrier write。

### 6.1 UDP admission deadline 与不得迟到提交

1. 向 sender actor 入队一条有效 Ping，等待 wrapper 的 `writeStarted` 信号，确认 actor 已进入同步 TCP write。
2. 另一 goroutine 设置 UDP deadline 为当前时间加 1 秒，调用 Write。
3. gate 保持到此次 UDP 调用约 1.2 秒后再释放，低于 carrier 2 秒写 deadline。通过 channel 判断进入/释放，不用固定 sleep 猜测状态。
4. r6 预期边界：UDP Write 可以一直等到 gate 释放，之后返回接纳成功，超出设置的 deadline。该方案尚未在 r6 执行。
5. r7 必须满足：UDP Write 在 deadline 附近返回 `n=0` 与 timeout；gate 释放且 actor 处理完已排队命令后，该超时请求没有增加 `messageNext`、没有进入 scheduler，也没有被 UDP target 收到。
6. 清除 deadline 后发送第二个不同请求，必须正常接纳并准确匹配，排除取消请求残留污染后续业务。

允许适度调度误差，判定应区分 deadline 附近返回与明显等到 1.2 秒释放后才返回；不要把 1 ms 精确墙钟比较作为 CI 条件。被取消请求的状态和 target 未收到事实是核心断言。

已有 `session/audit_test.go:42-60` 验证 TCP queued Write 取消后不迟到提交，可作为 UDP 同类回归的结构参考；它阻塞 actor closure，不足以代替上述真实 TCP 写阻塞试验。

### 6.2 Stats 吃掉预算的独立变体

复用同一个 gate。先记录 udpStarted，actor 受阻时调用 Stats，待 gate 释放后按原 deadline 执行 exchange。预期在 Write 前超时。该结果可确定性证明观测前置耗时的口径，不能自动认定 WAN iteration 46 是这一路径。

### 6.3 TCP incoming 背压与退出

使用完整、有效且可以逐个关联的 TCP record；握手和双向同步完成后，受控暂停接收端 actor 的出站 TCP write，让接收端 reader 仍可读。发送超过 incoming 容量的 record，目标是验证 reader 到 actor 的 admission，而不是让 UDP target 的 32 消息上限成为新的丢弃来源。

- 用受控 fixture 逐个消费完成消息，或在有效帧处理层统计顺序与数量，明确隔离 UDP 完成消息队列容量。
- incoming 饱和时，reader 应在有界 admission 处停读并把背压传回 TCP，不能 default 丢弃已经完整读取的 record。
- 释放接收端写 gate 后，已接收的 record 按原顺序交给 actor；计数完整。发送端可能因 TCP 背压等待，测试不能让发送和释放都依赖同一个同步 goroutine。
- 独立取消 Session context，或关闭被阻塞的 carrier，必须直接解除 reader 的 admission 等待；验证旧 generation reader 退出，随后新 generation 可以工作。
- 取消路径不能靠 `Stats()`、`s.call()` 或另一个 actor closure 解阻，也不能持有 actor、Flow、server map 或 candidate 的锁。双向 socket write 都被阻塞时，也应能通过 socket deadline、context/carrier close 收敛。
- gate、sender worker、reader worker 和 target worker 都有独立退出信号和超时上界，最后核对 goroutine/target 关闭，防止测试 cleanup 自己死锁。

调度队列的 FIFO 可另做小型 scheduler 用例验证。真实端到端测试不要在一个 UDP Flow 中伪造 StreamData/控制组合；命令和 ACK 会触发额外 flush，简单发送 400 帧不能保证得到 1 秒 tick-only drain。

## 7. 后续代码修复的精确范围与验收条件

### 7.1 UDP Write deadline

主要范围是 `session/flow.go` 的 UDP Write 和必要的 Flow deadline/写入串行化辅助状态，配套测试放在 `session`；沿用 `session/session.go` 的 `call` 取消/提交语义，只在回归证明存在不足时作小范围修正。不改线格式、Ticket、UDP 默认优先策略、切换协议或 scheduler 权重。

修复必须同时处理以下边界：

- 在等待 actor 前读取并应用 write deadline；已有过期 deadline 应在修改状态前返回 timeout。
- 如果取消先于 actor admission/提交，命令之后即使从 commands 中取出也必须成为 no-op。不能启动一个后台 Write 并仅让外层 select 返回 timeout；那会留下迟到提交。
- actor closure 的提交边界必须明确。提交前再次核验取消/当前 deadline，预算/Flow 检查在分配 datagram id 和入队前完成；完成 admission 的 datagram 返回接纳结果，不把已经提交的请求伪装成 `0+timeout`。
- 一个被取消或失败接纳的数据报不能留下部分分片，`messageNext`、scheduler 与 target 断言一起验证。若当前预检查不足以保证整包 admission，需要最小的预检查或批量提交机制，不能用发送残片作为成功。
- 空 UDP 数据报、16 KiB 边界、ErrClosed、ErrLimit 和正常重复调用继续保持定义明确。
- 当前 `writeMu.Lock()` 本身不接受 deadline。并发 UDP writer 等串行化锁也应受 deadline 约束；修复不能只覆盖单个 writer 等 actor 的情况。
- `SetDeadline`、`SetWriteDeadline` 会影响正在等待的操作。固定快照可以修复本次明确边界，但不能宣称完整满足 net.Conn deadline 语义；缩短、延长和清除待定 deadline 的行为必须明确定义并有回归。可使用独立 deadline-change 通知和可取消写入 admission，避免通过 actor 更新 deadline。

完整 deadline 语义的候选回归包括：已有过期 deadline；actor 受真实 TCP 写阻塞；commands channel 满；并发 writer 等串行化；等待中缩短 deadline；延长/清除后能够继续；取消先于提交后无迟到入队；正常接纳和下一包恢复。r7 采用固定 deadline 快照，只完成其中已授权的 admission 范围；动态 deadline 与串行化等待仍列为限制，见第 9 节。timeout 必须满足 `net.Error.Timeout()` 并可用 `errors.Is` 识别 deadline 错误。

### 7.2 TCP reader 到 actor 的背压

主要范围是 `session/session.go:293-313` 的 TCP record admission 和必要的 `session/carrier.go` 关闭通知，配套 TCP 背压/关闭测试。服务端共享 UDP reader 的 `session/server.go:278-304` 继续按有界、非阻塞方式分发，避免一个 UDP Session 堵住所有客户端。不能把通用 deliver 无条件改成阻塞发送。

建议的内部边界：

- TCP reader 读取一条完整 record 后，用有界、可取消的 channel admission 交给 actor；等待期间停止读取后续 TCP 字节，不持有任何 actor 需要的锁。
- select 应能直接监听 Session context 和 carrier 关闭信号。只监听 `s.done` 不足以在 actor 尚未退出时解除等待；carrier 更换/关闭也应释放旧 reader。
- carrier 关闭通知如需新增，应在 `makeCarrier` 初始化，在 `closeOnce` 内可靠关闭，并兼容现有手工构造的 state-test carrier。通知的发布不能需要先执行 actor 命令。
- stale generation 包仍由 `receive` 的 `s.current != p.c` 检查过滤；不要从 reader 无同步读取或修改 `s.current`、queue、Stats 来规避背压。
- TCP 错误事件的 admission 同样需要关闭/取消出口；不要在数据 admission 修好后留下 error send 的退出阻塞。
- 不通过取消 incoming 上限、无限缓存或为每包生成 goroutine 解决问题。维持有界内存与单 reader 顺序。

该修复保证 TCP reader 不因 incoming 饱和在本层静默丢 record，不能保证 UDP target、重组/完成消息队列或已过 deadline 的交换全部成功。真正的实时数据报在 TCP 上仍受 TCP HOL 约束，默认 UDP 和失败回退 TCP 的设计边界应如实记录。

## 8. 验收顺序与交付口径

先保留 r6 FAIL 及原始证据，再在 r7 增加分阶段 telemetry 和独立边界回归，完成两处修复后运行相应单测、race 和已要求的全量检查，最后重新执行严格 WAN 场景。

只有回归证明取消不迟到提交、TCP admission 不静默丢弃且退出无死锁，才能报告两处代码边界已经修复。只有新的严格 WAN 全部通过，才能报告该版本满足当前 WAN 验收。若仍有首包超时，按 split telemetry 定位到具体阶段，保留失败，不用关联修复、延长预算或某个潜在原因替代现场证据。

## 9. r7 本地已完成范围与未覆盖边界

本地修复修改 `session/flow.go`、`session/session.go`、`session/carrier.go`，新增 `session/transport_admission_test.go`。未改变线上协议或 generic `s.call` 语义。

### 9.1 已完成的实现

- UDP Write 在进入 admission 分支时读取 write deadline，已有过期 deadline 返回 `net.OpError` timeout；固定 deadline 作为 context 传给既有 `s.call`。
- actor closure 入口以及分配 datagram id、入队分片前再次检查 context 和绝对时间。提交前取消的命令不耗消息编号、不留下分片；提交边界获胜后的有限 actor mutation 完成，并返回真实接纳结果。
- 最大 `messageNext` 在修改状态前拒绝，避免溢出导致编号先归零再返回 ErrLimit。
- UDP 原有整包 conservative cost 预检查保留。在 Session 使用的默认 total-byte-only scheduler 限制下，这覆盖所有分片成本；没有新增特殊的 per-flow/per-class queue 限制。
- TCP 完整 record 与 read error 的 incoming admission 都使用有界等待，监听 Session context、Session done 和该 carrier 的关闭通知。每个 reader 等待时不继续读取 TCP 字节，也不持有 actor、Flow 或 server 锁。
- `makeCarrier` 初始化内部 closed channel；`closeOnce` 先发布关闭通知再关闭独立 Conn。不关闭服务端共用 UDP socket。手工构造、closed channel 为 nil 的 state-test carrier 保持兼容。
- TCP reader 在取消或 carrier 退休后返回；旧 generation 仍由 actor 的 current-carrier 比较过滤。UDP ingress 保持非阻塞 default 丢弃策略，未从 network goroutine 读写 actor 的 Stats 或 current。

### 9.2 修复前后可控回归

原始失败和修复后通过日志保存在 `verification/experiments/r7-transport/`，该目录不属于 Go 源码 manifest：

| 文件 | 证据 |
|---|---|
| `before-fix.log` | 真实 TCP gate 下 120 ms UDP deadline 未生效；约 260 ms 释放 gate 后返回 `n=1800` 且无 timeout，消耗编号并进入后续 echo。满 incoming 时完整 TCP record 丢失 |
| `after-fix.log` | 同一真实 TCP gate 回归在约 120 ms 返回 `n=0` timeout；释放 gate 后编号与队列没有迟到提交，下一包正确恢复。所有 Transport 用例通过 |
| `repeat-10.log` | 同一 Transport 回归组连续 10 次通过 |

本地完成 8 个 Transport 顶级测试，包含已有过期 deadline、满 commands、整包预算拒绝、最大 message id 不突变、空和 16 KiB 数据报、TCP 满 incoming 保留顺序、直接取消/关闭解阻、真实旧 reader 退出与新 generation 正常 admission、满 incoming 下 read error 退出，以及 UDP 入口保持非阻塞。`go vet ./session` 通过。

这些回归的 120 ms/260 ms 控制参数用于快速、确定性地复现 admission 边界，与 WAN 的 1 秒 operation 阈值不是同一实验。未在此把本地回归成功记作 WAN PASS，主验收另行运行全包、race 和严格 WAN。

### 9.3 明确未完成的范围

- write deadline 是本次操作开始 admission 时的快照。等待期间再调用 `SetWriteDeadline` 或 `SetDeadline` 的缩短、延长、清除，不会动态重建该已排队 context。
- 进入分支之前的 `writeMu.Lock()` 仍是原来的串行化锁；第二个并发 writer 等锁的时间不受其 deadline context 限制。因此不能宣称完整实现 `net.Conn` 的动态 deadline 和并发写入等待语义。
- 已提交数据报的出站 queue age、目标处理时间、TCP HOL、UDP 重组/完成消息缓存丢弃和保活/切换时限不在本次修复范围。保留 inactive UDP 分支现有的 best-effort drop 语义。
- 双端均因 incoming 饱和而反向 socket write 阻塞时，现有 2 秒载体 write deadline 仍是收敛出口；此次测试证明直接 context/carrier close 可以解除 admission 等待，未证明所有双向拥塞场景都在 1 秒内完成。
- r6 WAN iteration 46 的根因仍未确认。r7 的 split telemetry 和 WAN 结果应独立记录，不能从两处可控复现推断现场已经定位。
