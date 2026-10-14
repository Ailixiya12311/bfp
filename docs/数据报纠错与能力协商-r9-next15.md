# BFP 数据报纠错与能力协商 r9-next15（实验）

日期：2026-10-09。源码位于 `C:\Users\developer\Desktop\bfp\.staging\r9-next15`，父边界为 next14 attempt02 的 130 个 Go/module 文件与 manifest `6024b78c50fa3542e7a0ba03757e4c3c57162aa86b8b5fbf3be87a6c5a694abb`。这是一份候选实现说明，不是四类功能的最终验收或发布声明。

## 实际实现

next15 将 next14 的纯 XOR 核心接入 Session 的 UDP Datagram 收发。每条应用数据报独立作为一个 block，不等待其他消息、不跨消息分组。原始数据按该 Flow 在 OPEN 时固定的 `ShardSize` 分片；实际片数为 `max(1, ceil(total/ShardSize))`，不得超过 `MaxDataShards`。原始片继续使用原 Datagram 帧的 message ID、总长和片偏移；修复片带原始长度表和一个固定大小 XOR parity。

XOR 只恢复一个缺失的真实片。两个或更多缺片继续等待原始数据或到期，不产生伪造的恢复结果。原始消息是 UDP 整报尽力交付，FEC 不把它升级为可靠事务。TCP 字节流及其偏移、确认和 FIN 合同不变。UDP Flow 切换到 TCP carrier 后保留原合同与编号，但不发送额外 parity；旧数据报不会因为恢复而重播。

## 能力与开流合同

实验 wireVersion 仍为 3。Noise 认证的 capability offer/selection 新增可选 `CapabilityDatagramXORV1=4`；原 capability 1 仍必需，bit 2 仍保留为未知可选能力。默认 offer 仍是 `{"p":"class-announcement-v1","o":1,"r":1}`，没有默认为慢链路增加冗余。

双方显式支持时选择 bit 4。只有一端可选支持时不选择；将 bit 4 设为必需而另一端不支持时，握手拒绝。恢复只能精确复用首次选择，不能新增、删除或降级能力。选中 bit 4 固定以下数值边界，无需依赖尚未确认的二次协商：最多 32 个 data shards、一个 parity、单片最多 900 B、block 上限 28800 B、Session 最多 64 个未完成 block。应用 Datagram 仍另受 16 KiB 上限限制。

Go API 通过 `NegotiationConfig` 显式协商，再在 `protocol.Target.FEC` 提供版本化 profile。`FECProfile.MaxDataShards` 的 JSON 字段为 `max_data_shards`；它是上限，repair metadata 的 `DataShards` 是当前消息的实际数目。`DeliveryContract` 和 FEC Profile 在 OPEN 时校验并按值保存；API 进入 actor mailbox 前复制 Target 的可选指针，后续重试不读取调用方变更。未协商、超数值上限或将 FEC 请求用于可靠 TCP 流，在分配 Flow/消费编号/拨目标之前拒绝。

`protocol.FECCapability` codec 保留资源描述格式。frame kind 25 为该描述的实验保留位，目前 Session 不接受二次能力修改；当前实际协商证据来自 Noise offer/selection。frame kind 26 是已接线的 `DatagramRepairFrame`。新 kind 追加在旧编号之后。

## 认证、预算和生命周期

Repair 位于 AEAD 内部。接收方先打开当前 carrier 的认证 record，再解析 repair；同时校验外层与 metadata 的 Flow、message/block ID、generation 和方向一致。客户端到服务端为 Outbound，反向为 Inbound。所有长度必须与总长度、固定片宽和实际片数唯一对应；未完成开流、terminal Flow、错误方向、旧代次或未协商能力不能安装修复状态。

发送端一次构造 data 与 parity 全批，再做一次 `PushBatch`。字节、item、Flow、类别限额以及取消/截止均在编号和分类字节发布前检查；失败不留下半批。分类仅统计原始应用字节一次，修复片按该 Flow 的调度类别消耗发送份额。parity 记录计入现有实际 UDP packet ACK、拥塞和 pacer 预算，但不进入逻辑业务重传。

Data-first 和 parity-first 共用同一 assembly、messageHigh 和 completed 去重窗口。期限从首次片或 repair 到达起算一秒，重复输入不刷新；接收路径也立即检查过期，避免依赖下一次维护 tick。完成、冲突、过期均终止同一 message ID；最多每 Flow 8 个、Session 64 个 assembly。逻辑字节准入预留原始数据、seen、parity、解码副本、恢复临时分片及保守 slice 开销。Go 分配器、map 和内核 socket 的总 RSS 仍须实测，不能由这个局部预算推导总内存保证。

carrier attach 将未完成旧消息标为终止并清空 assembly；Flow 合同、唯一编号、分类和可靠流继续保留。RESET 与 Session close 同步清理 repair 状态，无新增后台 goroutine、永久身份或独立 FEC 缓存。

## 短时网络接入边界

next15 gateway 明确拒绝常见 fake-IP 池 `198.18.0.0/15`，即使 `AllowPrivate=true` 且显式 CIDR 允许也不例外。IPv4-mapped 输入同样拒绝。DNS 返回该地址时不拨号、不写入 Session 缓存；上游 Mihomo/sing-box 必须先还原域名或真实目标。

这项防护不实现 fake-IP allocator、反向 NAT、客户端 DNS 代理、TUN 或 IPv6 支持矩阵。临时 Session 地址空间与上游 fake-IP 池是不同资源。

## 验证与剩余工作

已执行的定向测试覆盖协议 codec、owner 单缺片/两缺片/乱序/重复/错域/到期/退役、握手选择与恢复、原子 batch 及合同指针冻结。owner 首轮有两个计数失败：空消息 parity 恢复未计数、assembly 容量拒绝未计 FECRejected；修复后原断言通过。首轮原工具输出截断，观察摘要明确保留这一证据限制；没有伪造完整 raw。

真实加密 UDP 定向样本已覆盖 1813 B 报文的一片实际密文丢失后恢复、目标仅收到一次、迟到原片不重复，以及两片丢失不恢复、实际一秒到期后迟到片不复活。它们验证该有限样本，不代替完整本地 gate、parser fuzz、独立 Linux race 或 WAN 验收。没有本候选新加坡上传或 WAN 业务场景。

第一次正式全量 gate 冻结 137 文件，manifest `f1e4dc42191660e25798dd16ae80b66eb836d2007f74accc7fd2c8d735d3e055`；16 包、445 顶层 PASS，但 Session 的 `TestTransportUDPRejectedAdmissionDoesNotMutate/buffer-limit` 失败，完整 test exit 1。vet、Windows/Linux 构建通过。该回归来自发送重构只检查队列容量、遗漏独立 Session 字节预算；修复为全批构造后累加每个 data/parity 的 record 成本，再与 `MaxSessionBuffer-queue.Bytes()` 比较。已有失败断言未改，另加大队列/小 Session 预算的 FEC 回归，定向通过。第一次 gate、原始日志、manifest 和二进制均保留；第二次完整 gate 使用新清单及不同二进制文件名，不能覆盖首次失败。

第二次正式 gate 仍失败：137 文件，manifest `2eb9026eac3b23460b457aef3cdc39f5b2facc6ab27681fc3d61ff9391c68a6d`；16 包、445 顶层 PASS，但 `TestBoundedCloseSimultaneousRequests/none` 失败，完整 test exit 1。独立 Session 字节预算回归通过，vet 与双平台构建通过。失败观察为 direction 0 已发出 Close 并让本地 Close API 返回 nil，却没有发送对端所需的 ACK；测试在该方向的断言终止，不能据此推断 direction 1 的最终结果。[原始日志](C:/Users/developer/Desktop/bfp/.staging/r9-next15/verification/r9-next15/local-gate-attempt02/go_test.log)、[摘要与清单绑定](C:/Users/developer/Desktop/bfp/.staging/r9-next15/verification/r9-next15/local-gate-attempt02/local-summary.json) 和该次二进制均保留。

同时关闭的时序问题来自独立 ACK 可先于本端 Close 到达：对端看到本地请求的 ACK 时尚不知道另一方也请求关闭，提前停止控制 owner，随后无法响应迟到的 Close。当前生产候选在仍需确认本端 Close 时，将 `[SessionClose, SessionCloseAck]` 按该顺序放进同一 AEAD record，使两帧不会被 UDP 重排。组合发送沿用 `nextRequest` 的请求退避，避免认证的重复对端请求以 ACK 响应节奏提前消耗全部请求次数；若下一次请求时间已不早于固定 deadline，允许尚在 deadline 内的短截止场景提前发送一次组合记录。请求和 ACK 各自的尝试次数在 I/O 前计入预算，完整写成功才发布本地 Close；实际记录字节只计一次。默认 3 秒关闭期限、单记录 332 B、累计 4316 B、最多 5 次请求和 8 次 ACK 的原上限均未扩大。

初版组合记录修复后的旧同时关闭 5 轮 PASS，以及 [close-order-attempt01 定向日志](C:/Users/developer/Desktop/bfp/.staging/r9-next15/verification/r9-next15/focused/close-order-attempt01.jsonl) 的局部 PASS，均保留为各自源码时点的历史观察。后续 `nextRequest` 节奏修复另行执行验证：[close-order-attempt02 原始日志](C:/Users/developer/Desktop/bfp/.staging/r9-next15/verification/r9-next15/focused/close-order-attempt02.jsonl) 为 17 顶层 PASS、0 fail，覆盖组合顺序、完整发布、失败写、退避、固定预算及短截止 ACK；[新节奏同时关闭原始日志](C:/Users/developer/Desktop/bfp/.staging/r9-next15/verification/r9-next15/focused/simultaneous-close-cadence-fix.jsonl) 为原运行时用例 5 轮 PASS。旧定向结果没有替代新源码验证。

第三次正式本地检查通过：冻结 138 个 Go/module 文件，manifest `b8e219ea619fe0378f014beaaa3370735568b9026d9337f6ace965c54612bed8`；完整 `go test -json -p 1 ./... -count=1 -timeout=180s` 为 17 包、454 顶层 PASS、exit 0，vet 与 Windows/Linux 构建通过，`source_unchanged=true`，耗时 176.321 秒。见 [attempt03 本地摘要](C:/Users/developer/Desktop/bfp/.staging/r9-next15/verification/r9-next15/local-gate-attempt03/local-summary.json)。摘要中的 `local_checks_pass=true` 只表示这些本地检查；整体 `pass=false` 与三个未验收/未发布标记保持，不将本地 PASS 等同于最终验收。前两次失败 manifest 仍绑定各自旧源码，原失败结论不改。

对同一 attempt03 manifest 的 `FuzzDatagramRepairDecodeCanonical` 执行了 5 秒、2 worker 的有界 parser fuzz，206642 次执行，PASS、exit 0、`source_unchanged=true`；见 [fuzz 摘要](C:/Users/developer/Desktop/bfp/.staging/r9-next15/verification/r9-next15/fuzz/summary.json) 与 [原始日志](C:/Users/developer/Desktop/bfp/.staging/r9-next15/verification/r9-next15/fuzz/repair-parser.log)。它仅覆盖该解析器的有限运行，不是完整 fuzz campaign 或独立安全审核。next15 洛杉矶 source-bound Linux race run `df694751c362311643bdf98946514c17` 已通过：17 个包、exit 0、无 DATA RACE 报告，owned 测试容器和临时目录已删除，receiver 前后快照 `unchanged=true`。138 个上传源码哈希与 attempt03 冻结清单一致，关联 Linux 二进制元数据匹配，当前源码及 next14 父边界未变。见 [race 结果](C:/Users/developer/Desktop/bfp/.staging/r9-next15/lab/runs/df694751c362311643bdf98946514c17/race-result.json) 与 [最终证据索引](C:/Users/developer/Desktop/bfp/.staging/r9-next15/verification/r9-next15/evidence-index.json)。新加坡/WAN 尚未执行；两次旧 gate 失败仍保留原结论，四类完成数量与三个 false 标记不变。 next14 的通过不继承到 next15。

尚需分类到 FEC profile 的部署配置/适配器桥接、混合类别开销与尾延迟实测、WAN 丢包与高 RTT/FEC 实验、长期资源压测、完整 close/recovery/READY 矩阵、安全评审与跨实现互操作。FEC 默认关闭，当前可通过 Go API 使用；CLI/SOCKS 尚未开放该扩展。四类仍为 2 类主体实现、2 类部分实现、0 类最终验收，`acceptance_complete=false`、`production_ready=false`、`released=false`。
