# BFP 分类协商 Stage B 实现门槛

日期：2026-10-08。状态：**设计与实施计划，尚未实现或验收 Stage B 能力**。

2026-10-09 状态补注：本文保留 next5 时点的实施门槛，不改写历史缺口。next6 已在独立 wire3 源码边界接入下列核心状态与传输路径；本地专项及冻结检查已有证据，完整验收尚未完成。当前实现、失败保留与尚缺门槛见 [分类协商StageB实现-r9-next6.md](C:/Users/developer/Desktop/bfp/docs/分类协商StageB实现-r9-next6.md)。

本文只读核对当前 `C:/Users/developer/Desktop/bfp/.staging/r9-next5` 的分类器、Session、协议与握手调用路径，提出下一源码边界的最小完整实施切片。本文不修改 next5，也不把next5 的传输验证解释为分类协商验证。`production_ready=false`、`released=false`。

分类与交付语义必须继续分离：本地规则和行为分类只影响发送调度与预算；TCP 保持字节流与 FIN/RESET 合同，UDP Datagram 保持 best-effort 合同，分类公告不能改变可靠性、重传、流控、目标 ACL 或目标连接。

## 1. 已核对的 next5 边界

| 对象 | 当前事实 | Stage B 缺口 |
|---|---|---|
| wire 门槛 | [bootstrap.go](C:/Users/developer/Desktop/bfp/.staging/r9-next5/session/bootstrap.go:20) 的 `wireVersion=2`；[prologue](C:/Users/developer/Desktop/bfp/.staging/r9-next5/session/bootstrap.go:78) 固定为 `bfp/v2-udp-ack1/...`，初次与恢复握手都绑定该值 | 没有分类公告能力/profile 的认证选择与恢复固定 |
| 初始握手 payload | [bootstrap.go](C:/Users/developer/Desktop/bfp/.staging/r9-next5/session/bootstrap.go:141) 调用 `hs.WriteMessage(nil)`；[sessionInfo](C:/Users/developer/Desktop/bfp/.staging/r9-next5/session/bootstrap.go:33) 无分类能力字段 | 没有 offer、required、selected profile/capability |
| 本地类别 | [classification.go](C:/Users/developer/Desktop/bfp/.staging/r9-next5/session/classification.go:66) 在 Observe/Tick 后设置 `effectiveClass`；classification.Update 已提供 Changed | 类别变化没有 TX version 和公告状态 |
| ClassUpdate | [frame.go](C:/Users/developer/Desktop/bfp/.staging/r9-next5/protocol/frame.go:44) 保留 kind 14；[Session 分支](C:/Users/developer/Desktop/bfp/.staging/r9-next5/session/session.go:1536) 作为 legacy no-op 消费 | 没有新版字段校验、announcement、精确 ACK 或 peer-view |
| 查询 API | [FlowClassification](C:/Users/developer/Desktop/bfp/.staging/r9-next5/session/classification.go:14) 只返回 LocalTX、ID、Network、Terminal | 没有 PeerTXAnnounced、已发布/已确认版本与 pending 状态 |
| 恢复 | [flowSnapshot](C:/Users/developer/Desktop/bfp/.staging/r9-next5/session/session.go:86) 有字节、信用、OpenResult、FIN/RESET 与 ar/mr/or；[生成路径](C:/Users/developer/Desktop/bfp/.staging/r9-next5/session/session.go:480) 无类别状态 | 没有 TX class/version 的快照与统一 peer-view merge |

设计依据是 [分类器接入方案](C:/Users/developer/Desktop/bfp/docs/分类器接入方案.md:180) 第 9–11 节；[分类器接线实现-r8](C:/Users/developer/Desktop/bfp/docs/分类器接线实现-r8.md:105) 明确 Stage A 不承诺版本化公告、ACK、peer-view 与能力协商。早期方案对 legacy ClassUpdate 行为的描述属于当时审查，当前 next5 的实际分支已经是 no-op。

## 2. 最小完整实施切片

下一源码边界应一次包含：认证 wire/profile 门槛、每端独立的 TX 版本与已发布状态、announcement/ACK 的有界合并重试、只读 peer-view、恢复快照 merge，以及覆盖这些路径的真实加密承载验收。只有增加 ClassUpdate 收发分支，或只有增加快照字段，都不足以承诺 Stage B 收敛。

建议新增纯状态模块管理每 flow 的最新公告；Session actor 是唯一调用方。每个存活 flow 至多保留一份 pending TX announcement 与一份待发送 ACK，不保存无限历史 operation。首次有效状态版本从 1 开始，每次实际本地 TX 类别变化增加一次；同类别 Tick、查询、排队、重试和换承载不增加版本。

客户端应在成功安装 OpenResult 后开放首次公告；服务端可在成功结果获得安装 receipt 后开放首次公告，以证明对端已经安装该 flow。此前已经产生的本地类别变化合并到最新版本，不阻止本地业务调度。失败 OPEN、未知 flow、reset/terminal flow 不创建公告状态或复活目标。版本到达 `MaxUint64` 后不得回绕；显式终止该 flow，沿用有界终止记录。

## 3. wireVersion 3 与认证能力/profile 绑定

新版 ClassUpdate 语义和新增恢复字段应提升到 **实验 wireVersion 3**，并使用新的、固定的 Noise prologue，例如 `bfp/v3-class-announcement1/...`。该名称是候选合同，实施时须同时冻结客户端、服务端、初次/恢复握手和测试向量；不在 next5 的 wireVersion 2 上静默改变 kind 14 的含义。

最小认证协商建议如下：

1. 在 Noise 首个认证 payload 内放有界的 `profile`、`offered_capabilities` 与 `required_capabilities`。服务端不再丢弃 `ReadMessage` 的 payload；必须完成结构校验和设备/恢复授权后选择能力。无须新增可识别的明文帧。
2. 服务端在 Noise 加密的 sessionInfo 中返回 selected profile/capability。客户端验证 selected 是 offered 与服务端支持能力的交集，且覆盖 required；profile 不匹配、未知 required bit 或选择未 offer 的能力均失败。
3. 首个切片要求 `class-announcement-v1` 能力。缺失必需能力时明确结束候选，不静默退回 legacy 命令语义。现有 challenge/channel binding 确认必须绑定包含 offer 和 selection 的 Noise transcript。
4. Session 固定保存所选 profile/capability。恢复握手必须证明采用同一选择；不能因新承载、配置改变或重试而降级、增添能力或重新解释类别字段。相同 attempt 的并发 UDP/TCP 候选不得提交两个不同能力的 Session。
5. wireVersion 2 与 3 必须明确拒绝混用；旧实现没有新版能力时不得收到新版公告。bootstrap 上限、UDP 首包 1200 B 和确认前反放大预算仍须通过原有检查。

wireVersion 3 本身提供新旧语义隔离；上述认证 offer/selection 另外提供显式能力验证。不能仅在普通 JSON、CLI 配置或 README 中写“支持分类协商”，就把它视为 transcript 绑定完成。

## 4. announcement、ACK 与 peer-view 的固定合同

| 字段 | announcement | ACK |
|---|---|---|
| Kind | ClassUpdate，kind 14 | ClassUpdate，kind 14 |
| Flags | 0 | 1 |
| Flow | 已建立 flow | 同一 flow |
| Offset | 本端 TX version，非零 | 被确认的 TX version |
| Value | 本端 TX class，完整 u64 在 0–2 内 | 同版本、同 class |
| Data | 空 | 空 |

必须先校验完整 u64 范围再转换到 protocol.Class，避免 `256` 截断成 Interactive。非法 Flags、version=0、非空 Data 和非法 class 不修改状态，按经认证的协议错误明确处理。

所有公告和恢复类别快照共用一个 actor-owned peer-view merge 函数：新版本更新 PeerTXAnnounced；同版同类幂等；旧版不回退；版本跳跃允许；同版不同类是冲突。对端即使公告 Interactive，也只改变对端 TX 的观察视图，不能改变本端 classifier、effectiveClass、baseline、HighestAllowed、累计唯一业务字节、信用或 ACL，不能诱发反方向类别修改链。

ACK 只能完成**已经成功写入认证承载并发布**的精确 `(flow, version, class)`。排队或写失败不算发布；旧 ACK 不清除新 pending，未来/未发布版本或同版不同 class 不接受。重复相同公告重新回 ACK，ACK 自身不要求 ACK、不独立无限重试。接收旧公告时可回该输入的精确旧版本/类别，避免通过快照得知的较新状态产生发送方尚未发布的“未来 ACK”。

建议 actor 查询 API 分开返回 LocalTX、LocalTXVersion、LocalTXPublished、LocalTXAcked、Pending，以及带 Known 标识的 PeerTXAnnounced `{Class, Version}`。Class=0 本身是合法 Interactive，不能用零值表示未知，也不能把未确认公告写成已验证的本地调度状态。

## 5. 两个实现陷阱与预算要求

**既有 latest-control 表不能原样承载类别。** [validKey](C:/Users/developer/Desktop/bfp/.staging/r9-next5/internal/latestcontrol/table.go:96) 不接受 ClassUpdate；[Update](C:/Users/developer/Desktop/bfp/.staging/r9-next5/internal/latestcontrol/table.go:118) 对业务信用/偏移要求 Value 单调，并在 [该判断](C:/Users/developer/Desktop/bfp/.staging/r9-next5/internal/latestcontrol/table.go:142) 拒绝 `value < previous`。类别可从 Bulk=2 恢复到 Normal=1 或 Interactive=0，只有 version 单调，class 值并不单调。把 ClassUpdate 接入原表会拒绝合法恢复，或为了修复类别而错误放宽信用/StreamAck 不变量。

建议独立的有界 class-announcement 状态表；也可对既有模块增加严格按 kind 区分的语义策略，但必须保留原信用/偏移规则，并为类别 ACK 保存精确 class 证明，不能只比较 revision。原 `internal/operation` 每个版本建一个不可变 key 会累计历史项，不能作为无界类别变更表使用。

**控制路径需要独立队列身份。** [enqueue](C:/Users/developer/Desktop/bfp/.staging/r9-next5/session/session.go:587) 使用 `queue.Push(f.Flow, ...)`，同 flow 的控制和业务共享 FIFO。仅将 ClassUpdate 标为 Interactive 仍可能排在该 flow 已排队的 Bulk 数据后。新增公告/ACK 应用独立、有限的控制队列身份，或由有界 class 表直接选择控制项；不能用可能碰撞业务 flow ID 的任意“保留整数”替代类型边界。

这些控制仍必须进入真实 record 成本、UDP pacer/cwnd/flight 和现有有限控制份额；新增机会应共享控制预算，不能每增加一种控制就无限增加优先发送机会。每 flow/key 至多一份排队引用，发送时读取最新版本；ACK 可合并。保留最多 8 次实际 retry 与固定 no-progress 时限的候选预算，更新版本、换承载和普通业务不得刷新仍 pending 状态的原始无进展起点。耗尽应明确挂起/恢复或终止，而非无限重发；验收须冻结最终耗尽策略。

UDP lost/PTO 重建路径 [resolveRef](C:/Users/developer/Desktop/bfp/.staging/r9-next5/session/udp_transport.go:109) 也须识别新版公告，只取当前最新状态，不能补发过期类别；TCP 完整写成功后使用逻辑 ACK 期限，不重传业务数据来模拟公告确认。类别控制、ACK、重试、padding 和恢复均不进入分类器唯一业务字节计数。

## 6. 恢复 merge 与业务开放

在协商该能力的 flowSnapshot 中增加发送方自己的 TX class/version。建议用一个有存在性标志的嵌套状态，避免合法 class=0 与字段缺失混淆；严格 JSON 解码与 wireVersion 3 一并冻结。接收快照调用同一 peer-view merge，不创建本地可信 Hint，也不重建本地 classifier。

attach 保留本端 classifier、baseline、业务累计量、TX version/acknowledgement 与 peer version；只清除当前 carrier 排队/transport scope。可靠业务补传按本端当前类别排队，不能再次 Observe。快照 receipt 只有在成功应用其全部恢复字段后才能发送；但快照应用本身不自动消耗精确 ClassUpdate ACK 的 publication 证明。

固定 flowSnapshot 之后发生的类别变化继续保留最新 pending。双方恢复 Done 完成后重新发送该最新公告并有限收敛；无需把类别塞进当前 ResumeDone dirty-credit 列表，因为其 Value 单调性与信用不同。类别公告 ACK 不作为新的业务开放条件，不改变现有 ResumeDone 的信用/字节/控制 barrier。当前 [syncAllowed](C:/Users/developer/Desktop/bfp/.staging/r9-next5/session/udp_transport.go:478) 不允许 ClassUpdate 在恢复完成前发送，应将恢复策略写明确，避免候选实现互相等待。

## 7. 必需测试与验收证据

| 门槛 | 必须证明的结果 | 证据类型 |
|---|---|---|
| wire/profile/capability | v2/v3 拒绝混用；不 offer 不选择；required 缺失失败；修改选择无法通过 Noise/channel binding；恢复不能降级 | 真实初次与恢复握手测试，固定编码/向量 |
| 本地版本 | 初始版本 1；仅实际类变化递增；Bulk→Normal/Interactive 合法；查询/重试/attach 不递增；版本不回绕 | owner-confined 虚拟时间状态测试 |
| 发布与精确 ACK | 排队/写失败不发布；ACK 丢失后重复请求重新回执；旧/未来/未发布/同版异类 ACK 不清新 pending | 状态表测试及真实加密 UDP/TCP 测试 |
| peer-view 安全 | 高优先级公告只更新 PeerTXAnnounced，不改 LocalTX、cap、ACL、信用、字节累计或 target | actor 快照前后对比、目标连接计数 |
| 乱序与冲突 | 先新后旧不回退，同版同类幂等，同版异类拒绝；未知/terminal flow 不分配状态、不 redial | 加密承载注入与终止回归 |
| 控制与预算 | 每 key 引用有界；Bulk 队列不能长期阻塞公告/ACK；不绕过 pacer/cwnd；版本更新/切换不续期；耗尽显式结束 | 虚拟时间、队列负载和预算测试 |
| 恢复收敛 | UDP→TCP 保留 classifier/version/counters/目标连接；快照不覆盖本地 TX；快照后最新变更最终获精确 ACK | 带丢公告/丢 ACK 的真实恢复测试 |
| 双机样本 | 两方向初始公告、Bulk 降级与恢复、缺失 ACK 重试、UDP→TCP 后 peer-view 最终一致；Session/目标不重建 | 新加坡→洛杉矶专项 run，freeze manifest/binary/config |

专项 WAN 应输出无秘密的 LocalTX/PeerTXAnnounced、版本、published/acked/pending、唯一业务字节、carrier generation、Session/目标连接保持和有界 retry 统计。不能用端到端带宽比例作为状态正确性的唯一判据，也不能把 Stage B 的收敛结果替代后续混合类别 fairness/goodput/p95/p99 验收。

纯模块、真实加密承载和恢复回归通过后，再运行适当的完整 Go test/vet、Linux race、双平台构建与专项 WAN。结果必须绑定新的源码清单、二进制、wireVersion 3、能力选择和 run ID；保留原始失败，不放宽既定传输 deadline 来制造通过。next5 的既有 race/WAN 不覆盖本实施计划。

## 8. 实施完成判据

只有认证能力/profile 门槛、announcement/ACK、精确发布证明、peer-view、独立控制预算、恢复 merge 和上述验收均有对应当前源码证据，才可把 Stage B 标为完成。本文目前仅冻结下一步实施要求；尚未增加 wireVersion 3、能力协商或分类公告能力。TUN/fake-IP/IPv6/DNS、原生 Mihomo/sing-box outbound、混合类别长期性能与独立安全评审仍有各自门槛，不能由 Stage B 完成自动推导。
