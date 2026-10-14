# BFP 独立协议技术文档 v0.1-r9

当前产品入口为 [根项目说明](../README.md) 和 [Mihomo 原生接入](Mihomo原生接入-v0.1.md)：独立协议包 preview.5、当前原生接入包 preview.12 已生成。本文保留各阶段设计和历史候选边界；相应时点的“未发布 ZIP”及未实现条目不能直接当作当前交付状态，当前运行证据以产品记录为准。

**文档状态：** r9 实验候选的设计与实现说明，尚未冻结为跨实现标准，也没有经过独立密码审计。  
**编写日期：** 2026-10-08  
**协议定位：** 独立于 QUIC、VLESS、WireGuard 的新协议；直接使用 UDP/TCP 承载。  
**验证拓扑：** 新加坡 `198.51.100.20` 作为发送机/客户端侧，洛杉矶 `192.0.2.10` 作为接收机、出口机和测试机。

本文把当前 r9 候选已经实现的语义、线上格式、故障切换和验证边界写在一起。规范性文字中的“必须”是实现不变量；“应”是当前候选的默认行为；“实验”表示已经有测试或代码，但还不能作为生产保证。

**已冻结的 next4 验证边界：** `r9-next4` 在 `r9-next3` 之后加入承载代次 operation 淘汰、TCP operation deadline 调度、有证明条件的 KeyUpdate 旧 epoch drain，以及 Session-level ResumeDone v1 状态/回执对齐、重复请求重新回执和单调 barrier supersede。该边界包含 88 个 Go/module 文件，ResumeDone 定向测试、vet、Windows/Linux 构建、独立 Linux race 和新加坡→洛杉矶三场基础 WAN 通过。该边界最新完整本地测试仍因活动 UDP blackhole 切换时序失败；最新 Ticket lifecycle WAN 因 UDP→TCP 场景一个 Datagram 未回包而严格失败，虽然三场 lifecycle gate 均通过。所有失败证据保留，具体边界见第 11 节。它仍是实验候选：`production_ready=false`、`released=false`，没有制作发布 ZIP。

**已冻结的 next5 诊断候选：** `r9-next5` 从 next4 的冻结清单复制，只增加恢复诊断和确定性回归，未改变生产 UDP 故障策略或原 8 秒集成测试期限。本次本地完整测试、vet、双平台构建、独立 Linux race 和基础双机 WAN 通过，Ticket lifecycle WAN run `cb7508814cd7c798b6dc8f83778df153` 本次通过：三场 TCP/UDP 均为 20/20，均安装 3 次刷新并跨过 12 s TTL；initial UDP blocked 的 elapsed 为 12005 ms，仅超过 gate 5 ms，只证明该有限样本。随机探测、清理及快照比较通过。next5 的一次通过不能回填 next4 的失败；状态与证据见第 11.6 节。

**当前 next6 分类公告候选（2026-10-09）：** `r9-next6` 在独立源码边界提升为实验 wireVersion 3，使用 `bfp/v3-class-announcement1/...` prologue，并在 Noise 认证载荷内协商、固定 `class-announcement-v1` / capability 1。版本化 TX 公告、完整写成功后的精确发布证明与 ACK、只读 peer-view、独立分类控制选择、恢复快照 merge 已接线；分类不能改变本地规则、信用、可靠性或目标连接。冻结清单为 98 文件 / SHA256 `055490ea2724f05796e24d2654236dcb6bdb4126e64125535d50c86865d3ce8e`，本地冻结完整测试为 16 包、320 顶层 PASS，vet 与双平台构建通过。首轮原 8 秒活动 UDP 黑洞失败仍保留；最终单次通过不证明时限策略已修复。独立 Linux race、双机专项样本及尚未完成的门槛分别记录在 [next6 实现与验收边界](C:/Users/developer/Desktop/bfp/docs/分类协商StageB实现-r9-next6.md)，不以 next5 证据替代。`acceptance_complete=false`、`production_ready=false`、`released=false`。

**当前 next25 检查点（2026-10-10）：** 项目根目录已晋级为 next25，199 个 Go/module 文件与冻结候选一致；本地 639 项顶层测试、vet、Windows/Linux 构建、实际 CLI DNS UDP/TCP→同一临时地址→SOCKS→加密 BFP→TCP echo 通过。绑定 next25 的 Mihomo 真实 fork 已完成目标代次与事务发布修复的本地验证。洛杉矶独立 Linux race run `5d31a139671ccfc66a5cc0877a7a5591` 已完成：编译准备与完整 race 均 exit 0，20 个有测试包 + 2 个无测试包全部有终态，638 项 Linux 顶层测试通过且无 `DATA RACE`；源码/二进制绑定未变、owned 清理与接收机快照比较通过。证据见 [race 结果](../.staging/r9-next25/lab/runs/5d31a139671ccfc66a5cc0877a7a5591/race-result.json) 和 [next25 证据索引](../.staging/r9-next25/verification/r9-next25/evidence-index.json)。系统 DNS/TUN/IPv6、客户端承载路由排除和新 WAN 仍未验收，旧严格 FAIL/timeout 保留。当前配置、证据与边界见 [next25 说明](客户端DNS与目标生命周期-r9-next25.md) 和 [实现进度](实现进度.md)；本文旧版本验证段落保持各自历史范围。

## 1. 目标与边界

**2026-10-09 后续验证状态：** 同一冻结 next6 二进制的分类 WAN run `387c7e9fd1f9ff07c43cc1ead2ca355a` 中，normal UDP 为 47/50，`tcp_exchange` 失败；UDP→TCP 为 50/50，但 idle 分类恢复未在 35 秒内完成；初始 UDP blocked 转 TCP 为 50/50，CLI 检查通过。主采集中断后仅补执行此前未启动的场景，两端 owned cleanup 完成；本次 before 快照未落盘，整体验收保持失败。next7 只新增一个真实恢复/分类丢帧测试文件，生产源码和两平台二进制与 next6 相同。新 5 顶层/7 叶子场景通过，完整 Windows gate 为 324 顶层 PASS、1 个 UDP 端口 setup 失败；自然退避与显式 loss signal 分开解释。详细证据见 [next6 实现](C:/Users/developer/Desktop/bfp/docs/分类协商StageB实现-r9-next6.md) 和 [next7 验证](C:/Users/developer/Desktop/bfp/docs/分类恢复丢帧验证-r9-next7.md)。新加坡链路较慢是后续实验负载约束，当前尚不能据此断言全部失败来自网速。

BFP 建立一个短时、会话级的逻辑网络。一次握手完成设备认证并提交一个 Session；之后同一 Session 内的多条 TCP 流和 UDP 数据报共享会话认证、出口映射和恢复状态。承载只是 Session 的传输路径，不能拥有流或目标连接的所有权。

协议的初版目标是：

1. 默认优先用 UDP 建立和承载业务。
2. UDP 建连失败或活动路径失效时，使用同一服务器的 TCP 恢复同一 Session。
3. 切换保留 Session、Flow、目标连接、字节偏移、分类状态、控制 revision 和恢复期限；应用只经历有限等待。
4. 一次握手认证后，Session 内的业务帧不重复做设备认证；记录仍逐条做 AEAD 完整性和防重放检查，并按策略更新密钥。
5. 流号、帧类型、目标和临时地址均放入加密内部；未通过准入和握手的输入不产生应用层响应或目标连接副作用。
6. 每条流在打开时确定类别，之后可由本地行为分类器在有迟滞的条件下升级或降级；分类只影响调度与预算，不改变可靠性合同。
7. Session 结束时销毁临时网络上下文、流表、出口映射、DNS/重组缓存和恢复资格，不把 Session 地址变成长期身份。

当前明确不属于基础 v0.1 的能力包括：自动 TCP→UDP 回切、跨进程重启后恢复目标 socket、mesh/二层局域网、原生 Mihomo/sing-box outbound、COVER/SHAPED 交通仿真和“完全不可识别”的流量分析保证。FEC 是默认关闭的候选扩展；next15 已接入可选能力和认证 Datagram repair，next16 又接入按类别的 CLI policy 选择，不改变可靠字节流合同，实际证据和边界见 [next15 说明](C:/Users/developer/Desktop/bfp/docs/数据报纠错与能力协商-r9-next15.md) 和 [next16 说明](C:/Users/developer/Desktop/bfp/docs/分类到FEC策略接线-r9-next16.md)。

## 2. 四个重点在设计中的位置

| 重点 | 设计落点 | 当前 r9 状态 |
|---|---|---|
| 认证复用 | 一次握手提交 Session；Session 内所有记录用方向密钥认证；key epoch 有界更新；断线用恢复秘密和 Ticket 快速重新绑定同一 Session | 主体已实现：首次 Noise、多 Flow 复用、定期密钥更新、Ticket 生命周期及同 Session/目标连接恢复已接线，有本地和双机选定证据。稳定的原 8 秒故障恢复合同和完整控制故障组合仍未验收完毕 |
| 伪装与混淆 | Session、Flow、kind、目标、类别、偏移和地址只在 AEAD 内；外层使用随机句柄、受保护 header、LIGHT 长度封装和随机 padding；未认证输入静默处理 | 基础主体已实现：首包准入、header protection、LIGHT、随机 padding、未认证输入无应用层响应，有本地及历史双机随机探测证据。长期主动探测/流量分析与独立安全评审仍待做；不宣称隐藏端口或不可识别 |
| 协议内分流 | OPEN 初始类别、本地可信元数据和行为窗口/迟滞；Interactive/Normal/Bulk 独立调度份额 | 部分实现：分类/公告/恢复、CLI 规则、按类别 Datagram XOR repair、受信本地 metadata 已接线；真实 Mihomo/sing-box 原生 fork 有局部验证，next25 又补 Mihomo UDP 目标代次与 Prepare/Commit/Abort。完整宿主元数据矩阵、混合类别性能和 FEC WAN 未完成 |
| 短时局域网 | Session 的临时地址/Flow ID，所属出口连接、DNS/映射缓存与恢复资格在终态回收 | 部分实现：临时地址、会话到期、出口 socket 与状态回收、Session 私有 DNS cache、客户端 fake-IP/A 前端已有实现；next25 CLI 把 DNS UDP/TCP 与 SOCKS 接到同一 Session，actual echo通过。系统 DNS/TUN、AAAA/EDNS、IPv6 系统入口和完整资源验收未完成 |

按最初四类的功能范围，当前计为 **2 类主体实现、2 类部分实现**；按所有验收门槛通过的严格口径，**0 类可以标记最终验收完成**。该计数用于功能状态，不把测试数折算成完成百分比。后续实验按用户说明的新加坡慢链路控制并发与负载，保留原失败，不扩大既定业务期限。

**next8 进展（2026-10-09）：** 新的 Session DNS scope 在 fresh confirmation 后创建、同会话恢复复用、终态清空，迟到解析或拨号结果被拒绝。真实 UDP 加密 Flow → 数值 TCP echo 联动测试首次发现 Client.Close 先取消 Session 父 context、导致关闭通知未发出的问题；修复为先取消建连/恢复操作，保留当前 Session 执行关闭通知，再取消其生命周期。原测试源码和 5 秒业务／1 秒清理观察期限不变，变更后单次通过两个 fresh Session、两个隔离缓存、两次解析和三个独立目标连接。首次失败保留；全量本地、构建与 Linux race 结果另见 [next8 实现与证据](C:/Users/developer/Desktop/bfp/docs/会话DNS与传输诊断实现-r9-next8.md)。该测试不提供 UDP 关闭通知丢失时必然及时回收的保证。

**next9 进展（2026-10-09）：** 构造器直接保有 TCP 与同号 UDP socket；仅请求临时端口时对第二协议候选不可用做最多 16 次内部选择，三个夹具不再预选并释放后重绑。冻结 111 文件，正式本地 363 顶层、vet 和双平台构建通过。撤销、寿命到期、服务端取消的真实加密 UDP/数值 TCP 终态测试均通过；只有到期场景要求客户端实际 ErrClosed，另外两场的读超时不能证明客户端已终止。Linux race 程序 16 包通过；原严格 overall=false 保留，因为已有 Xray 动态 UDP socket 的前后快照变化，归属与 BFP owned 清理另行核对。无 next9 WAN 或新加坡业务负载；见 [next9 记录](C:/Users/developer/Desktop/bfp/docs/监听与会话终态验证-r9-next9.md)。[有界关闭实施方案](C:/Users/developer/Desktop/bfp/docs/会话有界关闭实施方案.md) 仍为待实现，不能据此把第四类记为验收完成。

**next10 关闭实现与失败门禁（2026-10-09）：** 有界 Close/ACK、独立控制预算、立即业务门禁及先清资源后回应已实现，冻结 117 个 Go/module 文件。但完整本地 test exit 1：14 包、193 顶层通过，Session 对缺少 cipher 的合成 TCP carrier 调用 Seal 后 panic，三个旧 gateway 行政终态用例的客户端 teardown 失败。DNS/目标原资源观察以及三个新增 DNS 关闭场景、默认黑洞场景在冻结完整运行中通过，不能使全套改判 PASS。vet 与双平台构建通过；没有 next10 Linux race 或 WAN。详见 [next10 实现与失败记录](C:/Users/developer/Desktop/bfp/docs/会话有界关闭实现-r9-next10.md)。next9 时点的“待实现”是历史状态，第四类仍未验收完成。

**next11 回归修复（2026-10-09）：** 从冻结 next10 全量同哈希复制，修复不完整关闭 carrier、区分 Client.Abort 本地 join 与 Close 远端确认，追踪被 fresh Session 替换的旧 drain owner，并使握手取消中断候选 socket I/O。定向回归通过，原 5/8/35 秒业务及 1 秒资源观察期限未增加。完整冻结门禁结果和后续边界见 [next11 记录](C:/Users/developer/Desktop/bfp/docs/关闭回归修复-r9-next11.md)；未完成引用收束、共享 UDP 严格阻塞界和全关闭矩阵，不把本阶段修复升级为四类完成。

**next11 冻结后续结果 / next12 修复中：** next11 冻结 120 文件，完整 test 命令在原 240 秒 helper 预算内未完成，原输出采集异常缺失 partial 日志，结果保持失败。独立 Session 逐行诊断在原 180 秒期限失败，定位旧虚拟传输时钟与现实关闭截止混用导致 `Close` 等待。next11 补执行此前未启动的 vet/双平台构建通过，无 race 或 WAN。next12 在新的父哈希一致边界分离关闭单调时钟和传输诊断时钟，详细证据与后续 gate 见 [next11 失败记录](C:/Users/developer/Desktop/bfp/docs/关闭回归修复-r9-next11.md) 和 [next12 时钟修复](C:/Users/developer/Desktop/bfp/docs/关闭时钟修复-r9-next12.md)。四类计数不因修复中或定向通过而改变。

**next12 最新完整本地结果：** 冻结 121 文件，manifest `a8523fb46443375cc5bc00a8f211f4f92b364bfff035dc91a62880d92de47634`；16 包、399 顶层测试、vet 和双平台构建通过，source_unchanged=true，175.253 秒，原有 test/helper 期限不变。原 3 秒关闭场和 50ms 诊断 episode 均保留；next10/next11 失败及新增测试首轮失败继续独立保存。独立洛杉矶 Linux race 已启动，当前没有新加坡负载或本版本 WAN。本阶段仍未完成全部资源引用和共享 UDP 阻塞界及完整故障/实网矩阵，四类计数保持不变。结果见 [next12 实现与证据](C:/Users/developer/Desktop/bfp/docs/关闭时钟修复-r9-next12.md)。

**next12 独立 Linux race 后续结果：** 洛杉矶 run `88bdb7339f7f6593cdd99d3e9269e98c` 的 16 个测试包通过、exit 0、无 race 报告；owned 容器/目录清理和原严格快照比较通过。121 个上传源码哈希及关联 Linux 二进制与本地冻结结果相同，源码在 race 后仍一致，见 [next12 最终证据索引](C:/Users/developer/Desktop/bfp/.staging/r9-next12/verification/r9-next12/evidence-index.json)。无该版本 WAN 和新加坡负载；此前各版本的本地/WAN/快照失败保持原结论。临时会话网络仍有引用收束、共享 UDP 阻塞界和完整矩阵未完，不能升级为最终验收。

**next13 会话资源退役实现与验证（2026-10-09）：** 从 next12 的 121 文件边界复制后，新增 command/incoming 发布门、私有 carrier reader registry 和独立 typed dial-result mailbox。所有已登记发布者在退休前退出；完整 TCP 队列、旧承载代次、迟到 reader、迟到/排队/取消后的目标连接都具有明确关闭 owner；共享 Server UDP reader 不属于 Session reader registry。backend/DNS scope 的 watcher stop 与 callback join 分离；首次 close intent 和直接 cancel 都先撤销 backend eligibility。Stats 在 control context 已停止但 actor 尚未发布 `done` 的窗口等待最终快照，避免返回零值观察。对外部 cleanup 或自定义 Conn 仍保留合作性契约限制：不能宣称任意永久阻塞回调或不合作 Conn 可被 CloseTimeout 强制终止。

next13 正式本地 gate 通过：125 个 Go/module 文件、16 个包、404 个顶层测试，vet 与 Windows/Linux 构建通过，source manifest `b446ee10ff967daf1bded5f7ace90ecd5f26c6226f6f163e5dafc4e026e30ca2`，见 [next13 本地证据](C:/Users/developer/Desktop/bfp/.staging/r9-next13/verification/r9-next13/local-gate/local-summary.json)。洛杉矶独立 Linux race run `09a74805d9f86838c7a6b141dc26eded` 通过，Go 1.27/GCC 12.2、16 包 exit 0、无 DATA RACE，owned 容器/目录清理且 receiver 前后快照 `unchanged=true`，见 [next13 证据索引](C:/Users/developer/Desktop/bfp/.staging/r9-next13/verification/r9-next13/evidence-index.json)。首次 race 的 SSH 收尾断线保留在同一 staging 的失败尝试目录；重试没有改变源代码。next13 没有新加坡上传和 WAN 业务场景，四类计数仍为 **2 类主体实现、2 类部分实现、0 类最终验收**；`acceptance_complete=false`、`production_ready=false`、`released=false`。

**next14 重传公平与共享 UDP 写 owner（2026-10-09）：** 在 next13 的 125 文件父边界上，Session 的 UDP 重传改为独立的 4:2:1 类别轮转和类别内 Flow 轮转；重传读取当前 `effectiveClass`，失效引用清理不占用重传槽位，写失败或预算拒绝不丢失 retry owner。Server 创建唯一共享 UDP writer，bootstrap/READY 和 Session 的共享 UDP 记录统一排队到该 owner；队列有上限，deadline 从提交时计算，Session close 只收紧自己的请求，不能改写 sibling 的 active deadline 或关闭共享 socket。private UDP 普通写也使用有界 deadline。合成 carrier nil guard 的回归已修复。

next14 另增加 `internal/fec` 的单丢片 XOR 核心：固定 data/parity/shard/block 上限、复制填充、原始长度裁剪和单缺片恢复，尚未接入能力协商或认证 Datagram wire。它不能改变可靠字节流合同，也不能单凭远端类别更新启用修复。

第一次正式本地 gate 保留一个运行中 UDP 黑洞恢复失败；不修改源代码的第二次完整 gate 通过：130 个 Go/module 文件、17 个包、412 个顶层测试，vet 和 Windows/Linux 构建通过，source manifest `6024b78c50fa3542e7a0ba03757e4c3c57162aa86b8b5fbf3be87a6c5a694abb`，见 [next14 本地证据](C:/Users/developer/Desktop/bfp/.staging/r9-next14/verification/r9-next14/local-gate-attempt02/local-summary.json)。洛杉矶独立 Linux race run `69913d6d52a84ed2c87ac2ba4f769158` 通过，17 包 exit 0、无 DATA RACE，owned 容器/目录清理且 receiver 前后快照稳定，见 [next14 证据索引](C:/Users/developer/Desktop/bfp/.staging/r9-next14/verification/r9-next14/evidence-index.json)。本阶段没有新加坡上传和 WAN 业务场景；四类计数仍为 **2 类主体实现、2 类部分实现、0 类最终验收**，`acceptance_complete=false`、`production_ready=false`、`released=false`。

**next15 数据报纠错接线（2026-10-09）：** Noise capability 新增可选 bit 4，默认仍只协商 class bit 1；恢复必须精确复用选择。OPEN 复制并固定 Delivery/FEC 合同，单消息分片与 XOR parity 一次队列提交。认证内部 Repair 绑定 Flow、方向、carrier generation 和 message ID；Data/Repair 共用一秒有界 assembly 和终止窗口，旧代次、重复、错域、过期、RESET 与 close 不得复活。Repair 消耗原 Flow 调度、实际 UDP 拥塞和 pacer 预算，不逻辑重传；TCP carrier 不发也不接受额外 Repair，可靠字节流不降级。fake-IP 保留网段 `198.18/15` 即使显式私网策略也拒绝直接出口拨号。

本地真实加密 UDP 定向样本已经证明：1813 字节报文的一片实际密文丢失后恢复、目标只收一次；两片丢失不伪造恢复，到期后迟到片不复活。定向首轮两个计数失败已修复并保留摘要。第一次正式 gate 因独立 Session 字节预算遗漏失败；修复后第二次 gate 的该回归通过，但 `TestBoundedCloseSimultaneousRequests/none` 失败，仍为 test exit 1，16 包、445 顶层 PASS，vet 与双平台构建通过。两次失败的原始日志、各自 manifest 和二进制均独立保留。

**当前 r9-next16 分类到 FEC 接线候选（2026-10-09）：** 在 next15 的认证 Datagram repair 上，客户端 CLI 增加 `datagram_fec` 的 `off`、`optional` 和 `required` 模式，以及按 `Interactive/Normal/Bulk` 选择 `off`/`xor1` 的 profile。选择发生在本地规则、可信 Hint 和类别 cap 之后、Flow 编号与目标拨号之前；显式 `Target.FEC` 优先，TCP 可靠流、行为降级、类别公告、UDP→TCP attach 和恢复均不重选已固定 profile。服务端只接受 capability mode，使用入站 OPEN 的 FEC 合同。profile 的 `max_data_shards` 为 1–32、`shard_size` 为 1–900，超过乘积的应用 Datagram 整体拒绝。配置解析拒绝未知/重复/case-alias/null/越界字段，错误不回显输入。详细接线和边界见 [next16 说明](分类到FEC策略接线-r9-next16.md)。

next16 冻结 143 个 Go/module 文件，manifest `64aea3d8982f3ff4a827ff347d10bed383477ea1cbdadacac66faf516b67c228`；完整本地测试 17 包、471 顶层 PASS，vet 和 Windows/Linux 构建通过，有限 repair-parser fuzz 通过。洛杉矶 source-bound Linux race `da9e492b398199fcbad740cb28bca91b` 通过，源码绑定、无 DATA RACE、owned 清理和接收机快照比较通过。一次小体量双机基线 `8f71118b9265c444a242f26066c77e43` 中，正常 UDP 与运行中 UDP→TCP 各 12/12，初始 UDP 阻断为 11/12 并触发 probe deadline，故 WAN 严格 FAIL；随机探测无应用响应，不能把该结果解释为 FEC WAN 验收。当前四类仍为 2 类主体实现、2 类部分实现、0 类最终验收，三个发布标记均为 false。

**r9-next17 受信本地元数据桥接候选（2026-10-09）：** 在独立复制的 next16 源码上新增 `LocalMetadataBridge`、local-only `Metadata.Application`/`Rule.Application` 选择器和 SOCKS fail-closed 接线。Bridge 清除来自 wire 的 Domain/RuleTag/Class；`WithTrustedApplication` 不写入 `protocol.Target`，真实加密 Session 测试确认 OPEN 不包含应用身份。Bridge 返回值深拷贝 Delivery/FEC/Hint；非法受信域名不调用后端。next17 冻结 146 个 Go/module 文件，manifest `9a6d248422f46de9945b22fb0b4de514855666d6b5015a555b525cab8fecbd79`；本地 17 包、475 顶层测试、vet、Windows/Linux 构建、有限 fuzz 和洛杉矶 source-bound Linux race `ff1b5a528f0e23ac0dde3921e53a2b07` 通过。该阶段没有新加坡/WAN 业务测试；证据见 [next17 文档](受信本地元数据桥接-r9-next17.md) 和 [证据索引](C:/Users/developer/Desktop/bfp/.staging/r9-next17/verification/r9-next17/evidence-index.json)。四类仍为 2 类主体实现、2 类部分实现、0 类最终验收，三个发布标记均为 false。

当前关闭候选将仍待确认的本端 Close 与对端所需 ACK 按 `[SessionClose, SessionCloseAck]` 合进同一 AEAD record，并按原 `nextRequest` 退避发送；下一次请求时间已不早于固定 deadline 时允许短截止场景提前发送组合记录。尝试预算在 I/O 前计入，完整写成功才发布 Close，不扩大原默认 3 秒、单记录 332 B、累计 4316 B、5 次请求和 8 次 ACK 上限。旧 5 轮与 close-order-attempt01 继续作为先前源码的历史观察；节奏修复另有 [close-order-attempt02](C:/Users/developer/Desktop/bfp/.staging/r9-next15/verification/r9-next15/focused/close-order-attempt02.jsonl) 的 17 顶层 PASS，以及 [同时关闭运行时日志](C:/Users/developer/Desktop/bfp/.staging/r9-next15/verification/r9-next15/focused/simultaneous-close-cadence-fix.jsonl) 的 5 轮 PASS。

next15 第三次正式本地检查通过：138 个 Go/module 文件，manifest `b8e219ea619fe0378f014beaaa3370735568b9026d9337f6ace965c54612bed8`；完整测试 17 包、454 顶层 PASS，vet 和 Windows/Linux 构建通过，`source_unchanged=true`，176.321 秒，见 [attempt03 本地摘要](C:/Users/developer/Desktop/bfp/.staging/r9-next15/verification/r9-next15/local-gate-attempt03/local-summary.json)。同一清单的 repair parser fuzz 以 5 秒、2 worker 执行 206642 次后 PASS，源码未变，见 [fuzz 摘要与有限范围](C:/Users/developer/Desktop/bfp/.staging/r9-next15/verification/r9-next15/fuzz/summary.json)。这不是完整 fuzz 或独立安全审核。next15 洛杉矶 source-bound Linux race run `df694751c362311643bdf98946514c17` 已通过：17 个包、exit 0、无 DATA RACE 报告，owned 测试容器和临时目录已删除，receiver 前后快照 `unchanged=true`。138 个上传源码哈希与 attempt03 冻结清单一致，关联 Linux 二进制元数据匹配，当前源码及 next14 父边界未变。见 [race 结果](C:/Users/developer/Desktop/bfp/.staging/r9-next15/lab/runs/df694751c362311643bdf98946514c17/race-result.json) 与 [最终证据索引](C:/Users/developer/Desktop/bfp/.staging/r9-next15/verification/r9-next15/evidence-index.json)。新加坡/WAN 尚未执行；两次旧 gate 失败仍保留原结论，四类完成数量与三个 false 标记不变。 历史通过不继承到新源码。详情见 [next15 说明](C:/Users/developer/Desktop/bfp/docs/数据报纠错与能力协商-r9-next15.md)。四类仍为 **2 类主体实现、2 类部分实现、0 类最终验收**，`acceptance_complete=false`、`production_ready=false`、`released=false`。

## 3. 分层架构

```mermaid
flowchart LR
    APP[应用 TCP/UDP]
    ADAPTER[SOCKS5 / 后续 TUN 适配]
    FLOW[Flow: target、class、offset、FIN/RESET]
    SESSION[Session: 临时网络、出口连接、凭证、恢复]
    TX[分类调度、流控、UDP ACK/PTO、latest-control]
    RECORD[Noise 派生方向密钥、AEAD、LIGHT、padding]
    CARRIER[UDP 首选 / 同端点 TCP 备用]
    GATEWAY[服务端 Session owner]
    TARGET[固定目标出口]
    APP --> ADAPTER --> FLOW --> SESSION --> TX --> RECORD --> CARRIER --> GATEWAY --> TARGET
```

### 3.1 核心对象

`Session` 是唯一的跨承载状态 owner。`Carrier` 只保存当前承载的 socket、record epoch、record number、UDP ACK history、sent ledger、RTT 和 PTO。`Flow` 保存目标、类别、双向字节偏移、接收缓冲、目标 socket、FIN/RESET 状态和逻辑控制 revision。

实现必须区分三个序号：

- `carrier_generation`：承载接管代次。一次 UDP→TCP 绑定使其递增，旧承载的记录和事件不能覆盖新承载。
- `key_epoch`：同一承载方向密钥的阶段。KeyUpdate 只允许有界的下一 epoch。
- `record_no`：该方向、该 epoch 的 AEAD record 序号。它只服务承载级防重放和 UDP 传输确认。

跨承载的业务去重使用 `flow_id + direction + byte_offset`；不能用 `record_no` 判断业务是否重复。

### 3.2 Session 状态机

```text
NEW
  └─(准入 + Noise + confirm)→ ATTACHED
      └─(双向 READY/ResumeDone)→ ACTIVE
          ├─(UDP 无进展)→ UDP_SUSPECT → TCP_CANDIDATE → ACTIVE(generation+1)
          ├─(显式 close / 到期 / 撤销)→ CLOSING → CLOSED
          └─(临时无承载)→ SUSPENDED → ATTACHED 或 CLOSED
```

`SUSPENDED` 只保留固定时间。默认 `RetainTimeout` 为 30 秒；重复候选、重复 READY、重复 attach 或收到普通控制帧都不能把这段期限重新计时。Session 到期后，旧 Ticket、恢复 secret、Flow 和出口 socket 一并失效。

## 4. 准入、认证与密钥

### 4.1 首次接入

首次连接使用 `Noise_IK_25519_ChaChaPoly_SHA256`。客户端固定服务端静态公钥，服务端检查授权设备公钥。准入 envelope 只负责把候选输入限制在有界范围；Noise 成功并不自动允许打开目标连接，仍须完成新鲜 challenge 和 `SESSION_CONFIRM`。

首次过程为：

1. 客户端生成随机 `attempt_id`，通过 admission envelope 发送 `init`。
2. 服务端验证准入、设备授权、重放窗口和资源限额，返回 Noise 响应及新鲜 challenge。
3. 客户端用新的方向密钥发送加密 confirm，绑定 challenge 和 channel binding。
4. 服务端原子提交 Session、Carrier、临时地址和出口权限，返回加密 READY。
5. 双方完成 ResumeState/ResumeDone 后才允许 OPEN、StreamData 和 Datagram。

确认前禁止 0-RTT 业务数据、DNS 查询、目标拨号和目标写入。相同合法重试沿用 `attempt_id`，服务端按“授权设备 + attempt_id”协调候选，避免 UDP 和 TCP 产生两个活动 Session。

### 4.2 恢复接入

恢复使用 `Noise_NNpsk0_25519_ChaChaPoly_SHA256` 和只属于当前存活 Session 的 32 字节 `resume_secret`。Ticket 是定位符，不是授权本身；恢复必须同时证明持有 secret、Ticket 未过期且绑定当前 Session、transcript 绑定新鲜 challenge/Session ID/候选承载/attempt_id/预期 generation，并且服务端仍持有该 Session。

恢复握手不会重新拨号已有目标，也不会因为客户端重试而增加 Session 寿命。新 Carrier 使用全新的 Noise 方向密钥和随机句柄；旧 Carrier 的 PacketAck、RTT、PTO 和 record ledger 不跨 generation 迁移。

### 4.3 记录加密与密钥更新

活动记录的外层逻辑为：

```text
opaque_handle(16B) || protected(epoch:u32, record_no:u64) || AEAD(body)
```

AEAD 使用 ChaCha20-Poly1305；body/header 通过 HKDF-SHA256 和用途标签分离。header mask 由 header key 派生，明文线上只保留必要的承载查找和受保护长度材料。每方向独立记录号；同一 `handle + epoch + record_no` 不复用。

KeyUpdate 是旧 epoch 内认证的逻辑操作。发送方在收到匹配的 KeyUpdateAck 前不能把提议当成已安装；接收方保留当前 epoch 和一个旧 epoch 的过渡空间。UDP 的旧 epoch ACK scope 必须在对应记录退役后才回收。

### 4.4 Ticket 生命周期

- Ticket 有固定绝对到期时间，可在健康承载上刷新。
- 刷新使用安装 ACK；旧 Ticket 只在有限 overlap 内有效，不能无限增加 alias。
- 刷新不会延长 Session 最大寿命，也不能用重试重新发行同一 serial 的更长 TTL。
- 设备撤销、Session 关闭、服务端重启或 Session 到期会使恢复资格失效。

## 5. 线上记录、帧与混淆

### 5.1 承载边界

- UDP 一个数据报最多一个加密记录，当前上限 1200 字节；UDP 应用整报最大 16 KiB，超过部分在内部 Datagram 帧中分片。
- TCP 使用带方向密钥的认证长度 envelope；一次完整记录必须先通过长度和 AEAD 检查，部分写入或解析错误直接结束 Carrier。
- 解密后的 plaintext 上限 16 KiB，最多 64 个内部帧。每个帧头固定 28 字节：`kind:u8 | flags:u8 | data_len:u16 | flow:u64 | offset:u64 | value:u64`。

字段、Flow ID、目标地址、类别、临时地址、恢复 Ticket 和业务长度都处于加密范围。外部仍可观察 IP/端口、承载类型、长度和时序；LIGHT 和 padding 只能降低直接结构暴露，不能给出不可识别保证。

### 5.2 r9 关键帧

| kind | 名称 | r9 语义 |
|---:|---|---|
| 1 | PacketAck | `flags=1` 时为 ranges；`offset` 为最大确认 record，`value` 为被确认 epoch，data 含 ACK delay、range 数和至多 32 个闭区间 |
| 4/5 | Open/OpenResult | Flow 目标和打开结果；OpenResult 由 latest-control revision 保护 |
| 6/7 | StreamData/StreamAck | 稳定字节偏移；StreamAck 的 `value` 为 revision、`offset` 仍为连续接收偏移 |
| 8/21 | MaxFlowData/MaxSessionData | `offset` 为 revision，`value` 为绝对信用 |
| 9/10 | Fin/FinAck | final offset；目标写入/半关闭完成前不能发送 FinAck |
| 11/12 | Reset/ResetAck | 终止 Flow；ResetAck 到达前发送方保留 pending 状态 |
| 13 | Datagram | `offset` 为 message ID，`value` 高 32 位为整报长度、低 32 位为片段偏移 |
| 15/16 | ResumeState/ResumeDone | generation 绑定的恢复快照和集合完成门槛 |
| 17/18 | KeyUpdate/KeyUpdateAck | 提议和安装确认的 epoch |
| 22/23 | TicketRefresh/TicketRefreshAck | serial、剩余 TTL 和客户端安装确认 |
| 24 | ControlReceipt | 对 StreamAck、信用、OpenResult 的逻辑安装回执；不是 PacketAck 的替代品 |
| 25 | FECCapabilityFrame | 实验资源描述保留位，当前 Session 不接受二次协商；实际 XOR 能力在 Noise offer/selection 中固定 |
| 26 | DatagramRepairFrame | next15 可选 XOR 修复；外层 Flow/message ID/generation 与认证内部 metadata、方向、规范长度表一致，只用于 UDP carrier 的 Datagram Flow |

`ControlReceipt` 的 kind 固定为 24，以保留既有 `TicketRefreshAck=23`。receipt 只能确认已经完整写入承载并发布过的 revision；仅排队、部分写入或写失败的状态不能被确认。发送端保存有限 publication history，低 revision 可幂等忽略，未来或从未发布的 revision 是经认证的协议错误。

### 5.3 UDP 传输可靠性

| 项目 | 上限/规则 |
|---|---|
| ACK ranges | 每帧最多 32 个不重叠、不相邻区间 |
| 接收 history | 每 epoch 4096 个 record 位 |
| sent ledger | 每 Carrier 最多 256 个 live record，其中 8 个 probe 预留给恢复 |
| lost metadata | 256 条 tombstone；不保存业务 payload |
| ACK delay | 0–25 ms，微秒量化 |
| 逻辑重试 | latest-control 每 key 只保留最新语义状态；发布前失败不消耗 retry 证据 |
| PTO | 基于 RTT/rttvar，有界指数退避；没有后继 ACK 证据时不把全部 outstanding 直接判为 loss |

PacketAck 只负责释放该 Carrier 的 flight、服务 RTT/拥塞和检测传输进展；它不能释放跨承载的 StreamData，也不能代表目标执行。StreamAck 负责连续字节进度，ControlReceipt 负责逻辑状态安装，三者不可混用。

## 6. UDP 优先与 TCP 平滑切换

### 6.1 健康检测

UDP 同时维护 `lastHealth`、`lastProgress`、PTO 截止、probe 预算、flight、cwnd、RTT/rttvar 和 Session 级逻辑控制 retry/no-progress 状态。

普通认证流量只能证明路径仍可解析，不能替代 PacketAck 进展，也不能清零某个 FIN、RESET、KeyUpdate 或 latest-control 的逻辑期限。持续无进展达到 UDP failure budget（默认 15 秒，仍受 Session 剩余寿命约束）时，客户端启动同服务器 TCP 候选。

### 6.2 切换不变量

1. 新候选通过与首次接入等价的设备认证和 Session 恢复证明。
2. `Session ID` 不变，`carrier_generation` 递增一次。
3. Flow ID、目标 socket、send/receive/consumed offset、分类器快照、Ticket serial、latest-control revision 和 no-progress 起点保留。
4. 旧 UDP 的 PacketAck/record ledger/RTT/history/queue 引用清空，不能在 TCP 上假装仍属于同一 Packet scope。
5. ResumeState/ResumeDone 完整互认前，不开放新的业务发送。
6. 目标连接不重新建立；若目标本身已关闭，按目标错误处理，不能把重连目标伪装成平滑切换。

当前策略是切换到 TCP 后保持 TCP 到 Session 结束，不自动回切 UDP，以避免路径抖动和双向候选竞争。

## 7. Flow、FIN/RESET 与恢复

### 7.1 OPEN 与分类

OPEN 的 Target 至少包含 `network=tcp|udp`、`address` 和初始 `class=Interactive|Normal|Bulk`，可包含 domain 和 rule tag。服务端只使用已认证 Session 的 OPEN，不把客户端传来的分类提示当作设备权限。

分类优先级为：可信本地规则/适配器 metadata、端口/协议规则、Clash/适配器 tag、行为分类。行为分类使用有限观察窗口和迟滞；类别变化不会修改目标、network、Flow ID 或 TCP/UDP 交付语义。调度使用类别总份额 4:2:1，类别内 Flow 使用等权 DRR。Interactive 控制帧独立于业务类别，并拥有有限控制发送预算。

### 7.2 FIN

FIN 携带固定 final offset。接收方先保存 final，等待所有此前字节连续到达：

- 客户端直接读取 Flow 时，可以先暴露 EOF，但 FinAck 要等应用消费完已接收字节。
- 服务端桥接目标时，必须确认全部字节已经写入目标，并成功 `CloseWrite`，然后才发送 FinAck。
- 重复 FIN 不改变 final offset；如果原始 FinAck 丢失，重复 FIN 会重新生成同一个 FinAck。

### 7.3 RESET 与终止状态

RESET 终止整条 Flow，清理目标 socket、拨号任务、发送块、接收片段、UDP 重组和 Flow 缓冲。发送方在收到 ResetAck 前保留 pending 状态并有限重试。终止 Flow 的有界 tombstone 必须继续服务重复 RESET 和迟到 ResetAck，但不能复活目标 socket、重置 Flow ID 或重新拨号。

### 7.4 ResumeState/ResumeDone

每次新 Carrier 激活时，双方为当前 generation 建立有限的 Flow 快照集合。快照至少包含 Flow ID、连续接收偏移、单流信用、OpenResult、FIN final 和 RESET 状态。双方必须逐项应用快照、返回对应确认，并在声明数量全部收齐后发送 ResumeDone；自己的快照集合全部获得确认且对端 ResumeDone 已确认后才开放业务。

Resume 快照是某一 generation 的冻结状态。r9-next 在快照中可携带 `ar`（StreamAck revision）、`mr`（MaxFlowData revision）和 `or`（OpenResult revision）作为对端控制状态的单调下界；冻结快照之后产生的 latest-control 新 revision 进入当前 ResumeDone 的 dirty barrier，并须获得覆盖该 revision 的回执，不能由旧快照 receipt 代替。旧 generation 的 ACK、旧 receipt 和迟到业务记录不能改变新 Carrier 的 flight 或状态。

`ResumeDone` v1 的 `Data` 是认证帧内部的有界 JSON 状态，字段为 `v`（版本）、`g`（carrier generation）、`s`（本次 snapshot ID）、`n`（声明的 Flow snapshot 数量）、`sr/sv`（Session-level credit revision/value）和有序 `d`（dirty latest-control 列表）。列表允许 `StreamAck`、`MaxFlowData`、`MaxSessionData` 和服务端到客户端的 `OpenResult`；每项携带 kind、Flow、revision 以及 value 或结果字节。建立 Flow 快照后产生的更高 revision 会进入 `d`，接收方必须先应用 Session credit 与 dirty state，再发带相同状态的 `ResumeDone` flags=1 snapshot receipt。发送方只有在 generation、snapshot ID/count、Session revision/value 和每项 dirty 状态全部一致时才清除本地 Done operation；旧 receipt 只能触发重新发布更高 barrier，不能清除新 revision。dirty 列表上限为 128 项，整个 payload 上限为 8 KiB，超限时 Session fail-closed，不能静默等待。

接收方对已应用且完整状态相同的重复 ResumeDone 请求必须重新发送完整 receipt，使首次 receipt 丢失后发送方仍可通过有限重试完成恢复。相同 generation、snapshot ID/count 的更高 barrier 可以单调 supersede 旧 barrier：Session credit 与已有 dirty-control 的 revision/value 必须覆盖旧状态，不能回退或在相同 revision 下改变值/结果；接收方先应用升级状态，再重新回显升级后的完整 barrier。未知 kind、乱序或重复 `(kind,flow)`、rollback、冲突和预算超限均 fail-closed。发送方收到旧 barrier 的 receipt 时仍保留更高 revision 的 pending，不得提前开放业务。

## 8. 主动探测防护

防护目标是让未授权输入不能获得可用的协议响应、不能触发目标连接、不能造成无界资源放大：

- admission envelope 先做固定长度认证和上限检查，未认证 UDP 输入静默丢弃；
- TCP 未认证输入不返回应用层错误，读取或认证失败直接结束承载；
- challenge、设备公钥、Ticket、恢复 secret 和 transcript 必须全部匹配，单项通过不能越过确认门槛；
- OPEN、DNS、目标拨号和出口写入只能发生在 Session 完成确认并通过 Resume 门槛后；
- 握手候选、replay cache、流表、重组、ACK history、retry 表和日志均有上限；
- 所有发送方错误都不能产生比已验证输入更大的无界响应，READY 只在合法确认后发送。

历史版本的选定双机 WAN 随机探测样本观察到：8 个随机 TCP 输入无应用层响应，16 个随机 UDP 数据报无应用层响应，目标连接计数没有增加。该结果只说明对应历史样本未产生应用副作用，不是 next15 WAN 验证；不能证明端口隐藏、协议不可识别或长期抗压能力。

## 9. 短时局域网与资源销毁

Session 内部使用随机临时地址和单调、不复用的 Flow ID。临时地址只存在于加密帧和 Session owner 内部，不作为长期设备身份。Session 关闭顺序为：转为 CLOSING、使恢复资格和任务失效、有限排空或 RESET Flow、关闭目标 socket/Carrier/重组表/latest-control/retry 表、等待后台任务退出、记录无秘密统计后进入 CLOSED。

Go 不保证把曾经存在过的秘密字节从所有内存副本中完全擦除；本文只要求对象生命周期和引用边界正确，不据此宣称内存零化。

## 10. 默认预算与实现限制

| 预算 | 默认值 |
|---|---:|
| HandshakeTimeout | 3 s |
| ProbeInterval | 1 s |
| UDPFailureBudget | 15 s |
| RetainTimeout | 30 s |
| MaxFlows | 32 |
| MaxFlowBuffer | 128 KiB |
| MaxSessionBuffer | 2 MiB |
| KeyUpdateBytes / Interval | 512 MiB / 30 min |
| KeyDrainTimeout | 10 s；新 epoch 未证明使用或旧 UDP ACK scope 未排空时，超时挂起当前承载 |
| Ticket TTL / refresh lead | 20 min / TTL 的四分之一 |
| MaxSessionLifetime | 24 h |
| plaintext / UDP record | 16 KiB / 1200 B |
| latest-control | 1024 keys、64 KiB payload、单结果 4 KiB、最多 8 次 retry、30 s no-progress |
| ResumeDone v1 | dirty latest-control 最多 128 项、状态 payload 最多 8 KiB；generation/snapshot/Session revision 必须一致 |

这些是用户态候选预算，不等于整机 RSS、内核 socket buffer、CPU 或日志的全局上限。生产前仍需做多 Session、恶意合法设备、长期反复创建销毁、内核资源和 CPU 压测。

## 11. 双机测试拓扑与已完成证据

### 11.1 角色

| 角色 | 主机 | 用途 |
|---|---|---|
| 发送机 | 新加坡 `198.51.100.20` | 启动 BFP 客户端、发送 TCP/UDP 业务和故障切换动作 |
| 接收机/出口/测试机 | 洛杉矶 `192.0.2.10` | 运行 BFP 服务端、维护 Session、连接测试目标 echo fixture |

清单、SSH host key 和运行凭据只在本地 runner 使用；本文不包含密码、私钥、admission secret 或完整服务器清单行。

### 11.2 当前 r9-next4 验证

当前证据只对应 `r9-next4` 的 88 文件源码边界和下列 Linux amd64 二进制；不能回溯覆盖 next2/next3 的历史结果，也不能把历史失败改写为成功。

- 二进制：[`bin/bfp-r9-next4-linux-amd64`](../bin/bfp-r9-next4-linux-amd64)
- 二进制 SHA256：`e6a3e3a84e1435efb6831a4ed88e7bb5e64d9e72059bde1c39db0837e6098016`
- Windows amd64 构建：`bin/bfp-r9-next4-windows.exe`
- Windows 构建 SHA256：`88f5af88828e24d0d9dd50894035b25b7acd7ca8e44cf718b73cfeeaef9b9662`
- 源码清单：`.staging/r9-next4/verification/r9-next4/source-manifest.json`
- canonical 清单 SHA256：`82dea0429520342eab7099020527849406bd70604add4a265634605d4dc657df`
- 独立 Linux race：`.staging/r9-next4/lab/runs/2b0740497fdd21fb4608fe5f61bc580b/race-result.json`
- 基础双机 WAN：`.staging/r9-next4/lab/runs/9922a59b0ae25b39f216220989e9e805/wan-result.json`
- 最新 Ticket lifecycle WAN：`.staging/r9-next4/lab/runs/a8dffd05d5bb86469e148f7ddbbaea22/wan-result.json`，严格 FAIL
- 阶段交接：`.staging/r9-next4/verification/r9-next4/handoff.md`

已执行并通过的检查：

```text
go test -p 1 ./session -run "TestResumeDone" -count=1 -v
go vet ./...
GOOS=linux GOARCH=amd64 go build -trimpath -o bfp-r9-next4-linux-amd64 ./cmd/bfp
GOOS=windows GOARCH=amd64 go build -trimpath -o bfp-r9-next4-windows.exe ./cmd/bfp
go test -race -p 1 ./... -count=1 -timeout=180s   # 独立 Linux runner
```

最新完整本地命令 `go test -p 1 ./... -count=1 -timeout=180s` 为 FAIL。`TestRunningUDPBlackholeRecoversSameExitAndBytes` 在 8 秒 deadline 到期时仍为 `Carrier=udp`、`Generation=1`、`Switches=0`、`UDPPTODue=3`、`UDPProbeSent=3`。随后含 initial-UDP-blocked 的 blackhole 定向三次运行，以及单独重复活动 blackhole 场景，均观察到 1 次失败、2 次通过。没有修改测试 deadline；这些结果保留为切换时序波动证据，不能把完整本地套件写成 PASS。

策略时限分析发现，本地 8 秒验收窗口早于当前独立 UDP watchdog 的 15 秒期限；有界 PTO 在 2 秒基准与连续退避条件下允许累计约 2/6/14 秒的探针截止序列。策略允许的检测时限与测试预算不匹配，须核对切换合同和启动条件，但这不证明任意单次失败的原因，也不能用理论序列代替当次实测 PTO 计数。当前没有改变测试 deadline。

Windows 本地 `go test -race` 仍因 `CGO_ENABLED=0` 且没有 gcc 无法运行；这是本机 race 环境限制，与上述完整本地测试失败分别记录。独立 Linux race 使用 Go 1.27.0、GCC 12.2，15 个包通过，run-owned race container 已删除，洛杉矶主机快照前后未变化。

基础双机 WAN 使用新加坡 `198.51.100.20` 作为发送机、洛杉矶 `192.0.2.10` 作为接收机/出口/测试机：

| 场景 | 初始承载 | 最终承载 | generation | switches | TCP | UDP | 结果 |
|---|---|---|---:|---:|---:|---:|---|
| `normal_udp` | UDP | UDP | 1→1 | 0 | 50/50 | 50/50 | PASS |
| `udp_to_tcp` | UDP | TCP | 1→2 | 1 | 50/50 | 50/50 | PASS |
| `initial_udp_blocked` | TCP | TCP | 1→1 | 0 | 50/50 | 50/50 | PASS |

三场均保持同一 Session 和同一目标连接。随机未认证输入没有应用层响应或目标连接副作用；两端临时目录已清理，发送机与接收机的监听、防火墙、路由和容器快照保持不变。

最新 Ticket lifecycle WAN `a8dffd05d5bb86469e148f7ddbbaea22` 使用 `count=20`、`size=4096`、`interval=200ms`、`timeout=35s`、`ticket_ttl=12s`、`ticket_refresh_lead=8s`、`ticket_overlap=6s`、`max_session_lifetime=5m`。三场 lifecycle gate 均为 true，刷新均为 3 次；随机探测、清理和快照比较通过。但 UDP→TCP 场景 UDP 只有 19/20，整体严格结果为 FAIL，不能用生命周期门槛通过替代业务验收。

| Ticket 场景 | TCP | UDP | lifecycle gate | Ticket refresh | 严格结果 |
|---|---:|---:|---|---:|---|
| `normal_udp` | 20/20 | 20/20 | true | 3 | PASS |
| `udp_to_tcp` | 20/20 | 19/20 | true | 3 | FAIL |
| `initial_udp_blocked` | 20/20 | 20/20 | true | 3 | PASS |

保存的发送机阶段证据见 [udp-operation-phase-analysis.json](C:/Users/developer/Desktop/bfp/.staging/r9-next4/lab/runs/a8dffd05d5bb86469e148f7ddbbaea22/udp-operation-phase-analysis.json)：iteration 7 已被本地写入接纳（`write_accepted=true`），在原始 1000 ms 读取窗口内 timeout，操作前后仍是 UDP/generation 1；下一次 iteration 8 在 TCP/generation 2 成功、交换耗时 177 ms，见 [udp_to_tcp.probe-log.json](C:/Users/developer/Desktop/bfp/.staging/r9-next4/lab/runs/a8dffd05d5bb86469e148f7ddbbaea22/udp_to_tcp.probe-log.json)。这些发送端观察没有证明 relay 黑洞发生的精确瞬间，也没有定位哪段链路丢失；不能据此宣称根因，严格结果与原始 1 秒操作 deadline 不变。

该单个 Datagram 未回包的原因仍未定位，Datagram 的 best-effort 合同也不能把既定 20/20 acceptance gate 改写成成功。旧边界成功 run `6ae1a0a1f0dba2f6293986569c22a9fb`（race）、`e604558042ef8f575f822e8d9f97f2ba`（基础 WAN）、`27cba672eb6813a093a5bc46e78f20e5`（Ticket）只覆盖原 canonical manifest `c02964bf97bdd09b5f193ef146c54790e3f9fb041c017e2704371965fcb50cb4` 和 Linux SHA256 `e36a4271fdb67deba5b0c724de0b3f7f62f376899d492abba08acbfa688f51ce`，继续保留为历史证据，不覆盖当前 supersede 代码。此前基础 WAN run `d1972af391309e251aa3dd57c1d89572` 的业务三场和随机探测通过，但发送机出现非 run-owned UDP listener 的前后快照差异，整体 baseline gate 为 FAIL；该失败记录保留。较短样本 `77eb5ff83504460b87839660d9ee04f6` 仍保留为严格失败：`count=20` 的场景运行时间低于 12 秒 gate；不能用正式重跑覆盖该失败记录。

### 11.3 r9-next2 最新验证边界

`r9-next2` 是在上一个 r9 候选之后重新冻结的源码边界，包含 Flow 写入 token 与动态 deadline、RESET 终止墓碑、以及 ResumeState 的 `ar/mr/or` revision 下界。它的源码清单包含 83 个 Go/module 文件，canonical 清单 SHA256 为 `6a81d481b6a8c14db14af4f59eba9f5272123b9f4bf0a1f25fd3c35785c541c2`。Linux amd64 二进制 SHA256 为 `847cc770b97bbb6efa933bdaa6d0f5e3731fdb3005d34e4563c5a2c12d59a7f5`，Windows amd64 构建 SHA256 为 `c9be13f330aaef48151504fafeda6172198560679eff5783c866067aac75cf58`。

- 独立 Linux race：`lab/runs/67b80a0adf1b2fc5a7c59b350b80517e/race-result.json`，14 个包通过，`pass=true`。
- 双机 WAN：`lab/runs/5785e4b093bf205a35886256ad4c529f/wan-result.json`，总体严格结果 `pass=false`。
- 阶段交接：`.staging/r9-integration/verification/r9-next2/handoff.md`。

本轮 WAN 仍使用新加坡 `198.51.100.20` 发送、洛杉矶 `192.0.2.10` 接收/出口。TCP 三场均为 50/50；初始 UDP 阻断场为 TCP 50/50、UDP 50/50，并保持 TCP。正常 UDP 场和运行中切换场各有 1 个 UDP 探针在原始 1 秒读取预算内超时，因此分别为 UDP 49/50、`udp_failed=1`，严格场景为 FAIL。运行中切换仍保持同一 Session、同一目标连接，并完成 generation 1→2；随机未认证 TCP/UDP 输入没有应用层响应，也没有新增目标连接；两台主机 baseline 未变化，run-owned 进程和目录均已清理。

该结果与当前 Datagram 的 best-effort 合同一致：UDP Datagram 不因 PTO 重发业务数据。严格 50/50 是本轮 WAN acceptance gate，不是任意公网路径上的无损保证；当前证据不能把 BFP 宣称为无损 UDP，也不能用后一条成功回包覆盖已经记录的超时。下一轮 WAN 需要增加同一 datagram ID 在发送端、relay、服务端接纳和目标回显四段的关联，先确定路径丢失、目标未执行还是应用读取截止点。

### 11.4 r9-next3 operation contract 与验证

`r9-next3` 在 `r9-next2` 之后建立独立源码边界，新增 `internal/operation` owner-confined 状态表。每个逻辑操作使用不可变的 `Kind/Flags/Flow/Serial/Epoch` key；`Started`、`LastSent`、`NextSend`、attempt/retry、no-progress deadline 和 terminal 状态由同一 owner 管理。`Prepare` 不产生副作用，只有完整 carrier write 成功后 `Publish` 才消耗一次 attempt；UDP 与 TCP 共用同一预算，carrier rebind 只提前唤醒重试，不重新计时。操作耗尽时，Flow 级操作明确失败，Key/Ticket/Resume 级操作 fail closed，避免无限固定间隔重发。

本阶段源码包含 85 个 Go/module 文件，canonical 清单 SHA256 为 `a3ed9a459c7e5126e05c152a0f4b0d1b13337ca73b1189e40b5e8b3006b161ed`。Linux amd64 二进制 SHA256 为 `9ea273d3239ee76a19dc432df845bab9c8e3dd3c16bb561b4c2b40d5ea48e629`，Windows amd64 构建 SHA256 为 `836785fe5e29d3016badad70565a6f90914272eb88ab878ffec9480b9f86b041`。

- 独立 Linux race：`lab/runs/e507478abeac6d757bef11420559ce8d/race-result.json`，Go 1.27/Linux amd64/GCC 12.2，15 个包通过，`pass=true`。
- 双机 WAN：`lab/runs/0f411db34dfe1e2f67aaf4b43a80e229/wan-result.json`，总体 `pass=true`。
- 阶段交接：`.staging/r9-next3/verification/r9-next3/handoff.md`。

新一轮 WAN 仍使用新加坡 `198.51.100.20` 发送、洛杉矶 `192.0.2.10` 接收/出口。正常 UDP 为 UDP→UDP、generation 1→1、TCP/UDP 50/50；运行中切换为 UDP→TCP、generation 1→2、1 次切换、TCP/UDP 50/50；首次 UDP 阻断直接为 TCP→TCP、generation 1→1、TCP/UDP 50/50。三场均保持同一 Session 和一个目标连接。随机探测的 8 条 TCP 和 16 个 UDP 输入均没有应用层响应，目标连接计数保持不变，远端 baseline 与 run-owned 清理通过。

这轮通过只适用于该源码清单、二进制、时间窗口和双机样本；它不能覆盖 `r9-next2` 的 WAN 49/50 失败，也不能把 best-effort Datagram 提升为任意公网路径上的无损保证。


### 11.5 r9-next4 增量与验证边界

`r9-next4` 从 next3 独立复制，加入承载代次 operation 淘汰、TCP operation deadline 调度、由 Session owner 控制的 KeyUpdate 旧 epoch drain，以及 Session-level ResumeDone v1。底层 `RecordCipher` 不再按“收到 4096 个新记录”自动删除旧 epoch；只有新 epoch 出现实际认证记录、旧 ACK scope 排空且达到最小 drain 时间后才退役，`KeyDrainTimeout` 默认 10 s，超时挂起承载并进入恢复。ResumeDone 在固定 Flow snapshot 之后冻结 Session credit revision，并携带有序 dirty latest-control；版本化状态与 flags=1 receipt 必须逐项相等，预算超限则 fail-closed。

next4 当前源码清单包含 88 个 Go/module 文件，canonical 清单 SHA256 为 `82dea0429520342eab7099020527849406bd70604add4a265634605d4dc657df`。Linux amd64 二进制 SHA256 为 `e6a3e3a84e1435efb6831a4ed88e7bb5e64d9e72059bde1c39db0837e6098016`，Windows amd64 构建 SHA256 为 `88f5af88828e24d0d9dd50894035b25b7acd7ca8e44cf718b73cfeeaef9b9662`。ResumeDone 定向测试、vet、双平台构建、独立 Linux race 和基础 WAN 通过；最新完整本地套件和 Ticket WAN 的严格失败见 11.2，不能宣称当前质量门全部通过。Windows 本机 race 受 `CGO_ENABLED=0` 且无 gcc 的环境限制，未能运行。新增的 ResumeDone v1 定向测试覆盖 Session credit、dirty state、完整 snapshot receipt、无序/未知控制、revision rollback、dirty budget fail-closed、重复请求重发 receipt，以及更高 revision barrier 应用并重新回执。

本阶段的 terminal receipt 修复已把 `FIN_ACK`、`RESET_ACK`、`KEY_UPDATE_ACK`、`TicketRefreshAck`、`ResumeDone` 和 `OpenResult` 的提交顺序改为“先完整校验语义，再确认 operation”。错误 final offset、malformed ACK、future/stale epoch 或 serial、未知 Flow、未知 Resume snapshot 和错误 snapshot count 均不能清除 pending operation；经认证但不匹配的输入按 fail-closed 处理。ResumeDone receipt 回显完整 barrier 的 Session revision/value 和 dirty latest-control；如果本地在恢复过程中产生更高 revision，旧 receipt 保持 pending 并重新发布新 barrier，接收方按单调 supersede 条件应用后重新回执。相同请求重试也重新回执，避免首次 receipt 丢失后卡死。测试覆盖这些边界，但还没有完成所有组合 fault matrix、长期 soak 或跨实现互操作。

本阶段交接：`.staging/r9-next4/verification/r9-next4/handoff.md`。

### 11.6 r9-next5 恢复诊断候选

next5 仍为 88 个 Go/module 文件，仅修改 `session/client.go`、`session/config.go`、`session/session.go`、`session/udp_transport_test.go`。canonical 清单 SHA256 为 `d0bc24b48c9f9d15d4b099a1bd6d85ce39de269182f9a1ec4e226e173e821f9f`，Linux amd64 SHA256 为 `5faa5939b568178bad8aa7fd00232b205e8485c91be54458e78fd92d8b50ba38`，Windows amd64 SHA256 为 `b5c63667233f26a02c23d406dfabcb61755a23deba916366d77afbe7f6a9723e`。

新增公开诊断只在 Session owner 内采样，固定内存大小，不包含凭证、候选 token 或原始错误。`udp_no_response_deadlines` 与 `udp_pto_rounds` 分别表示连续无响应次数与 PTO 退避轮次；另提供路径存在/suspect、base PTO、剩余截止时间、无进展年龄，以及 `tcp_recovery_attempts/failures/in_flight`。TCP 候选计数覆盖建立承载与 attach/merge，不能证明 ResumeDone 已结束。

新虚拟时钟回归在 base PTO 为 2 秒、1 秒收到认证但不匹配 fresh probe 的 Pong 时，验证 2/6/14 秒三次 PTO 只产生两次连续无响应，尚未 suspect；15 秒独立 watchdog 在第四次 PTO 前暂停 UDP，保留同一 Flow、目标连接、chunks、偏移和缓冲。生产 `UDPFailureBudget=15s`、原 8 秒集成测试和 Datagram best-effort 合同未修改，因此本次是诊断改进，不能宣称修复了所有偶发超时。

本次 `go test -json -p 1 ./... -count=1 -timeout=180s` 通过，15 个包、272 个顶层测试；Windows symlink 检查因环境能力跳过。vet 和双平台构建通过。独立 Linux race run `b8dc83f8c94e7c0bc3932f90ec7b643e` 通过，冻结清单及二进制匹配，run-owned 容器/目录清理、洛杉矶快照比较通过。基础双机 WAN run `e1e6980e72887aa4cabae40714f866f5` 三场 TCP/UDP 均为 50/50，Session/目标连接保持，活动切换 generation 1→2、一次 TCP 候选且失败计数为 0；随机探测、清理、快照 gate 通过。原始接收端周期日志实际出现 PTO 3 次但连续无响应 2 次，见 [诊断分析](C:/Users/developer/Desktop/bfp/.staging/r9-next5/lab/runs/e1e6980e72887aa4cabae40714f866f5/udp-recovery-observation-analysis.json)，不能据此回溯宣称旧失败根因已经证明。Ticket lifecycle WAN run `cb7508814cd7c798b6dc8f83778df153` 本次通过：三场 TCP/UDP 均为 20/20，均安装 3 次刷新并跨过 12 s TTL；initial UDP blocked 的 elapsed 为 12005 ms，仅超过 gate 5 ms，只证明该有限样本。随机探测、清理及快照比较通过。

阶段证据：[next5 交接](C:/Users/developer/Desktop/bfp/.staging/r9-next5/verification/r9-next5/handoff.md)、[本地验证索引](C:/Users/developer/Desktop/bfp/.staging/r9-next5/verification/r9-next5/local-summary.json)、[独立 race](C:/Users/developer/Desktop/bfp/.staging/r9-next5/lab/runs/b8dc83f8c94e7c0bc3932f90ec7b643e/race-result.json)。分类协商后续实施门槛另见 [Stage B 实施计划](C:/Users/developer/Desktop/bfp/docs/分类协商StageB实现门槛.md)；该计划在 next5 时点尚未实现，next6 的接线与验收边界见 [Stage B 实现记录](C:/Users/developer/Desktop/bfp/docs/分类协商StageB实现-r9-next6.md)。

## 12. 当前未完成项与发布门槛

r9 仍是实验候选，不应称为生产发布包。后续门槛包括：

当前还须定位完整本地活动 UDP blackhole 切换的时序波动和最新 Ticket WAN 的 UDP→TCP 19/20 Datagram 失败；历史或局部成功不能清除此轮失败。保持 `production_ready=false`、`released=false`。

1. 完整的 FIN/RESET/KeyUpdate/TicketRefresh/ResumeState/ResumeDone terminal receipt fault matrix：丢请求、丢响应、丢 receipt、重复消息和 exhaustion 后的状态收敛；当前 next4 已完成语义先校验后提交及定向回归，但不能把有限测试写成全组合证明。
2. source/device/global resource budgets，以及多 Session、恶意合法设备、长期反复创建销毁、内核资源和 CPU 压测。
3. Stage B 核心接线已在 next6 实现；仍需完成真实恢复期间的类别新变更/丢公告/丢 ACK 组合、专项 WAN 缺失 ACK 与 retry exhaustion，以及完整门槛验收。
4. 混合类别 WAN fairness、goodput、p95/p99、持续丢包/乱序、MTU 缩小和高 RTT。
5. 已有 Session fake-IP/A DNS 前端、next25 CLI DNS/SOCKS 接入和两个真实原生 fork 的局部验证；仍需完整 TUN、系统 DNS、AAAA/EDNS、IPv6、客户端承载路由排除与原生支持矩阵验收。
6. long soak、跨实现 wire vectors、解析 fuzz 和独立安全评审。

旧 r8 的 WAN 严格失败记录必须继续保留，不能因为旧 r9 的三场实验通过或 r9-next2 的局部场景通过就改写为历史成功。每个结论只适用于对应的二进制、源码清单、时间窗口、双机拓扑和测试矩阵。
