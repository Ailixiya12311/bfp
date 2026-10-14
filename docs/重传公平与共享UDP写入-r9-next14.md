# BFP 重传公平与共享 UDP 写入 r9-next14

日期：2026-10-09。源码路径：`C:\Users\developer\Desktop\bfp\.staging\r9-next14`。

本阶段从 next13 的 125 文件父边界复制，加入三项工作：UDP 重传按类别和 Flow 公平选择；Server 共享 UDP 唯一写 owner；按类纠错的有界 XOR 核心。

## 重传公平

原实现把 `p.retries` 按 kind、Flow ID、offset 排序，每轮只取前两个，持续重填低 ID Flow 时可能使高优先级 Flow 饥饿。next14 使用 `Interactive:Normal:Bulk = 4:2:1` 的有界轮转；类别内用 Flow 游标轮转，StreamData 每次从当前 owner 状态读取 effective class。失效引用先清除，不能消耗重传槽位；底层写失败、拥塞窗口或 pacer 拒绝时保留引用。每轮上限仍为 2 个重传和 4 个普通发送，Datagram 和控制原语的原有 retry 语义不变。

新增真实本地 UDP/RecordCipher/ledger 回归覆盖低 ID Bulk 不饿死 Interactive、类别变化作用于已有引用、stale 清理不占槽位以及失败写保留 owner。

## 共享 UDP 写 owner

Server 现在为共享 UDP socket 创建一个 `sharedUDPWriter`。bootstrap 回复、READY 和 Server Session 的 UDP 记录均走同一个有界队列；写请求在提交时计算绝对截止时间，队列等待和物理写入共用预算。只有 writer 可以设置/收紧/清理共享 socket deadline。Session 的 close 通过 carrier-local wake 取消本请求，不会修改其他 Session 的 active deadline，也不会关闭共享 socket。private UDP carrier 的普通写和显式 close deadline 使用与 TCP 相同的 min 组合规则。完整写成功前不会发布 READY、ledger、latest-control、WireSent 或 close-success 状态。

支持边界仍明确为会响应 deadline/Close 的生产 `net.UDPConn`。任意故意不合作的自定义 socket 可能阻塞 worker，不能据此宣称强制终止；真实 blocked kernel UDP send 的跨 Session 证据和完整 Server shutdown 矩阵仍待补齐。

## 按类纠错核心

`internal/fec` 提供固定 data shard、单 parity shard、shard size 和 block size 的 XOR block。Encode 复制并填充 payload，Recover 只接受一个缺失 data shard并按原长度裁剪。该模块没有 Session/Carrier/Flow 引用，不能单独作为线上 FEC。

接入前还必须完成：能力协商、AEAD 内的 block 元数据和 repair shard、Session/carrier-generation/flow/direction/block ID 隔离、寿命/组数/字节预算、重复/回放检查，以及只对可选 Datagram 使用而不改变可靠流合同。

## 验证边界

第一次 next14 正式本地 gate 的失败保留在 `verification/r9-next14/local-gate/local-summary.json`，失败测试为 `TestRunningUDPBlackholeRecoversSameExitAndBytes`。在无源代码改变的第二次完整 gate 中，17 个包、412 个顶层测试、vet 和双平台构建通过；source manifest 为 `6024b78c50fa3542e7a0ba03757e4c3c57162aa86b8b5fbf3be87a6c5a694abb`。洛杉矶绑定 run `69913d6d52a84ed2c87ac2ba4f769158` 的 17 个 race 包通过、无 DATA RACE、owned 清理和前后 receiver 快照通过。next14 没有新加坡上传、WAN 业务验证或发布操作。

四类统计仍然是 2 类主体实现、2 类部分实现、0 类最终验收。FEC wire、完整分类 WAN/可靠性/FEC、公平性长期样本、完整 close/recovery/READY 矩阵、原 8 秒恢复稳定性、客户端 DNS/fake-IP/TUN/IPv6 和独立安全评审仍未完成。
