# r9-next21：客户端 DNS 与数据报恢复

日期：2026-10-09。开发源码位于 `C:/Users/developer/Desktop/bfp/.staging/r9-next21`，从 next20 冻结父源码合入客户端 DNS、数据报暂停与生命周期，并加入公共 factory 取消、排队 Connect 取消及关闭测试修正。next21 的 181 个 Go/module 文件已完成源码绑定的本地 18 包、578 顶层测试、vet、Windows/Linux 构建、5 秒 repair-parser fuzz 和独立 Linux race，见 [最终证据索引](../.staging/r9-next21/verification/r9-next21/evidence-index.json)。自身 WAN 未执行，最终验收仍未完成。后续开发为 next22/23 及真实原生 fork，见 [当前记录](公共UDP与原生接入-r9-next22-23.md)；其结果不改变本页 next21 的边界。主目录 Go 源码仍为历史 r8。

## 客户端网络归属

客户端地址 factory 为一次授权 Session 创建映射；所有 `Dial*` 在选定的一个 Session 内还原地址、分类并执行 OPEN。UDP→TCP 恢复沿用这个 owner、映射和目标连接。关闭、到期或已观察到的撤销清理旧映射；新会话不接收旧地址。同一内置 factory 生命周期内的地址游标不回绕，不能据此保证进程重启或重建 factory 后永不重用地址。

`adapter/dns` 提供字面量 loopback 上的 UDP/TCP DNS 前端。支持单个 IN/A 查询，使用 `golang.org/x/net/dns/dnsmessage v0.58.0`。每个查询选择一次 Session，按实际 mapping lease 和会话剩余寿命给出向下取整的 TTL，再扣除响应写入窗口；不足一秒返回 SERVFAIL。没有独立前端缓存，AAAA、EDNS、递归和其他类型尚未接入。

AD、AA、RA 回复均为 false，CD/RD 按请求回显。前端没有声称自己做 DNSSEC 验证、递归或权威解析。租约 validation 会拒绝已知终止 owner；validation 与 socket write 之间仍有并发 Close 窗口，可能出现一个晚到正响应。旧地址的实际拨号仍受 Session-use guard 和不立即复用约束。查询取消若输给已开始的准入，可能留下一条归原 owner 且有界的 mapping，不发送响应，不能写成“取消后零分配”。

Connect 等锁可被本次调用或 Client 取消；其他调用正在做的首次握手继续使用自己的上下文。公开 factory 的创建预算也绑定 Connect/Close，迟到 scope 清理一次，成功 scope 脱离单次建连取消并归长期 Session。Carrier TCP/UDP hooks 用于宿主物理拨号；next21 本身没有原生上游 outbound 或 TUN 配置，后续真实 fork 的本地验证另行记录。

## UDP 业务暂停和整报生命周期

UDP 路径进入 suspect 或 TCP 恢复候选后，停止在旧路径提交 OPEN、字节流、Datagram 和 repair；必要的反馈、健康和恢复控制仍受预算约束。新 UDP Write 等待可用承载及 peer-ready，超时返回 `n=0`，不会把未准入消息伪装成成功写入。

每次 UDP Write 在入口捕获 `min(当前 writeDeadline, 入口时间 + RetainTimeout)`，同一 cutoff 覆盖 per-flow 写 token、恢复等待和 actor 准入。SetDeadline/SetWriteDeadline 可以缩短已在等待的每个 UDP 操作，延长或清零只对后续 Write 生效。短暂缩短后立即延长也不会续期；排队 actor 操作使用同一可取消 context。末次截止检查与整报队列、编号和保留量提交在 flow 锁内线性化，分类仅统计成功准入。TCP 保留既有可延长的 token 等待行为。

每个本地并发 Write 调用有一个小操作节点和 timer；等待时不复制 caller payload，也不建立专用等待 goroutine。等待受时间上限约束，本地 caller 并发没有单独数字额度。Session 的发送数据和元数据另受每流整报数量、每流字节及 Session 字节预算限制，不能把逻辑保留量当成 RSS 上限。截止与 Close 同时就绪时可能返回 timeout 或 ErrClosed，不声明两者的严格先后优先级。

准入后的整报记录原始 cutoff、generation、分片数与逻辑保留量。首个分片完整提交后整报不可迁移；carrier write 报错的送达未知结果也按已提交处理。仅零分片提交、尚未到期的完整消息可在恢复后迁移，保留 message ID；新 generation 重新生成 repair，TCP 不发 parity。部分提交或送达未知的消息退役，不为了补齐测试重放。Best-effort UDP 仍不提供业务 ACK/重传，平滑切换保持会话和连接并允许有界暂停，不保证每条在途 UDP 无损。

## 关闭测试修正

next20 attempt02 保留严格失败。原 simultaneous-close fixture 丢弃了双方独立请求，解除 drop gate 后又把 `[Close,Ack]` 整条记录丢掉，因而未接收 peer Close 的一侧发出零 ACK 是合理结果，原测试却要求至少一个 ACK。

next21 的修正只改变测试：持有双方首条原始加密请求，在双方本地关闭意图成立后原样双向交付，观察实际 peerRequested，再解除屏障。另测一个方向请求持续丢失，确认零 ACK、双方 ErrCloseUnconfirmed 和一次性资源清理。生产关闭配对、700 ms 测试截止、最多 5 次请求、8 次响应及字节预算没有因该修正扩大。

## 验证与未完成范围

next21 attempt02 冻结 181 个 Go/module 文件，manifest `2fe9c1e60d062e255a8f58c3284d170ac30ecf3bf7a18b87db5dfedd40fc601a`；完整本地 18 包、578 顶层测试、vet 和 Windows/Linux 构建通过。同一源码的 5 秒 repair-parser fuzz 与洛杉矶 Linux race run `d35a25914f4cb6a52e031406d39478a1` 通过，源码与 Linux 二进制绑定、测试自建容器/目录清理及接收机基线核对均通过。证据见 [本地摘要](../.staging/r9-next21/verification/r9-next21/local-gate-attempt02/local-summary.json)、[race 结果](../.staging/r9-next21/lab/runs/d35a25914f4cb6a52e031406d39478a1/race-result.json) 与 [最终索引](../.staging/r9-next21/verification/r9-next21/evidence-index.json)。

原 next21 attempt01 因 UDP 选中的 DNS 端口无法绑定 TCP 而严格失败，修复 listener 后的新 attempt02 独立验证通过；[首次失败](../.staging/r9-next21/verification/r9-next21/local-gate-attempt01/local-summary.json)、next20 attempt02 关闭测试失败及各切片的旧结果全部保留。next21 没有自己的 WAN；原 next19 运行中 UDP→TCP 为 TCP 12/12、UDP 11/12，整轮严格失败，Session 与一个 TCP 目标连接保留。

本阶段没有新加坡上传或新 WAN。还需完成 Mihomo/sing-box 原生接入的完整支持矩阵、系统 DNS/TUN、IPv6/EDNS、认证 UDP 撤销通知、消息级 WAN 观测和完整故障矩阵、混合类别/FEC 性能、长期资源稳定性、独立安全评审及跨实现互操作。后续 next22/23 和真实 fork 已有源码与本地检查，不回填为 next21 的接入或实网验收。

四类计数仍为 **2 类主体实现、2 类部分实现、0 类最终验收**。`acceptance_complete=false`、`production_ready=false`、`released=false`。
