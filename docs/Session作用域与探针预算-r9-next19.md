# r9-next19：Session 临时映射、探针阶段预算与入口限额

日期：2026-10-09。独立候选路径：`C:/Users/developer/Desktop/bfp/.staging/r9-next19`。next18 原始本地失败和 WAN strict FAIL 保留，未复用其验证作为本候选通过证据。

## 目前新增的实现

1. `gateway.Dialer.ForSession` 在已授权的 Session 确认后建立独立 DNS/Fake-IP 作用域。临时地址只在所属作用域恢复；还原先于 DNS、目标策略和 numeric socket dial。Close、revocation、不可变 Session expiry、parent cancellation 清理 map/lease/cache。保留 API 使用时检查 eligibility，不等待异步清理才能拒绝新操作。
2. 可选 `SessionAddressAllocator` 和 `Session.AddressAllocator()` 发布实际已安装的 backend scope。承载恢复沿用原 scope，新 Session 不继承旧映射。数值 fake-IP 在 lease 释放后可能重用，适配器必须按 Session 丢弃旧缓存。
3. 默认 `probe -duration` 保持从调用入口开始的绝对总截止。新增 `-setup-duration`，只有显式大于零才启用独立建立预算；业务 `-duration` 从 Session 与请求 flow 建立后开始。parent deadline 仍约束全部阶段；单次 TCP 最多 8 秒、UDP 最多 1 秒，取更早的业务 deadline。记录 setup/business/total 耗时、budget_mode、failure_phase、last_iteration_started 和业务完成计数。
4. 未认证 TCP 入口保留全局 64 个 raw socket 上限，并增加每来源 IP 8 个上限。源端口变化不会增加来源额度；认证完成、失败、首包绝对截止或关闭归还额度。测试覆盖来源饱和时另一来源完成真实认证、溢出无应用响应及慢首包滴字节不延长期限。此数值是候选默认值，同一 NAT 的设备共享未确认额度，不代表已完成 UDP 来源预算或全服务器抗压。

Session 临时映射实现及边界见 [作用域说明](../.staging/r9-next19/docs/短时网络-SessionScope集成-r9-next19.md)。
来源预算实现及边界见 [主动探测来源限制](../.staging/r9-next19/docs/主动探测-来源TCP握手预算-r9-next19.md)。

## next18 WAN 失败的定位

原 run：`9c596cee534aab23b53d1e194e8f7696`。正常 UDP 12/12；运行切换和初始 UDP 阻断均为 11/12、`probe deadline`。两场已完成的 TCP/UDP 业务全部成功，`udp_failed=0`；最后进度为 iteration 10，随后 interval 等待撞到总上下文截止，iteration 11 未开始。运行切换已经在 iteration 5 进度前恢复到 TCP generation 2，Session 和原目标 socket 保留；初始阻断业务始终为 TCP generation 1。

这定位了本次 11/12 的 deadline 原因，不构成协议整体通过。原 20 秒绝对总预算结果保持严格 FAIL。显式分阶段预算属于新的实验合同，不能回写旧样本。逐项原始日志哈希、完成计数和进度观察见 [诊断证据](../.staging/r9-next19/verification/wan-next18-deadline-diagnosis.json)。

## 验证状态

统一源清单已冻结为 154 个 Go/module 文件，manifest SHA256 为 `cde4aea56fe1aedbcf08690a39db6c3ae40f5b1716d09b7fbbfd20944a983b50`。完整本地检查通过：17 个包、506 个顶层测试，`go vet`、Windows/Linux 构建通过，源码未变；5 秒、2 worker 的有限 repair-parser fuzz 通过。独立洛杉矶 Linux race run `22f84c248bad40b573637e154890de1d` 为 17 包通过、exit 0、无 DATA RACE，owned 容器/目录已清理，接收机快照未变化。上述证据均绑定本候选源码及同一 Linux 二进制，不构成独立安全审核。

新分阶段预算 WAN run `0efd1b3bfaad0389c540e7e57478d8eb` 已完成：新加坡发送、洛杉矶接收/出口，12 次 × 1 KiB、1 秒间隔，显式 setup 8 秒、business 30 秒，单次 TCP 最多 8 秒、UDP 最多 1 秒，FEC off。正常 UDP 和初始 UDP 阻断后转 TCP 均为 TCP/UDP 12/12；运行中 UDP→TCP 保持同一 Session、generation 1→2 和单一 TCP 目标连接，TCP 12/12、UDP 11/12，`udp_failed=1`、`failure_phase=udp_exchange`，整轮严格 FAIL。该场 business 耗时约 18.7 秒，不能套用 next18 的总预算耗尽解释。超时发生于 iteration 4（第 5 条）的 UDP 读取；iteration 5 起已转 TCP 并完成后续业务。未收到回包的具体原因仍需定位。

随机 TCP/UDP 探测没有应用响应或新目标连接副作用，两端 owned cleanup 完成，前后快照均未变化。旧 next18 的原始严格 FAIL 及哈希保留。完整源码、本地/fuzz/race、二进制、新实验预算和 WAN 结果见 [统一证据索引](../.staging/r9-next19/verification/r9-next19/evidence-index.json)。

## 四类与未完成范围

仍为 2 类主体实现（认证复用、基础混淆/主动探测）、2 类部分实现（协议内分流、短时会话网络）、0 类最终验收。`acceptance_complete=false`、`production_ready=false`、`released=false`。

尚未实现客户端 DNS 协议代理、TUN、完整 NAT、IPv6 fake-IP pool、wire mapping 同步、Mihomo/sing-box 原生 outbound。分类公平性/FEC WAN 性能、长时间资源稳定性、独立安全审查与互操作仍需完成。
