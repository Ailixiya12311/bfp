# BFP 会话 DNS 生命周期实现方案

日期：2026-10-09。实施基线：`.staging/r9-next8`。本文对应最初第四项“会话结束时销毁临时网络所属 DNS 结果”，描述会话出口解析结果的归属和销毁合同。

**当前状态：gateway 的会话 DNS 模块已实现并通过一次定向测试；Session 实际接线已写入 next8，Session 层运行时测试仍由独立测试执行确认。** 本文不把计划、代码审查或 gateway 单元测试写成整个第四项已经验收完成。下一版本仍须完成实际新建、恢复、终止、撤销和迟到结果的联动证据，并保持完整协议验收边界。

## 1. 需求与实现范围

一次确认建立一个临时会话网络。会话内多个域名目标可以复用该会话的正向 DNS 结果；恢复到新的 UDP/TCP 承载时保留同一个结果空间。新的 Session 从空空间开始，原 Session 终止后不能命中旧结果、加入新结果或用迟到结果创建可交付的出口连接。

本阶段是出口 `gateway.Dialer` 的会话专属正向解析缓存，不是新增 DNS 查询协议、DNS 服务器、客户端 DNS 代理、TUN、fake-IP 或 DNS 劫持。系统 DNS 缓存、上游递归服务器的缓存和原生 resolver 内部工作不属于该 map 的销毁范围；这项边界不改变既有域名出口解析路径。

已有默认 ACL 保持不变：私网、loopback、link-local 和既有 non-public 前缀默认拒绝；CIDR、port allowlist 只收紧，否则允许范围。域名解析必须保留 `ResolveOnceValidateAllAndDialNumeric`：一次结果中的全部地址先通过 ACL，之后才选择网络族并拨数值 IP。不能先选“看起来可用”的地址，从而跳过同次结果中的禁止地址。

## 2. 现有 owner 路径与接线位置

初次只读检查发现：原 `gateway.New` 创建一个 server 共用 Dialer；每次 `DialContext` 调用 `net.DefaultResolver.LookupIPAddr`，无 Session DNS map。`Server.confirm` 将同一 `cfg.Backend` 传给所有 `newSession`。这一行为不能提供 BFP 自己的会话 DNS 结果隔离。

next8 现已补入最小接口与接线：

| 位置 | 当前职责 | 完整接线要求 |
|---|---|---|
| [internal/backend/backend.go](C:/Users/developer/Desktop/bfp/.staging/r9-next8/internal/backend/backend.go) | 无 session/gateway 相互依赖的 `Dialer`、可选 `SessionFactory` 合同 | `ForSession(ctx, valid) (Dialer, func())` 仅创建空 scope；cleanup 必须幂等、同步失效本地状态且不等待网络 I/O |
| [session/config.go](C:/Users/developer/Desktop/bfp/.staging/r9-next8/session/config.go) | `Backend` 与 factory 使用最小接口别名 | 保留旧 Backend 兼容；默认 gateway 必须走 factory 才具有本阶段 DNS 归属 |
| [session/server.go](C:/Users/developer/Desktop/bfp/.staging/r9-next8/session/server.go) 的 `confirm` | 打开确认密文，校验 challenge/transcript binding，锁定 attempt/authority，并检查候选有效后才建立新 Session | 不在 HELLO、未确认 pending 或未经认证输入上创建会话解析 scope 或查询 DNS |
| [session/session.go](C:/Users/developer/Desktop/bfp/.staging/r9-next8/session/session.go) 的 `newSession` | actor 启动前调用 `bindSessionBackend` | scope 在 actor 可接收 OPEN 前完成绑定；仅新 Session 调用一次 factory |
| [session/backend_scope.go](C:/Users/developer/Desktop/bfp/.staging/r9-next8/session/backend_scope.go) | 复制不可变 lifetime、保留 atomic revocation guard，安装 scoped backend 和 cleanup | guard 不能读取可变 actor 状态；终态 cleanup 不能等 server map 的周期回收 |
| `confirm` 的已有 `p.group.session` / resume 分支 | 使用原 Session，并在同 attempt 去重后 attach | 不再次调用 factory，不清空或迁移到其他 Session cache |
| `handleOpen` | 仅服务端、peer ResumeDone 门通过且流非 terminal 时开目标任务；使用 `s.ctx` 派生的固定 10 秒 dial context | 目标 DNS 与拨号仍在这个受确认约束的任务内，不由 cache 查询创建新 Flow |
| `run` 退出 defer | 关闭 carrier、目标 socket、失败全部 flow，并执行 `closeBackend` | cleanup 必须在 `done` 关闭之前完成，本地缓存关闭不用等待 resolver 返回 |

factory 必须是短小的本地初始化，不能查询 DNS、拨号或阻塞网络。当前 `confirm` 在 server/authority/attempt 的提交锁内创建 Session，默认 gateway factory 只创建 context、空 map 和 callback，未引入锁内网络工作。自定义 factory 也必须遵守同样合同，否则能阻塞其他管理和确认操作。

## 3. 三种状态不能混用

| 状态 | cache 是否可用 | 已有目标连接 | 后续行为 |
|---|---|---|---|
| 初次确认前 | 不创建、不查询 | 不创建 | 随机探测、认证失败、坏 confirm 均不能触发目标解析 |
| 活动或保留恢复中的同一 Session | 未到本地 max-age 且 owner 仍有效时可用 | 原连接按既有恢复合同保留 | carrier 切换保留同 scope；TTL 继续按本机时间流逝，不因恢复续期 |
| Session 终态或权限/lifetime 失效 | 立即禁止命中、提交和新可交付拨号；清空 map | 按 owner 既有终态关闭 | 迟到 resolver 结果被丢弃，不能让 scope 重新变为活动 |

`suspend` 只关闭/替换 carrier、设置暂停时间，不取消 Session；不能顺便调用 DNS cleanup。`maintain` 在 authority 撤销、MaxSessionLifetime 到期或 RetainTimeout 耗尽时取消 owner；这些才是 cache 的终态边界。单个 Flow 的 FIN、RESET 或调用方超时不会销毁仍活动 Session 的其他缓存。

显式 `Session.cancel` 的接线先取消 owner context，再同步执行 once-protected cleanup。父 Server context 取消会立即使 guard 失败，AfterFunc 触发 cleanup，actor 退出也执行同一个 cleanup。应区分“从 context 取消开始结果在逻辑上不可用”和“异步 callback 已清除 map”的时刻；`Session.Close` 返回及 `done` 关闭之前必须已经清除。

设备撤销通过 `RevokeDevice` 设置 atomic revoked，取消各 owner 并等待 done。cache hit、lookup 返回和拨号前也检查同一撤销/lifetime guard，不能在下一个 10 ms maintain tick 或 server 每秒清理前继续使用结果。ticket refresh 或 overlap 不延长 Session lifetime，也不重置 DNS max-age。

## 4. gateway 模块的当前实现

[gateway/session_dns.go](C:/Users/developer/Desktop/bfp/.staging/r9-next8/gateway/session_dns.go) 为每次 `ForSession` 创建独立 `sessionDNS`，克隆 Dialer 的只读策略和函数，保留 server 共用的拨号许可及 resolver 许可。cache 不以长期设备标识索引，不进入 Server 全局结果表。

固定预算如下，均为当前模块内的固定值：

| 项目 | 上限/语义 |
|---|---|
| 每 Session 正向结果 entry | 64；到期删除后满表淘汰最早 expiry，平局按 key 确定 |
| 每次解析返回地址 | 16；检查整个返回结果后才能存储或拨号，不能截取前 16 个绕过后续禁止地址 |
| resolver hostname 长度 | 253 字节；超限在实际 resolver 调用之前拒绝 |
| 正向结果 max-age | 30 秒，从成功解析结果存入 cache 的本机时间起计算；是本地保留策略，不是权威 DNS TTL |
| server 拨号预算 | 继续共享原 `Policy.MaxConcurrent` channel，默认 32；克隆不能分配每 Session 的新 channel |
| server DNS 执行预算 | 同一个 factory 下共享 32 个 resolver invocation 许可；没有每 Session 再乘 32 |
| 单次拨号预算 | 原 `Policy.Timeout`，默认 10 秒；cache 与 DNS 排队不能延长调用方/owner 的期限 |
| 错误与否定结果 | 不缓存；空结果、解析错误、非法地址、zone、全量 ACL 拒绝及超限结果都不能成为 positive entry |

key 使用实际交给 resolver 的完整 hostname，不合并 port 或网络族：`LookupIPAddr` 返回的是同一域名的完整地址集合，ACL 仍检查全量后才做网络族选择。不会自行剥除末尾 dot，从而把带搜索域的相对名称和绝对名称混为一谈。此阶段也不新增 IDNA、fake-IP 还原或客户端 resolver policy。

cached 地址使用值类型 `netip.Addr`；resolver 给出的可变 `net.IP` 不被原样保存，存入和读取的地址 slice 都复制。外部修改原 resolver 结果或测试查询副本不能改写已经缓存的数值目标。

不使用 singleflight：同 Session 同域名的并发 miss 可以各自解析，但实际执行仍受 server 的两组许可和 Session Flow 上限控制。这样避免某个调用方取消与共享异步 completion 之间引入额外 owner 生命周期。不同解析返回不同合法地址时，各次拨号固定到自己完整验证过的结果；cache 只保留最后成功提交的正向集合。

## 5. 命中、解析完成和拨号的失效检查

处理顺序为：

1. 进入 `DialContext` 先检查调用方 context、scope 是否关闭、owner context 和有效性 guard。
2. 校验 network、hostname/port、port allowlist；使用原拨号许可和原 timeout。
3. 数值 IP 路径直接做全部原 ACL 和 owner guard，不绕过会话终态。
4. 域名路径先检查 scope cache，删除本地到期结果；命中值复制后再次验证全量地址和 owner guard。
5. miss 在实际 resolver 执行前获取共享 DNS 许可，并再次检查 owner；不额外分配无界查询队列或后台重试。
6. resolver 返回后先检查 owner，再检查返回数量/格式/zone 和全部 ACL。
7. 以查询开始时的 scope generation 提交。cache mutex 内同时检查 closed、owner context、guard 和 generation；任意失效均不写入。
8. 对选定数值 IP 的 OS dial 前再次检查有效性。OS dial 使用同时受调用方、Session scope 和原 timeout 约束的 context。
9. OS dial 返回后再次检查。若终态已经发生，关闭返回 socket 并返回错误，不将它交给 owner。

cleanup 同步设置 closed、递增 generation、清空 entry，并取消 scope context。重复 cleanup 不再次递增或重开。缓存读写使用有界短 mutex，resolver 与 OS dial 均不在该 mutex 内执行，故网络等待不会直接阻塞 map 清除。

最后一次 guard 与实际进入 OS dial 之间存在并发窗口，不能声称 context 已取消就绝不可能进入系统拨号函数。合同是：失效前已经开始的拨号立即受 context 取消；若不合作 dialer 在失效后仍返回 socket，则该 socket 被关闭且不交付。resolver 在关闭后才返回的结果则在拨号前被拒绝，不能触发新的拨号调用。

## 6. 不合作 resolver、系统缓存与 TTL 边界

一个 resolver 如果忽略 context，函数执行本身不能由 Go 强行中断。当前模块将 DNS 许可一直保留到该调用真正返回，不能在取消时提前归还，否则不断创建/取消 Session 就能突破 server 的实际调用预算。关闭 cache 不等待这类调用，迟到结果没有可提交的 generation，也不能命中或重新填充已经关闭的 map。

这组许可统计 BFP 的 resolver 函数调用。`net.DefaultResolver` 内部的 A/AAAA 查询、原生/cgo 工作、系统线程、系统 cache 或上游 server 的缓存都有独立边界；不能将 32 个调用许可直接写成“整个操作系统至多 32 个 DNS 包或原生工作线程”。系统 resolver 可能内部合并并发查询，也不能据此宣称两 Session 的 BFP cache 共用。

`LookupIPAddr` 只提供地址与错误，缺少 answer TTL、CNAME 链 TTL、negative TTL 和 DNSSEC 证明。本阶段只能准确称为“30 秒本地 max-age 的会话结果缓存”。如果后续要遵守权威 TTL，应引入有界、显式的 resolver result API，保留完整 answer set，并以整条使用路径的最小正 TTL 与本地上限/Session lifetime 取最严格值；TTL=0 不缓存。该扩展需要单独验证，不在此模块中通过假设 TTL 补齐。

close 清除协议持有的结果与 hostname 引用，不清理系统/上游 cache，不修改系统服务或 DNS 设置。Go 删除引用与 map 清空也不证明已把所有堆内存物理擦除；在途不合作 resolver 可能仍暂时持有入参和临时结果。文档和完成状态应按“协议缓存失效与归属销毁”表述，不声称控制 OS 内部或所有内存副本。

## 7. 已做测试与待做完整验证

gateway 一次定向命令已通过：

```text
go test ./gateway ./internal/backend -count=1 -timeout=60s
ok bfp/gateway 0.647s
?  bfp/internal/backend [no test files]
```

证据见 [gateway-summary.json](C:/Users/developer/Desktop/bfp/.staging/r9-next8/verification/session-dns/gateway-summary.json) 和 [gateway-go-test-tool-capture.txt](C:/Users/developer/Desktop/bfp/.staging/r9-next8/verification/session-dns/gateway-go-test-tool-capture.txt)。原工具只保留包级简明输出；summary 明确标为 `partial_tool_capture`，没有补造 verbose 日志，也没有重复执行同一测试来补日志。source hashes 是记录时的当前源码快照，正式冻结版本还须绑定自身 manifest 和完整门槛。

[gateway/session_dns_test.go](C:/Users/developer/Desktop/bfp/.staging/r9-next8/gateway/session_dns_test.go) 的定向覆盖包括：

- factory 创建不查询 DNS；同 Session 命中、不同 Session 独立结果、一个 scope 关闭不影响另一个。
- 精确 30 秒边界到期、64 entry 上限、resolver 原 IP 与输出 slice 的防别名复制。
- 混合允许/禁止地址和其他网络族私网地址先全量拒绝，允许集合才拨数值 IP。
- hostname/answer 预算、空结果/解析错误/拒绝结果不缓存。
- close、owner cancel、撤销和寿命 guard 变化后的迟到 resolver 不入 cache、不 dial；缓存命中与数值 IP 也不能绕过失效。
- clone 共用拨号许可；不合作 resolver 在 scope 关闭后仍占实际执行许可，返回后才归还。
- 失效时已经开始的 dial 返回 socket 后关闭；单个调用方取消不破坏仍活动 owner 的 cache。

Session 接线当前已存在，以下实际联动证据仍需独立确认，不能用上述模块测试替代：

| 门槛 | 所需证据 |
|---|---|
| fresh confirm 之前零副作用 | HELLO、bad confirm、错误设备/恢复 proof 不调用 factory，不 lookup、不 dial；合法 confirm 仅创建一次空 scope |
| 初次 UDP/TCP 候选与同 attempt | 两候选竞争只生成一个 Session scope，重复 confirm 不重复生成 |
| 同 Session carrier 恢复 | 用真实加密 UDP→TCP / attach 保留原 scope 和未过期正向结果，不重新调用 factory；原目标连接不被 DNS cache 重建 |
| 新 Session 隔离 | 同域名建立不同 Session 必须调用独立 resolver/cache，旧已关闭 Session 不能成为新 owner 的命中来源 |
| 终态立即失效 | SessionClose、Close、RevokeDevice、MaxSessionLifetime、RetainTimeout、父 Server cancel 后，cache、迟到查询和迟到 socket 都不能可交付；done 前 cleanup 完成 |
| failed initial attach | 创建 scope 后 attach 失败必须走终态 cleanup，不留活的私有 cache |
| nil factory 结果 | nil 与 typed-nil 都 fail closed；不在未来 OPEN 中 panic；cleanup 仍至多一次 |
| 并发与资源 | 并行 OPEN、close/revoke/expiry、排队取消与不合作 resolver 的 `-race`；server-wide 实际 resolver/dial 预算不随 Session 数增长 |
| 正式版本 | 冻结源码清单、完整 Go tests/vet、Windows/Linux build、独立 race；新的联动证据只覆盖对应 revision，不能移用旧版本 |

无需为了这个内存归属阶段立即增加 WAN 负载。先完成实际 Session 与 gateway 联动的本地加密承载测试及 race，再决定与后续适配层 DNS/IPv6/fake-IP 门槛的关系；任何新业务实验都保留事前冻结期限和失败，不通过延长时限或重复 unchanged 场景筛选通过。

## 8. 本次审查发现的接口边界

初次审查 `backend_scope.go` 时只看到 `scoped == nil` 判断。Go 的 typed-nil Dialer 接口可能非 nil，之后会在目标 OPEN 中 panic；base backend 的 `NewServer` 检查也有同类问题。root 后续已加入共用 `backend.IsNil`，本次回读确认 `NewServer`、scope 的 base 和 factory 返回结果都调用它。此项源码修正已接入，factory/base 的实际测试结果仍应由对应门槛确认，不能用 gateway 的非 nil 正常返回替代。

自定义 factory、valid 或 cleanup 如果违反“不做 I/O、不阻塞、线程安全、幂等”合同，会使锁内初始化/终态等待阻塞。默认 gateway 已按该合同实现；管理层 timeout 不能被写成可强行杀死任意 Go 回调的保证。

本文不标记全协议生产可用，也不把 session DNS cache 的完成推导为 TUN、client DNS、fake-IP、IPv6 或系统 cache 清理已经交付。最终状态需要由对应 revision 的 Session 联动、完整本地门槛与明确边界共同证明。
