# r9-next25：客户端 DNS、出口候选回退与 UDP 目标生命周期

状态：整合候选本地门禁、实际 CLI smoke 与洛杉矶独立 Linux race 已通过，已晋级项目根目录；最终验收仍未完成。

本轮把客户端 DNS 入口、gateway 出口排除策略和 Mihomo UDP 目标生命周期合入同一开发候选。整合候选的本地门禁、实际 CLI smoke 和绑定源码的洛杉矶 Linux race 均已登记；分支的局部通过不代表整合候选通过。Linux race run `5d31a139671ccfc66a5cc0877a7a5591` 的编译准备与完整 race 均 exit 0，20 个有测试包 + 2 个无测试包全部有终态，638 项顶层测试通过且无 `DATA RACE`；源码/二进制绑定未变、owned 清理与接收机快照比较通过。证据见 [race 结果](../.staging/r9-next25/lab/runs/5d31a139671ccfc66a5cc0877a7a5591/race-result.json) 和 [next25 证据索引](../.staging/r9-next25/verification/r9-next25/evidence-index.json)。四类状态仍为 2 类核心实现、2 类部分实现、0 类最终验收，`acceptance_complete=false`、`production_ready=false`、`released=false`。

## 客户端 DNS 配置与实际业务路径

在 `bfp keygen` 生成的客户端私有配置中增加以下根字段，保留该文件原有的服务器与凭据字段：

```json
"dns": {
  "listen": "127.0.0.1:15353",
  "mapping_ttl": "10m",
  "mapping_capacity": 64
}
```

该入口同时绑定 UDP 和 TCP，当前只合成 IN/A 记录。它与 SOCKS 使用同一个 Client 及其选定的 Session。客户端查询域名得到 `198.18.0.0/15` 中的临时地址；随后 SOCKS 收到该地址时，通过同一 Session 的映射还原域名，再经加密 BFP OPEN 交给出口策略处理。

省略 `dns` 保留原行为。显式 `null`、空对象、未知字段、重复字段和大小写变体均拒绝。监听地址必须是没有 zone 的数值 loopback 地址，端口使用规范的十进制表示，范围 0–65535；0 由系统分配临时端口。映射 TTL 默认 10 分钟，必须为正且不超过 720 小时；容量只接受 64 或 128，默认 64。

DNS 监听入口没有独立的长期映射缓存。会话终态使原映射失效；新会话建立自己的作用域。关闭监听入口只结束它所拥有的监听与请求任务，调用方仍存活的 Client/Session 继续拥有映射。Client 终止后，原作用域不能继续分配或还原地址。

启动日志在入口请求开始前捕获当前 Session 的统计。没有已选定 Session 时返回 `session.ErrClosed`；日志不会通过调用 Connect 创建会话，也不会在可能变为 nil 的 current 指针上调用 Stats。两个入口中任意一个 Serve 返回，helper 都取消并关闭另一个，再等待两者退出。

公开的 `clientconfig.Load` 仍是最小凭据加载器。它识别 `dns` 为高级 CLI 配置并明确返回 `ErrUnsupported`；宿主软件应使用自己的 DNS 子系统，不会因读取该字段就隐式启动 BFP DNS 监听。

这段实际接入尚未配置系统 DNS、创建 TUN 或安装主机路由，也没有实现 AAAA/EDNS 与完整 IPv6 系统入口。

## 出口拒绝网段

`gateway.Policy.ExcludedCIDRs` 在服务器出口拒绝指定网段。`gateway.ErrRouteExcluded` 可以由调用方用 `errors.Is` 识别。IPv4、IPv6 和 IPv4-mapped 地址/CIDR 在构造时规范化。

数值目标直接检查；域名只进行一次有界解析，并在创建任何 socket 前检查全部候选。任何候选命中排除策略，整次请求拒绝，即使另一个候选原本允许。未还原的 fake-IP 继续被拒绝。该字段不实现客户端 direct/bypass，也不负责排除 BFP 承载连接的主机路由。

## TCP 域名候选连接失败后的回退

实际 CLI smoke 发现，Windows 上 Go 的 `localhost` 解析顺序为 `::1`、`127.0.0.1`；只监听 IPv4 的 echo 目标无法接受首个 IPv6 连接。原 gateway 在首次连接失败后直接返回，没有尝试已验证的 IPv4 候选。原失败保留在 next25-cli 的 CLI smoke attempt02；独立 Go resolver 与真实回环拨号的复现保留在 next25-connect 的 `localhost-before.json`。

修复范围为 TCP、tcp4、tcp6 的数值候选连接回退。所有候选先通过同一次解析的策略验证，然后按地址族筛选。各次连接尝试共享一个调用期限和一个并发许可，每次拨号前后都检查 caller/Session 是否仍有效。连接成功立即返回；失败返回的异常非 nil socket 先关闭；会话失效、撤销、取消或期限到达后停止继续尝试。操作系统始终接收已检查的数值地址，不重新解析域名。

UDP 保持一次固定 peer 的语义。UDP Dial 成功本身不能证明远端应用存在，本轮没有增加数据报重发或把未知交付改写为失败后的重放。

## UDP 目标代次与 Mihomo 事务

公共 PacketConn 为每个实际目标分配单调的 `packet.TargetToken`。token 同时绑定地址、generation 和不可由外部直接设置的 PacketConn owner。同一地址退休后重新打开，必须得到新 generation；计数达到上限时在分配资源前拒绝，不能回绕并复用旧 token。

`MetadataForTargetToken` 让受信本地宿主为确切目标代次附加元数据，与旧的 `MetadataForTarget` 互斥。`ExposeTargetToken` 使回包携带实际来源代次；`TargetAlive`、`RetireTarget` 和宿主来源还原均验证 owner 与 generation。退休清除该目标排队的回复，并通知宿主删除对应映射；旧回包不能在同地址的新关联上取得新的 origin。

Mihomo sender 采用 Prepare/Write/Commit/Abort：Prepare 返回单次写入的 opaque 事务地址；tracker 执行真实 WriteTo；成功后 Commit 发布回复映射；失败、取消或未提交事务由 Abort 回收。快速回包必须等待成功发布，Abort 或退休则结束等待并拒绝。目标映射跟随公共 PacketConn 的真实生命周期，回复活动会延长其实际闲置期限，不使用另一个固定一分钟的映射过期计时器。

本地 metadata/退休回调是受信接口，必须配合上下文并及时返回。回调 panic 被捕获并记录为 cleanup failure；任意不配合的本地回调不能获得无条件有界退出保证。该边界应与协议对网络输入的资源限制区分。

## 源码合并与证据

next24 父源码、next25-cli、next25-dns 和 next25-connect 的原记录保留。整合只复制 Go/module 文件，先以同一父清单检查冲突并备份生命周期分支，再产生合并清单。整合候选必须有自己的完整本地 test、vet、Windows/Linux 构建及实际 CLI smoke。

实际 CLI smoke 使用临时 keygen 凭据、本机 fixture、BFP server/client 和真实 SOCKS 请求。它验证 DNS 的 UDP/TCP 查询共享一个临时地址、该地址可经 SOCKS 与加密 BFP 到达真实 TCP echo；退出后结束 owned 子进程并删除私有 runtime。第一次失败来自测试脚本未处理 DNS 压缩指针；第二次已通过 DNS 解析，在真实 gateway 地址选择阶段失败。修复后的新尝试不能覆盖这两条失败。

如将候选晋级至项目根目录，应先保存根目录历史 r8 源码与每文件回滚映射，只复制 Go/module 源码，核对根目录与冻结候选逐字节一致。历史实验、verification、lab、bin 和 dist 不由源码晋级覆盖。

## 当前仍需完成的范围

系统 DNS/TUN/IPv6、客户端实际承载路由排除与 detour、混合类别和 FEC 实网性能、完整原生软件支持矩阵、长期资源测试、互操作向量和独立安全评审继续作为完整目标。新加坡链路较慢，本轮开发优先本地与洛杉矶隔离验证，避免增加新加坡上传负担。旧 WAN 严格失败仍保留，不能作为新候选的通过结果。
