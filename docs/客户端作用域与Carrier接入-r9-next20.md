# r9-next20：客户端 Session 地址作用域与 Carrier 拨号接入

日期：2026-10-09。合并候选：`C:/Users/developer/Desktop/bfp/.staging/r9-next20`。共同父边界为 next19；两项切片先在独立目录实现，再三方合并。只复制 Go/module 源码和实现说明，没有复制旧 gate、binary、race 或 WAN 结果。next19 的严格 WAN FAIL 保留。

本页保留 next20 的历史结果：attempt01 本地检查通过，加入 factory 取消修复后的 attempt02 因关闭测试严格失败，未执行 next20 race/WAN。后续 next21 已独立通过本地、有限 fuzz 和 Linux race；next22/23 各自的本地检查通过，真实上游 fork 已有原生代码，但完整接入仍未验收。最新证据见 [next21](客户端DNS与数据报恢复-r9-next21.md) 和 [next22/23](公共UDP与原生接入-r9-next22-23.md)，不覆盖 next20 的原始失败。

## 合并后的实际行为

`ClientConfig.AddressScopeFactory` 在首次确认的新 Session 中创建客户端本地地址映射。`Session.LocalAddressAllocator()` 返回这个具体 Session 的 allocator。`Client.Dial*` 选择一次 Session，地址还原、分类与 OPEN 在该 Session 的业务准入内完成；Carrier 恢复不会更换 map。关闭、到期和取消使保留的 allocator 失效，并清理映射。恢复只允许缩短原期限。反向映射不能修改网络、交付、FEC 或本地元数据的可信来源。

`gateway.NewFakeIPScopeFactory` 使用不回绕游标；同一 factory 生命周期内的新 Session 不立即复用旧地址。它不保留旧域名或 Session 身份，不覆盖进程重启、替换 factory 或外部 DNS 缓存的归属隔离。配置 scoped Client 的 SOCKS Backend 不能再同时配置独立 `TargetRestorer`，避免先用旧映射还原后再自动选择新 Session。

`ClientConfig.DialUDP` 接收宿主提供的 `net.PacketConn` 和具体 UDP peer；库固定 peer、过滤其他来源并保留报文边界。`DialTCP` 接收专用 TCP stream。首次 UDP、初始 UDP 失败后的 TCP fallback，以及运行中的 TCP 恢复均接入相同拨号入口。socket 返回后归 BFP 所有；迟到结果关闭，不安装到 Session。每 Client、每 carrier 类型最多一个未退出的 hook callback。没有配置 hook 时仍使用 `net.Dialer`。

## 验证与公开工厂取消修复

组合回归使用不可直拨的 `.invalid` carrier 配置，通过 hooks 创建真实本地 sockets；正常 UDP、初始 UDP 黑洞转 TCP、运行中 UDP 黑洞转 TCP 三场景通过。测试同时检查同一 Session/map、单一 TCP 目标连接、随后 UDP 业务、关闭时映射失效，以及新 Session 对旧 fake-IP 的零 OPEN 拒绝。第一次新 fixture 因只允许 `tcp4` 而拒绝实际 `tcp` 目标；更正 fixture 后通过，原日志保留。

第一次完整本地 gate 冻结 164 个 Go/module 文件，manifest `1ae18b2669a9f502bc36b2a6cb9c00547f762de5e050bbffc021753301073613`。17 包、531 个顶层测试、vet、Windows/Linux 构建通过，源码未变，206.689 秒。结果仅证明这份源码的上述本地检查；见 [attempt01](../.staging/r9-next20/verification/r9-next20/local-gate-attempt01/local-summary.json)。

独立外部 Go module 编译确认宿主可以使用公开 aliases、factory 与两种 dial hooks，不需要导入 `bfp/internal`。随后真实审核复现了一个未被首轮测试覆盖的缺陷：`Connect` 同步调用自定义 factory，但 factory 获得的是独立 Session context，无法收到 Connect 的操作截止或 `Client.Close` 的握手取消；等待这个取消信号的 factory 可以阻塞 Connect 和 Close。内置短操作 factory 的组合回归不覆盖这一公共扩展问题。

修复在独立 `.staging/r9-next20-factoryfix` 完成并合入。每 Client 在握手前保留一个 factory callback slot，创建预算取 HandshakeTimeout 与 Connect 剩余期限的较早者；Connect/Client 取消可以结束等候，成功 scope 脱离单次操作取消并归 Session。迟到或失败 scope 清理一次。相关真实定向与外部 module 测试通过，首轮 gate 和原始复现保留。

实际 attempt02 冻结 166 个文件，manifest `8621b18909cd4fcac1700f03863b60b4da2e7a9685b364cc09d259f6b5cd047e`，源码未变，208.43 秒。538 个顶层测试通过，Session 包的 `TestBoundedCloseSimultaneousRequests/both-ack-directions` 观察到 ACK=0，导致完整 test 严格失败；vet 和 Windows/Linux 构建通过。原失败日志和二进制保留在 [attempt02](../.staging/r9-next20/verification/r9-next20/local-gate-attempt02/local-summary.json)，没有据此启动 next20 race/WAN。

后续 `.staging/r9-next21` 补 queued Connect 取消、客户端 DNS、数据报恢复等待与原始截止，并只对上述关闭测试的前置交付条件做修正。其 attempt02 的 181 个源码文件、18 包、578 顶层测试、vet、两平台构建、有限 fuzz 和独立 Linux race 已通过；它没有借用 next20 的首轮结果。next21 自身 WAN 未执行，详见 [next21 合并记录](客户端DNS与数据报恢复-r9-next21.md)。

## 仍未完成

- 服务端撤销目前没有向 UDP 客户端发送认证撤销通知。本地关闭同步清理与 TCP 可观察断路后的 retention 清理，不证明远程 UDP 撤销即时到达。
- next20 提供 Session map 和 socket 接口；next21 新增 loopback DNS A 前端，完整 DNS/TUN/NAT/IPv6 仍未完成。后续 Mihomo/sing-box 已有真实原生 registry/outbound 及本地证据，完整支持矩阵仍待验收。
- next21 已实现 suspect 后停止旧 UDP 业务提交和未提交整报生命周期，且完成源码绑定的本地/fuzz/race 检查；实网行为仍需自己的验证。已提交、送达未知的数据报不得为了补齐测试重放。
- 混合类别/FEC WAN 性能、长期资源稳定性、完整复杂故障矩阵、独立安全审核及跨实现互操作仍需验证。

四类仍为 2 类主体实现、2 类部分实现、0 类最终验收。`acceptance_complete=false`、`production_ready=false`、`released=false`。
