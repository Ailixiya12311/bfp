# BFP 可运行预览版

2026-10-13 当前交付入口是 `credentials-client-ready/BFP 客户端/BFP客户端.cmd`，Windows preview.7 / native preview.36。应用代理已用当前程序完成真实公网 HTTPS，出口 `192.0.2.10`，停止后资源释放；证据为 `verification/product-windows-tun/proxy-preview7-real.json`。公开包为 `dist/BFP-Client-Windows-0.1.0-preview.7.zip`，不含密钥。两台现有 BFP 实例也已升级到 preview.36；新加坡单次 HTTPS 检查取得 207 字节响应并确认洛杉矶出口。

全局 TUN 仍在修复：2026-10-13 最新管理员实机 attempt07 使用私有 debug-tun07，达到 ready 后 HTTPS 仍返回 curl 35 / TLS 握手失败；30.84 秒内完成，最终网卡库存、物理 DNS、默认路由与客户端资源恢复，清理通过。三次业务会话结束中仅一次早于 stop 日志创建，其 owner 为 1；此时业务上下文结束、控制上下文仍存活、无关闭意图，来源仍为 `context_end_without_cancel`。新增 parent/outbound/owner 诊断仍未解释根因，不能认定来自 Fake-IP flush、对端关闭或某一 DNS 请求。HTTPS 失败后未进入强杀恢复场景。结果为 `verification/product-windows-tun/windows-tun-real-attempt07.json` 与 `windows-tun-real-attempt07-audit.json`，旧 attempt03 至 attempt06 不改写。开发源码继续补齐原始业务取消边界和本地转发复现；诊断不是修复完成的新发行版。系统代理锁竞争、累计流控制预算和失效 Fake-IP 租约重试修复均未被确认为 TUN 根因。尚未通过 TUN 联网和强杀恢复，不能称为成熟成品。原交付记录为 `verification/product-windows-tun/release-client-preview7.json`；后文保留对应历史版本的说明，旧独立根包 preview.23 也保留，当前两台实例使用 native preview.36 包内的 BFP 程序。

BFP 是独立的 Go 代理协议。客户端默认通过 UDP 加入服务端的会话网络，UDP 初始连接失败或运行中失效后，使用同一服务端的 TCP 承载。会话里的可靠流和目标 socket 在有效保留期限内继续使用。

当前协议程序位于 `dist/BFP-Mihomo-0.1.0-preview.36/bin/`，其中 BFP 的 Windows/Linux amd64 客户端与服务端使用同一个程序，源码在包内 `source/bfp`。历史独立根包 `dist/BFP-0.1.0-preview.23/` 及 ZIP 保留。各版本程序哈希见对应包的 `release-manifest.json`；下文旧版本的 WAN 记录仍属于当时的二进制。

preview.23的协议修复：TCP与UDP共享已认证bootstrap密文的防重放缓存；已经提交的CONFIRM只接受首次合法Message密文的相同重试，篡改请求不返回缓存READY。LIGHT保留原有填充预算，并增加最多63字节的随机桶尾；普通单范围UDP ACK由恒112字节变为112–166字节，反馈总开销仍不超过66字节，UDP记录仍不超过1200字节。缓存仅保留约1分钟、最多4096条，旧INIT在缓存到期或服务端重启后仍可能获得候选响应；本轮没有加入时序整形或永久防重放。字段和wire3版本保持兼容，参见 [wire合同](docs/wire-v0.1.md)。

## 直接运行

已有当前项目试用配置时，双击根目录 `BFP客户端.cmd` 打开 Windows 控制窗口，点击“启动”，应用填写 HTTP/SOCKS5 `127.0.0.1:17890`，再点击“检查出口”。窗口可关闭并保留客户端运行，重新打开后可停止。窗口提供进程归属状态、出口检查、复制地址和启动日志；命令入口另有 `启动BFP.cmd`、`停止BFP.cmd`、`状态BFP.cmd`、`检查BFP.cmd`。该窗口使用当前项目的私有试用配置，不在旧冻结发布 ZIP 内；软件包单独运行方式如下，详细管理见 [双机试用部署](deploy/README.md)。

现在另有 `dist/BFP-Client-Windows-0.1.0-preview.4.zip`，独立客户端包含相同控制窗口、Windows 原生程序、完整冻结源码和许可证。它使用固定的相对目录布局，停止后可以整体搬动；公开 ZIP 不含密钥，将已有受服务端授权的客户端配置放入 `client/credentials/client.json` 后运行。本机已配置且受 ACL 保护的私有副本位于 `credentials-client-ready/BFP 客户端`。它使用原生 preview.33，将 Windows TUN 接管与恢复带入实际客户端。

preview.4提供“应用代理 / 全局 TUN”模式选择。TUN 的管理员启动、服务器地址路由排除、出口网卡绑定、就绪判断及恢复实现见 [Windows 全局 TUN](docs/Windows全局TUN-v0.1.md)。实机验收仅以本轮对应记录为准，完整系统生命周期和长期稳定性仍在完善。

应用代理提供当前用户Windows系统代理接管：启动代理后点击“接管 Windows 系统代理”，遵循系统代理的应用即可使用；“恢复原代理设置”单独撤销接管。普通停止、自然退出和独立监控观察到的启动器强杀会恢复原设置；身份无法验证时保留备份等待重试。若用户或其它软件修改代理，BFP保留当前设置、归档原备份并释放自己的接管。该功能不接管WinHTTP、系统DNS或不遵循代理的应用，全局TUN的实现与实机验证范围见上述说明。

Windows：在解压包目录打开 PowerShell。

```powershell
.\bin\bfp-windows-amd64.exe version
.\bin\bfp-windows-amd64.exe demo
```

Linux：在解压包目录执行。

```sh
chmod +x ./bin/bfp-linux-amd64
./bin/bfp-linux-amd64 version
./bin/bfp-linux-amd64 demo
```

`demo` 在内存中生成临时凭据，启动本地 BFP 服务端、SOCKS5 入口和 TCP/UDP echo 出口，再实际通过加密 UDP 会话收发 TCP/UDP 数据；同时用一个故意拒绝 UDP 物理拨号的临时客户端验证初始 UDP→TCP 回退。成功时输出 `"event":"demo_pass"` 和 `"fallback_carrier":"tcp"`。它只监听本机回环地址，不访问两台测试服务器，也不生成凭据文件。

## 原生应用接入

当前原生接入包为 `dist/BFP-Mihomo-0.1.0-preview.33/` 及同名 ZIP，包含当前 BFP 程序、Mihomo 原生 BFP 出站、gVisor TUN、两平台启动脚本与可搬目录重建源码。Windows 普通代理入口为 `start-native.ps1 -Mode proxy`，应用连接 HTTP/SOCKS5 `127.0.0.1:17890`。完整生成配置、Linux 命令和 TUN 范围见 [Mihomo 原生接入](docs/Mihomo原生接入-v0.1.md)。

preview.22 / 原生 preview.31 统一了 `client.json.classification` 的严格解析。同一份文件可供独立 BFP 客户端和原生 Mihomo 使用；Mihomo YAML 中若显式设置 `proxies[].classification`，它会替换 JSON 中的整个策略，不做合并。公共文件加载器仍拒绝 `options`、`socks_metadata`、`datagram_fec` 和 `dns` 字段。

preview.31 修复 Windows 原生启动器按模式分配不同 Mutex 的问题，并让 Go 监督器在启动器强制结束时回收 Mihomo 子进程和临时 TUN 状态。proxy 与 TUN 共用 `Local\\BFP-Mihomo`，同一个包实例不会同时占用 mixed port、runtime 或生成配置；根包 preview.22 的 demo 自检也覆盖初始 UDP→TCP。进程级回归见 `verification/product-mihomo/release-preview31.json`。

生成新配置时可加 `-classification-profile low-bandwidth`。该预设把 UDP 53、TCP 22 固定为 Interactive，其他流初始为 Normal；累计至少 32 KiB 且持续满足 8 KiB/s 阈值时归为 Bulk，持续低于 2 KiB/s 后恢复。观察窗口为 4 秒，高速持续期为 3 秒，恢复持续期为 8 秒，具体判定还受活动间隔与冷却时间约束。它调整分类和调度，不是限速器，也不改变流可靠性或 FEC 协商。默认 `standard` 保持原有行为。

preview.23 修复 Linux TUN 被强杀后策略规则残留的问题。每次启动选择空闲路由表和规则范围，保存完整内核规则；子进程或入口被 SIGKILL 后清理本实例，整组进程被 SIGKILL 后由下一次 proxy/tun 启动持锁恢复。预先存在的 IPv4/IPv6 9000 优先级规则保持不变。

preview.23 当时通过 Windows 原生代理的 7 个目标 TCP/UDP 往返、配置及错误诊断检查；洛杉矶隔离环境的三种自动路由强杀/恢复，以及另一轮 8 个 TUN 数据场景、初始/运行中 UDP→TCP、重复启动、SIGTERM、旧设备恢复和缺失 TUN 拒绝均通过。两轮远程资源清理与宿主基线比较通过，那一轮未使用新加坡。记录见 [preview.23 生命周期](verification/product-mihomo/lifecycle-linux-preview23.json) 和 [preview.23 包校验](verification/product-mihomo/package-check-preview23.json)。这些旧记录不改写为 preview.24 的新运行。

Linux 强杀检查使用隔离命名空间的自动路由，8 个数据场景另用隔离 UID 路由；Windows 检查为回环代理。宿主/Windows TUN、真实公网承载路由排除、IPv6 公网、跨系统启动恢复、自定义 auto-redirect 防火墙状态、完整负向矩阵及长期负载仍未完成。最近 TUN WAN 仍绑定 preview.19。四类保持 2 类核心实现、2 类部分实现、0 类完成最终验收。

preview.19 修复 Linux 启动器的三处产品问题：两种模式共用实例锁，第二次启动不能覆盖第一实例的标记；随机 TUN 名称缩短到 Linux 的 15 字节限制内；TUN 未创建时，启动器会停止子进程并返回错误。SIGTERM 收尾会先停止子进程，再删除本实例的网卡、标记和生成配置。Linux 需要 util-linux 的 `flock`，TUN 还需要 iproute2 的 `ip`。

此前 preview.19 的 Linux 启动器已在洛杉矶 owned network-none 环境验证：8 个 IPv4/IPv6/Fake A/AAAA 的 TCP/UDP 场景都有 TUN 与出口抓包证据，运行中/初始 UDP→TCP、未知 Fake-IP 拒绝、路由删除阻断、重复启动、SIGTERM 清理、旧标记恢复和缺失 TUN 拒绝均通过。摘要见 [Linux 启动器与 TUN 证据](verification/product-mihomo/lifecycle-linux-preview19.json)，run `d2a5f6b1b8dafb7146edf2e01cebb14e`。该记录使用隔离 UID 路由，不等于宿主自动路由或实网验收。此前 preview.18 的超长网卡名失败记录保留在 run `43be83d1e63034cef82fcfa0d62514cc`，没有改写为通过。

preview.19 另已完成新加坡→洛杉矶的 TUN WAN，run `cff1977f1f1af2aec6e01372d0b4178e`。新加坡 owned network-none 容器运行包内启动器和 Mihomo，使用自动路由；UID 20001 的普通内核 socket 经 TUN 发出 UDP/TCP DNS 查询，取得 Fake A/AAAA 后建立一条 TCP 和一条 UDP 连接，并各交换 12 次 1024 字节，间隔约 1 秒。正常 UDP、运行中 UDP→TCP、初始 UDP 阻断后三场均为 TCP/UDP 12/12。运行中同一 Session 的承载代次 1→2，临时逻辑地址、原目标 TCP 连接与 Fake-IP 租约保持。三个场景均通过数值 IPv4 UDP、退出后网卡/标记清理和自动路由/策略规则恢复；随机探测、owned 资源清理和双机基线比较通过。摘要见 [TUN 实网证据](verification/product-mihomo/wan-tun-preview19.json)。

TUN WAN 的加密承载经私有 Unix socket 桥接到宿主 WAN socket，BFP 在隔离命名空间使用回环承载和显式 lo 接口；该 fixture 不改变协议字节。公网承载使用 IPv4，覆盖的 IPv6 是 Fake AAAA 应用路径。宿主全局路由、真实公网承载地址在 TUN 下的路由排除、Windows 系统 TUN、IPv6 公网承载、整组进程同时强杀及自动路由模式的完整异常清理仍待验证。切换场最长 TCP/UDP echo 操作为 2984.3/3021.6 ms，包含 fixture 和恢复时间，不是独立切换停顿指标，也不能保证所有 UDP 数据报无损。业务期间的承载轨迹和退出后的 suspended 状态分别保留；此前三个 fixture/采样失败 run 原样保留在摘要索引中。

Windows 已使用 preview.17 包的 native 程序通过两份样例配置检查，以及数值 IPv4/IPv6、域名和 UDP/TCP DNS Fake A/AAAA 的实际 TCP/UDP 往返；同一包的 Windows native 回环生命周期记录为 `verification/product-mihomo/lifecycle-preview17.json`。这些是本机应用接入证据；当前包另有下面的 Linux 原生代理 WAN 记录。完整 TUN、平台与系统生命周期仍未验收完。

preview.14 已有一条可复核的 Linux 隔离 TUN 通过记录：洛杉矶测试机 `192.0.2.10`、run `44bb2d84fb410062a2a10f487ac54daa`。它实际跑通 8 个 IPv4/IPv6/Fake A/AAAA TUN TCP/UDP 场景、运行中和初始 UDP→TCP 回退、未知 Fake-IP 拒绝、路由删除阻断和正常退出清理。这是当前 TUN 的隔离验证基线，不是 preview.17 新包的实网验收。完整记录见 `verification/product-mihomo/runs/44bb2d84fb410062a2a10f487ac54daa/remote-result.json`，摘要见 `verification/product-mihomo/session-dns-preview14.json`；preview.17 的 Windows native 回环证据见 `verification/product-mihomo/lifecycle-preview17.json`。

preview.17 根协议包已经重新跑过一轮真实 WAN：新加坡 `198.51.100.20` 发送、洛杉矶 `192.0.2.10` 接收/出口，三场各 12 次、TCP 每次 1 KiB、间隔 1 秒。正常 UDP 为 TCP/UDP 12/12；运行中 UDP→TCP 为 TCP/UDP 12/12，保持同一 Session 且 generation 1→2；初始 UDP 阻断后由 TCP 接管，TCP/UDP 12/12。随机探测无应用响应、目标连接数无副作用、两端 owned 进程和目录已清理、基线快照未变化。摘要见 `verification/product-mihomo/wan-preview17.json`，原始记录见 `lab/runs/fcc4afa13f17944db9547f86cb565a8b/wan-result.json`。

此前 preview.16 运行中切换的 UDP 11/12 严格失败记录继续保留在 `verification/product-mihomo/wan-preview16.json`；preview.17 的有界 handover 重放修复后，新的同场景记录为 12/12。上述根协议记录和下面的 Mihomo 原生代理记录分别绑定各自包内二进制。

preview.17 原生 Mihomo 代理包也已完成新加坡→洛杉矶 WAN 矩阵，run `b5e027d27b1e07dddd617a86e96b0ba6`。每场保持一条 SOCKS TCP 连接和一个 SOCKS UDP association，TCP/UDP 各发送 12 次 1020 字节，间隔约 1 秒。正常场使用 UDP（generation 1）；运行中 UDP 黑洞后，保持同一 Session 和原目标 TCP 连接，转为 TCP（generation 2）；初始 UDP 阻断场通过 TCP 建立会话（generation 1）。三场均为 TCP 12/12、UDP 12/12。8 次 TCP 与 16 次 UDP 随机探测无应用响应、无新增目标连接，测试进程/运行目录清理与两端基线比较通过。程序与配置哈希已核对包内清单；摘要见 [原生代理 WAN 证据](verification/product-mihomo/wan-native-preview17.json)，原始记录见 `verification/product-mihomo/runs/b5e027d27b1e07dddd617a86e96b0ba6/native-wan-result.json`。

这条新记录覆盖原生代理模式和数值 IPv4 echo 目标，不覆盖 TUN、系统 DNS/路由、IPv6 WAN 或长期负载。切换可能暂停读写，本轮没有单独测量切换停顿，也不保证所有 UDP 数据报无损。原始脚本的负载字段写为 1024 字节，实际逐次记录是 1020 字节；摘要保留并说明该差异，原始结果未改写。

## 两台机器使用

完整命令见 [成品运行与部署](docs/成品运行与部署-v0.1.md)。当前角色是洛杉矶 `192.0.2.10` 为接收/出口，新加坡 `198.51.100.20` 为发送/客户端。启动客户端后，将应用的 SOCKS5 代理指向 `127.0.0.1:1080`；域名经 SOCKS 交给出口处理。

凭据由 `keygen` 单独生成；交付包不含 SSH 或 BFP 私密配置。完整 TUN、系统路由和原生 Mihomo/sing-box 的平台矩阵仍未验收。

## 四类需求目前做到哪里

| 需求 | 已有实现 | 尚未完成的范围 |
|---|---|---|
| 认证复用 | 首次认证后复用 Session、多流、密钥 epoch 更新、Ticket 刷新；UDP→TCP 恢复保留存活会话和目标连接 | 更长时间的恢复、资源压力和异常矩阵；独立安全审查 |
| 混淆与防主动探测 | 加密内部地址/流编号/帧、受保护记录、首包准入、防重放、随机长度填充；无效请求不返回应用数据 | 时序整形、掩护流量、专项安全审查；公网 IP、端口、包长和时序仍可观察 |
| 协议内分流 | 本地分类规则、可信元数据入口、行为分类、三类调度，以及按类别配置的数据报纠错策略 | 完整原生适配、混合负载公平性与背压、真实丢包路径上的纠错收益 |
| 短时会话网络 | 会话拥有临时地址、流和目标连接；关闭/到期清理；根模块与原生 Mihomo 的 DNS A/AAAA 映射都绑定 Session，旧地址终止后失效；Linux 隔离 TUN 的自动路由、DNS 劫持与 WAN 切换保持租约已通过 | 宿主/Windows TUN、完整系统 DNS/路由异常生命周期、IPv6 公网承载；当前不是完整二层局域网 |

计数口径仍是 **2 类已有核心实现、2 类部分实现，4 类均未完成最终验收**。每条加密记录仍做完整性和重放校验，“认证复用”仅表示不重复完整身份握手。

## 本次功能更新

会话 DNS 支持 A/AAAA。两个地址共用同一域名映射、不可续期的原始租期和 Session 所有权；关闭或过期一起失效。IPv6 临时池为 `fd42:6266:7000::/96`，未映射或带 zone 的地址不进入真实拨号。自定义地址 scope 只有显式支持 IPv6 租约时才可以回答 AAAA；旧 IPv4 scope 仍可使用 A。

原生 Mihomo 的 Fake-IP 配置增加 `dns.fake-ip-session-proxy: BFP`。启用后地址分配直接调用 BFP 出站的当前 Session，承载从 UDP 切到 TCP 时不建立新映射；Session 终止后 DNS、TCP 和 UDP 目标准备都会重新验证租约，旧地址不会自动加入新 Session。该模式禁止 `profile.store-fake-ip`，并要求使用 `198.18.0.0/15` 与 `fd42:6266:7000::/96` 的临时池。配置检查和跨会话失效回归记录见 `verification/product-mihomo/session-dns-preview14.json`。

普通 EDNS(0) 查询已支持，不再返回 NOTIMP。UDP 响应按客户端能力限制在 512..1232 字节，传统 DNS 的 UDP 上限为 512；TCP 使用独立的 1232 字节消息上限。响应保留 DO 提示，AD/AA/RA 不置位；未实现的选项忽略且不回显，不参与出口目标选择。不支持的 EDNS 版本返回 BADVERS；无效 OPT 在选择 Session 之前拒绝。映射或 Session 在派发前失效时，返回保留 OPT 的 SERVFAIL，不泄露过期地址。

传统 DNS 和 EDNS 分别通过 UDP/TCP DNS × A/AAAA × 实际 IPv4/IPv6 TCP/UDP 出口的八种组合，以及实际 CLI EDNS DNS → IPv6 SOCKS5 请求 → BFP TCP echo。原有租期、会话归属和关闭清理仍有效。IPv6 WAN、完整 TUN/系统 DNS 和 DNSSEC 验证不在这些通过范围内。

## 已有运行证据及边界

2026-10-10 的两轮新加坡→洛杉矶小流量矩阵分别覆盖正常 UDP、运行中 UDP→TCP、初始 UDP 阻断→TCP；每场 TCP/UDP 均为 12/12。运行中切换保持同一 Session 和原目标 TCP socket。第二轮还跨越原 12 秒 Ticket 有效期，观察到刷新安装。随机主动探测没有应用响应，实验资源已清理。

这两轮对应历史 Linux 二进制 `5049bcad7a8635008c7860690d403d489414f2d97d69707c2bdaf532295e3c22`，原始证据在工作区 `lab/runs/8c72745e6c4a3b740b8c9ddcab5d9a95/` 和 `lab/runs/bc730c12581cd4a49a1a9050fff27af4/`。本预览包由冻结的根模块源码重新构建，带新的版本和构建时间，二进制哈希以包内清单为准；不将历史 WAN 记录写成本包二进制的新实网验收。

此前切换场的 UDP 11/12 失败记录保留。两轮通过不能证明旧失败的根因已经解决，也不能保证所有 UDP 数据报无损。已提交而交付未知的数据报不会为制造通过结果而自动重放。

当前预览包不宣称生产成熟：`acceptance_complete=false`、`production_ready=false`、`released=false`。当前源码的 `go test ./...`、`go vet ./...` 和 WAN 工具 13 个回归用例已通过；本机 race 仍未运行，因为 Windows 环境没有 C 编译器。Linux 历史 race 的分阶段范围和原始失败继续保留，不能改写成当前包的一次完整 race 通过。两个 WAN 运行的临时资源已清理，接收机基线未变化；preview.17 根包冻结 205 个 Go/module 文件，preview.20 原生包冻结 207 个；三个 CLI 文件变化见包校验中的基线比较。

## 在源码上继续开发

源码位于包内 `source/`。需要 Go 1.26 或更新版本，首次构建按 `go.mod` 下载依赖：

```sh
cd source
go build -o bfp ./cmd/bfp
./bfp demo
```

Windows 可执行 `go build -o bfp.exe ./cmd/bfp` 后运行 `.\bfp.exe demo`。PowerShell 打包脚本为 `source/build.ps1`；每次使用新的版本号或输出目录，避免覆盖已交付包。两个平台都构建成功后才生成统一清单和 ZIP；构建失败会返回错误并恢复环境变量。


