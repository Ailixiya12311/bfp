# BFP 原生 Mihomo 接入与交付

当前接入包为 `dist/BFP-Mihomo-0.1.0-preview.31/` 和同名 ZIP。它包含 Windows/Linux amd64 的独立 BFP 客户端/服务端及 Mihomo 原生 BFP 出站，配套配置、启动脚本、冻结源码和校验清单。应用进入 Mihomo 后，目标 TCP/UDP 直接交给 BFP Session。

preview.31 修复 Windows 启动器的实例锁和子进程生命周期：proxy 与 TUN 共用 `Local\\BFP-Mihomo`；Go 监督器在启动器被强制结束时回收 Mihomo、清理临时 TUN 状态。根包 preview.22 的 `demo` 还验证初始 UDP→TCP。进程级回归见 [release-preview31.json](../verification/product-mihomo/release-preview31.json)。

BFP 使用独立的握手、加密记录、流和会话恢复合同。Mihomo 提供应用入口、规则、DNS 和 TUN；其上游包含的其他协议不改变 BFP 的线上协议。

## preview.24 分类配置与慢链路预设

以下是历史 preview.24 记录：当时独立协议包是根 preview.18，原生应用包是 Mihomo preview.24。两包均含 Windows/Linux amd64 程序、冻结源码、校验清单和运行说明。

本次把 `client.json.classification` 接入公共原生加载器，与独立 CLI 共用严格解析。Mihomo YAML 若显式提供 `proxies[].classification`，会整体替换 JSON 策略，不做合并。公共加载器仍拒绝 options、socks_metadata、datagram_fec、dns 字段。

`keygen -classification-profile low-bandwidth` 在两端写入相同策略：UDP 53、TCP 22 固定为 Interactive；默认 Normal；累计至少 32 KiB、持续满足 8 KiB/s 阈值后进入 Bulk，持续满足 2 KiB/s 低速阈值后恢复。它调整分类/调度，不是限速器。

包内 demo 已通过。Windows 原生回环检查中，160 KiB 的持有 TCP 从 Normal→Bulk→Normal，类别版本 1→2→3 的发布/确认一致；Interactive TCP 和 Normal UDP 各完成 42 次往返，同一 Session、原目标连接、locked 分类与应用字节计数通过。七类目标 TCP/UDP 与四项配置/诊断检查通过，临时进程和私有目录已清理。

运行记录见 `verification/product-mihomo/lifecycle-preview24-attempt02.json`，原生包绑定见 `package-check-preview24.json`，根包绑定见 `package-check-root-preview18.json`。首轮检查脚本失败分别保留于 `lifecycle-preview24-attempt01.json` 和 `package-check-root-preview18-attempt01.json`。本机回环检查完成后，另有 preview.24 低带宽 WAN 记录；本段回环样本不证明饱和公平性、FEC 收益或长期稳定性。四类仍为 2 类核心实现、2 类部分实现、0 类最终验收。 本轮还重复运行了 5 次真实 Session FEC loopback 丢片测试：单片恢复、迟到原片不重复、双片不误恢复、过期不复活和后续完整数据报均通过；证据见 `../verification/product-mihomo/fec-runtime-repeat-preview24.json`。这不是 WAN FEC 收益或吞吐公平性证明。

## 启动普通应用代理

在接入包目录执行一次配置生成。下面沿用洛杉矶接收/出口端：

```powershell
.\bin\bfp-windows-amd64.exe keygen -out .\credentials -server-listen 0.0.0.0:51880 -server 192.0.2.10:51880 -tcp-server 192.0.2.10:51880 -classification-profile low-bandwidth
```

生成的 `server.json` 放出口端，`client.json` 放发送端的 `credentials/`。Linux 出口端运行：

```sh
chmod +x ./bfp-linux-amd64
./bfp-linux-amd64 server -config ./server.json
```

Windows 发送端在接入包目录运行：

```powershell
.\start-native.ps1 -Mode proxy
```

控制台出现 `Mihomo runtime ready` 后启动应用请求；这表示路由和代理组已完成初始化。代理端口可能更早开始监听。

应用使用 HTTP/SOCKS5 `127.0.0.1:17890`。UDP 应用需要使用 SOCKS5 UDP ASSOCIATE。原生接入不需要另起 BFP SOCKS 客户端。

Linux 发送端：

```sh
chmod +x ./bin/* ./start-native.sh
./start-native.sh proxy
```

普通代理模式监听回环入口。配置中的 DNS 为 `127.0.0.1:1053`，应用可按需使用；DNS 上游可在 YAML 中修改。首次配置检查和程序启动均从包目录执行，使 `./credentials/client.json` 正确指向私有配置。

Linux 启动器依赖 `flock`（util-linux）；TUN 模式另需 `ip`（iproute2）。proxy/tun 共用实例锁，重复启动会返回错误且保留当前实例。Linux TUN 的成功提示为 `BFP TUN interface ready`，启动器检查网卡存在后才输出该提示；收到 SIGTERM 后会停止子进程并清理自身的网卡、标记和生成配置。

样例中的 `dns.fake-ip-session-proxy: BFP` 把原生 Fake-IP A/AAAA 映射绑定到 BFP 出站的实际 Session。UDP→TCP 承载切换沿用同一地址租约；Session 关闭、到期或撤销后，旧地址在 DNS 恢复、TCP 拨号和 UDP 目标准备时都会被拒绝。下一次 DNS 查询才建立新 Session，并从单调临时地址空间取得新地址。不要在该模式启用 `profile.store-fake-ip`，也不要让其他出站使用这两个地址池。

preview.16 保留并交付 `proxies[].classification`。每条规则可以按目标 network、端口范围、可信 domain/domain-suffix、rule-tag 或 application 选择 `interactive`、`normal` 或 `bulk`，并设置 priority/locked；`behavior` 用有限窗口、持续活动、迟滞和冷却时间把持续大流量降为 bulk，再在低速持续期间恢复。配置在 Session 建立前严格校验，未知字段、非法类别、端口和 window/bucket 会拒绝启动。实际 Mihomo YAML 配置检查见 `verification/product-mihomo/session-dns-preview14.json`。

## TUN 与构建范围

Windows 管理员 PowerShell 可使用 `start-native.ps1 -Mode tun`；Linux root 可使用 `start-native.sh tun`。TUN 样例启用 gVisor、自动路由、严格路由和 DNS hijack。Linux 启动器在 TUN 模式为每次运行分配 `bfp-tun-` 加 7 个十六进制字符的设备名，总长 15 字节，写入包内 runtime marker，并在启动前清理上一次留下的同名 owned 设备；Windows 还有单实例互斥和有界子进程收尾。当前已运行验证的是 Windows `proxy` 生命周期和 Linux 隔离 TUN；Windows 系统 TUN、宿主路由恢复和完整异常退出矩阵仍未验收。

原生源码位于 `integrations/mihomo/source/`，固定基于 Mihomo v1.19.32 提交 `88dcbf7f1614a67c3b36b848ee3592dfa92ada36`。构建标签是 `with_gvisor,no_tailscale`，该构建未启用 Tailscale 出站。Windows Wintun 由 sing-tun 依赖嵌入程序。

Mihomo 在解析配置时检查系统 IPv6 地址。系统仅有 `::1` 时，即使 YAML 写了 `ipv6: true`，它也会停用 Fake AAAA 池。隔离运行需要先配置实际 IPv6 单播地址；本次使用容器内部的 ULA 地址，不跳过系统 IPv6 检查。仅配置 IPv6 DNS 开关不能代替系统数据路径。

包内 `source/bfp/` 与 `source/mihomo/` 使用相对模块替换。运行 `python source/build-mihomo.py --version <新版本> --output-root ./dist` 可重新构建；项目中的入口为 `python integrations/mihomo/build.py`。当前包的源码、程序和 ZIP 对应关系见 `dist/BFP-Mihomo-0.1.0-preview.31/release-manifest.json`；Session DNS 的配置和回归证据见 `verification/product-mihomo/session-dns-preview14.json`。

## 当前实际验证

preview.23 修复 Linux TUN 被强杀后策略规则残留的问题。每次启动选择空闲路由表和规则范围，保存完整内核规则；子进程或入口被 SIGKILL 后清理本实例，整组进程被 SIGKILL 后由下一次 proxy/tun 启动持锁恢复。预先存在的 IPv4/IPv6 9000 优先级规则保持不变。

preview.23 当时通过 Windows 原生代理的 7 个目标 TCP/UDP 往返、配置及错误诊断检查；洛杉矶隔离环境的三种自动路由强杀/恢复，以及另一轮 8 个 TUN 数据场景、初始/运行中 UDP→TCP、重复启动、SIGTERM、旧设备恢复和缺失 TUN 拒绝均通过。两轮远程资源清理与宿主基线比较通过，本轮未使用新加坡。 证据为 [preview.23 生命周期](../verification/product-mihomo/lifecycle-linux-preview23.json) 和 [Windows 原生代理](../verification/product-mihomo/lifecycle-preview23.json)。

Linux 强杀检查使用隔离命名空间的自动路由，8 个数据场景另用隔离 UID 路由；Windows 检查为回环代理。宿主/Windows TUN、真实公网承载路由排除、IPv6 公网、跨系统启动恢复、自定义 auto-redirect 防火墙状态、完整负向矩阵及长期负载仍未完成。最近 TUN WAN 仍绑定 preview.19。四类保持 2 类核心实现、2 类部分实现、0 类完成最终验收。

preview.20 修复 Linux 启动器被 SIGKILL 后 Mihomo 继续运行、占用端口和实例锁的问题。包内 Go 监督器使用 Linux 父进程死亡通知，锁保持到子进程实际停止；强杀可能留下 marker/config，下一次 proxy 或 tun 启动取得锁后恢复。子进程异常退出由监督器返回错误并清理本实例。

preview.20 当时在洛杉矶隔离环境通过 4 个 proxy/tun × 启动器/子进程强杀场景与重启，以及 8 行 TUN 抓包矩阵、初始/运行中 UDP→TCP、重复启动、SIGTERM、旧设备恢复和缺失 TUN 拒绝。两轮 owned 资源清理和宿主基线比较通过，本轮未使用新加坡。Windows demo、根测试/vet、四个平台/程序构建和文件/ZIP 校验通过。 记录见 [preview.20 Linux 证据](../verification/product-mihomo/lifecycle-linux-preview20.json)。本轮使用隔离路由，不证明启用自动路由后的子进程 SIGKILL 能恢复全部策略规则、整组进程同时强杀、宿主/Windows TUN 或 IPv6 公网。相对 preview.19 只有三个 BFP CLI 文件变化，协议、Session、分类、DNS 和 Mihomo 源码相同；下面的 WAN 仍绑定其原版本。四类计数保持 2 类核心实现、2 类部分实现、0 类完成最终验收。

preview.19 的 Linux 启动器已在洛杉矶隔离 TUN 环境通过 run `d2a5f6b1b8dafb7146edf2e01cebb14e`：8 个 IPv4/IPv6/Fake A/AAAA 的 TCP/UDP 场景、两种 UDP→TCP 回退、未知 Fake-IP 拒绝、删路由阻断、重复启动保护、SIGTERM 清理、旧标记恢复和缺失 TUN 拒绝。记录见 `verification/product-mihomo/lifecycle-linux-preview19.json`。这条记录使用隔离 UID 路由；下面的 preview.17 WAN 与 Windows 记录仍绑定原版本，未改写为 preview.19 的新验收。

preview.19 另有 TUN WAN run `cff1977f1f1af2aec6e01372d0b4178e`，摘要见 `verification/product-mihomo/wan-tun-preview19.json`。新加坡普通系统 socket 经自动命名空间路由、TUN DNS 劫持与 Fake A/AAAA 进入原生 BFP；正常 UDP、运行中 UDP→TCP、初始 UDP 阻断后三场各为 TCP/UDP 12/12。运行中 Session、临时逻辑地址、原 TCP 连接和 Fake-IP 租约保持。退出后网卡/标记、路由和规则恢复，双机测试资源清理与基线比较通过。加密承载通过私有 Unix fixture 使用宿主 IPv4 WAN；命名空间内 BFP 显式使用 lo 接口。这条结果没有修改宿主全局路由，也不证明公网承载地址在宿主 TUN 下的路由排除、Windows TUN 或 IPv6 公网承载。

preview.17 的 Windows 原生回环生命周期记录为 `verification/product-mihomo/lifecycle-preview17.json`，覆盖配置检查、Fake A/AAAA DNS、实际 SOCKS TCP/UDP 往返与退出清理。preview.17 的 Linux 原生代理 WAN 记录为 `verification/product-mihomo/wan-native-preview17.json`，原始 run 为 `b5e027d27b1e07dddd617a86e96b0ba6`：新加坡发送、洛杉矶接收/出口；正常 UDP、运行中 UDP→TCP、初始 UDP 阻断→TCP 三场每场 TCP/UDP 均为 12/12。运行中切换保持同一 Session 和原目标 TCP 连接，generation 1→2；实际业务负载为 1020 字节/次、约 1 秒间隔。包内程序/模板哈希、随机无效探测、测试资源清理和双机基线已核验。该 WAN 记录只覆盖代理模式、数值 IPv4 echo 目标，不覆盖 TUN、系统 DNS/路由、IPv6 WAN 或长期负载。

历史 Windows preview.8 使用当时包内程序完成两份样例以及分类配置的 CLI 配置检查，并通过原生 mixed SOCKS 入口完成 7 个目标场景的 TCP/UDP 往返：数值 IPv4、数值 IPv6、域名、UDP DNS 获取的 Fake A/AAAA、TCP DNS 获取的 Fake A/AAAA。服务端观察到实际 BFP Session。旧证据保留为 `verification/product-mihomo/windows-native-preview8.json`，测试进程和临时凭据均已清理。

原生适配、配置依赖图和 tunnel 的选定测试共 17 个顶层用例、3 个包通过；这不是 Mihomo 全项目测试。 主程序另通过 vet；配置错误日志已改为按文本输出，文件及 inline 配置的真实 CLI 负向用例均能保留包含百分号的错误描述。原始主程序 vet 失败保存在 `verification/product-mihomo/main-vet-before-printf-fix.log`。已检查缺失、自引用及循环 dialer-proxy 依赖，防止配置激活不可用的承载链。

此前接入包的 Linux 原生代理通过了相同的 7 个目标场景。Linux TUN 使用普通内核 socket、UID 20001、`--network none` 隔离容器，实际完成数值 IPv4/IPv6 与 Fake A/AAAA 的 TCP/UDP 共 8 个场景；每场均有 TUN 包和数值出口包。抓包同时确认承载端口没有进入业务 TUN。这些运行记录按 preview.14 证据保存，不能直接改写成 preview.16 新包的 WAN/TUN 结果。

preview.16 新增的 Windows `proxy` 启动器运行级检查使用临时本地凭据和无效回环 endpoint：Mihomo mixed port 成功监听；第二个同模式实例被互斥体拒绝；受控终止 Mihomo 子进程后端口消失，未留下启动器生成的配置或 TUN marker；非管理员路径还验证了上次 `bfp-tun-deadbeef` stale marker 会被清理后再拒绝 TUN。完整记录见 `verification/product-mihomo/lifecycle-preview16.json`。这不等同于 Windows 管理员权限下创建真实 Wintun、修改系统路由或验证异常退出恢复。

preview.16 的当前 Linux BFP 二进制还做了新加坡→洛杉矶小流量 WAN：正常 UDP 与初始 UDP 阻断后的 TCP 接管均为 12/12；运行中 UDP→TCP 保持同一 Session、generation 1→2、TCP 12/12，但 UDP 11/12，严格结果为 FAIL。随机探测无应用响应，两端 owned 清理和快照比较通过。摘要见 `verification/product-mihomo/wan-preview16.json`，原始记录见 `lab/runs/da3756d8e2b26883c53178fec3c18b92/wan-result.json`；该记录属于根 BFP 二进制链路，不等于 Mihomo TUN 的实网验收。

运行中 UDP 黑洞后，已建立 TCP 连接继续收发；Session ID 保持不变，承载从 UDP 变为 TCP，generation 从 1 变为 2，出口累计 TCP 连接数保持 6→6。本地样本恢复后的 echo 用时 249ms，不作为公网或高 RTT 性能承诺。首次 UDP 阻断时，新客户端也能通过 TCP 建立会话并完成 IPv4 TCP/IPv6 UDP。

未知 Fake A 请求被拒绝，Session opened 计数保持 12→12，出口没有新连接；移除测试 UID 的 TUN 路由后，请求返回 network unreachable，没有直达同命名空间出口。Mihomo 正常停止后 TUN 接口消失。owned 容器、临时凭据和 run 目录均已清理，宿主机固定服务、路由与防火墙快照未变化。仅保留标记明确的测试工具镜像及按哈希缓存的公共程序，减少后续上传。

旧的 preview.8 原生 TUN 记录仍保留在 `verification/product-mihomo/runs/754be1714e539c0f51bfb76b94d5e60a/remote-result.json`，它只作为历史基线；preview.14 的 Linux 隔离记录改用下面的 run，不把旧二进制结果冒充当前包验收，也不把该记录改写为 preview.16 的新运行。

该 TUN 检查使用显式 UID 路由，关闭自动路由，并在容器内部开启同命名空间出口需要的 IPv4 accept_local/关闭 rp_filter；相关配置都有记录。它证明当前程序的 TUN 数据路径和上述恢复行为，不证明宿主机自动路由、系统 DNS、异常退出恢复或原计划全部 32 行矩阵完成。两份产品样例都通过 CLI 配置检查，系统执行范围仍按这条边界判断。

完整原生 sing-box、Windows 系统 TUN、完整承载/元数据/绕行矩阵、系统 DNS/TUN 异常恢复、混合流量分类与纠错收益、长期资源稳定性及独立安全审查仍需继续完善。原生 Session DNS 的地址归属已经接入，但第四类整体仍是部分完成；四类需求仍是 2 类核心实现、2 类部分实现、0 类完成最终验收。

## preview.14 保留的 Linux owned TUN 证据

preview.14 在洛杉矶测试机 `192.0.2.10` 的 owned `network=none` 容器中通过了 run `44bb2d84fb410062a2a10f487ac54daa`。该 run 使用 preview.14 包和工具镜像 `sha256:3d824652b974f035ca4198a245d7a3dbd0bff08435831a79eab2feb24d2205df`，完整记录见 `verification/product-mihomo/runs/44bb2d84fb410062a2a10f487ac54daa/remote-result.json`。它是隔离 TUN 基线，不是 preview.16 新二进制的 TUN 或 WAN 证据。

通过项目包括：mixed SOCKS TCP/UDP 与 Fake-IP DNS；数值 IPv4/IPv6、Fake A/AAAA 的 TCP/UDP 共 8 个 TUN 场景；运行中和初始 UDP→TCP 回退；同一 Session、原目标连接保持；未知 Fake-IP 拒绝；删除 owned UID 路由后的阻断；正常退出后的 TUN 清理；owned 容器和临时目录清理；洛杉矶宿主快照无变化。该验证使用 `fd42:6266:7000::/96` 作为 IPv6 Fake-IP 池。

这里的 TUN 是 owned UID 路由隔离验证，不等于 Windows 系统 TUN、系统 DNS、生产路由或新加坡→洛杉矶 WAN 验收；这些边界仍按下文和统一证据文件记录。

