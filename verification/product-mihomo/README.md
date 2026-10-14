# 当前原生接入交付记录

当前包：`dist/BFP-Mihomo-0.1.0-preview.31/` 和同名 ZIP。

## preview.31 Windows 启动器锁与子进程回收

preview.31 修复了一个会影响实际成品运行的 Windows 启动器错误：旧代码按 `proxy`/`tun` 模式创建不同的命名 Mutex，两个模式可以同时启动并争抢同一个 mixed port、runtime 和生成状态。现在两种模式使用同一个 `Local\\BFP-Mihomo` 锁；Go 监督器在启动器被强制结束时通过父进程句柄回收 Mihomo，并清理 marker/generated config。新包的完整性、冻结源码、demo、共享锁和“只结束启动器、不手动结束 Mihomo”回归均记录在 [release-preview31.json](release-preview31.json)。当前 `demo` 还会验证初始 UDP 被阻断时的 TCP 接管，输出 `fallback_carrier=tcp`。

## preview.24 分类配置与慢链路预设

以下是历史 preview.24 记录：当时独立协议包是根 preview.18，原生应用包是 Mihomo preview.24。两包均含 Windows/Linux amd64 程序、冻结源码、校验清单和运行说明。

本次把 `client.json.classification` 接入公共原生加载器，与独立 CLI 共用严格解析。Mihomo YAML 若显式提供 `proxies[].classification`，会整体替换 JSON 策略，不做合并。公共加载器仍拒绝 options、socks_metadata、datagram_fec、dns 字段。

`keygen -classification-profile low-bandwidth` 在两端写入相同策略：UDP 53、TCP 22 固定为 Interactive；默认 Normal；累计至少 32 KiB、持续满足 8 KiB/s 阈值后进入 Bulk，持续满足 2 KiB/s 低速阈值后恢复。它调整分类/调度，不是限速器。

包内 demo 已通过。Windows 原生回环检查中，160 KiB 的持有 TCP 从 Normal→Bulk→Normal，类别版本 1→2→3 的发布/确认一致；Interactive TCP 和 Normal UDP 各完成 42 次往返，同一 Session、原目标连接、locked 分类与应用字节计数通过。七类目标 TCP/UDP 与四项配置/诊断检查通过，临时进程和私有目录已清理。

运行记录见 `verification/product-mihomo/lifecycle-preview24-attempt02.json`，原生包绑定见 `package-check-preview24.json`，根包绑定见 `package-check-root-preview18.json`。首轮检查脚本失败分别保留于 `lifecycle-preview24-attempt01.json` 和 `package-check-root-preview18-attempt01.json`。本机回环检查完成后，另有 preview.24 低带宽 WAN 记录；本段回环样本不证明饱和公平性、FEC 收益或长期稳定性。四类仍为 2 类核心实现、2 类部分实现、0 类最终验收。 本轮还重复运行了 5 次真实 Session FEC loopback 丢片测试：单片恢复、迟到原片不重复、双片不误恢复、过期不复活和后续完整数据报均通过；证据见 `verification/product-mihomo/fec-runtime-repeat-preview24.json`。这不是 WAN FEC 收益或吞吐公平性证明。

## preview.24 低带宽 WAN


本包随后在新加坡 `198.51.100.20` → 洛杉矶 `192.0.2.10` 做了低带宽小流量 WAN：`low-bandwidth` 配置、每场 4 次、每次 1024 字节、间隔 2 秒。正常 UDP、运行中 UDP→TCP、初始 UDP 阻断后三场均 TCP/UDP 4/4；运行中场保持同一 Session、generation 1→2 和一个目标连接。随机探测无应用层响应，发送端/接收端临时进程和目录已清理，双机基线未变化。摘要见 [wan-native-preview24.json](wan-native-preview24.json)，原始记录见 `verification/product-mihomo/runs/3890d35ce6e2021013f56e84666a7bd0/native-wan-result.json`。这只覆盖原生 proxy 模式和数值 IPv4 目标，不替代 TUN、系统 DNS/路由、IPv6 公网承载、饱和公平性、FEC 收益或长期稳定性验收。

## preview.23 自动路由与异常恢复记录

preview.23 修复 Linux TUN 被强杀后策略规则残留的问题。每次启动选择空闲路由表和规则范围，保存完整内核规则；子进程或入口被 SIGKILL 后清理本实例，整组进程被 SIGKILL 后由下一次 proxy/tun 启动持锁恢复。预先存在的 IPv4/IPv6 9000 优先级规则保持不变。

preview.23 当时通过 Windows 原生代理的 7 个目标 TCP/UDP 往返、配置及错误诊断检查；洛杉矶隔离环境的三种自动路由强杀/恢复，以及另一轮 8 个 TUN 数据场景、初始/运行中 UDP→TCP、重复启动、SIGTERM、旧设备恢复和缺失 TUN 拒绝均通过。两轮远程资源清理与宿主基线比较通过，本轮未使用新加坡。 摘要为 [lifecycle-linux-preview23.json](lifecycle-linux-preview23.json)，Windows 原生运行记录为 [lifecycle-preview23.json](lifecycle-preview23.json)，包绑定为 [package-check-preview23.json](package-check-preview23.json)。

Linux 强杀检查使用隔离命名空间的自动路由，8 个数据场景另用隔离 UID 路由；Windows 检查为回环代理。宿主/Windows TUN、真实公网承载路由排除、IPv6 公网、跨系统启动恢复、自定义 auto-redirect 防火墙状态、完整负向矩阵及长期负载仍未完成。最近 TUN WAN 仍绑定 preview.19。四类保持 2 类核心实现、2 类部分实现、0 类完成最终验收。

失败记录保留：preview.20 的自动路由强杀残留为 `e45d6411899a165b048afb6b057b531d`；preview.21 的规则删除 EINVAL 为 `f1da48f543892d1a23f1152b919efc4f`；preview.22 的路由地址族启动失败为 `2705aa786c62e4d5a6aceb2a206b9996`。preview.23 的自动路由与 TUN 数据运行分别为 `d78dc83e096f3bb6aa0609c2396019b5`、`61821f67ab17158333015156d91c02dd`，原始失败均未覆盖。

此前 preview.20 的 4 个 proxy/tun 强杀场景及 8 个 TUN 数据场景保留在 [lifecycle-linux-preview20.json](lifecycle-linux-preview20.json)，该版本使用隔离路由，未覆盖本轮新增的自动路由强杀恢复。

旧 preview.19 的强杀失败 run `096a2c06b8397241b79089fd955d2ec9` 原样保留；此前 fixture 预建凭据目录使 keygen 拒绝的 run `0e10692da93b4ae29480494d31b0bf81` 未进入启动器，另行标注。两个新版 run 为 `d66693bc67c6b7447670d1ee66cc22ef`、`6a38909a33bb2e9c9667c4b4a1a50d32`。

`wan-tun-preview19.json` 是 preview.19 包的 TUN 实网摘要，绑定 run `cff1977f1f1af2aec6e01372d0b4178e`。三场（正常 UDP、运行中 UDP→TCP、初始 UDP 阻断后 TCP）每场 TCP/UDP 12/12；普通 UID 20001 内核 socket 使用自动命名空间路由、TUN UDP/TCP DNS 劫持和 Fake A/AAAA，保持同一 Session、临时逻辑地址、原 TCP socket 和地址租约。三场退出后设备/标记、路由和策略规则恢复，owned 清理与双机基线比较通过。BFP 加密承载经私有 Unix fixture 发到宿主 IPv4 WAN socket，命名空间内使用回环地址与显式 lo 接口；宿主全局 TUN、真实公网承载地址排除和 IPv6 公网承载不在这条范围内。业务期间的 carrier 轨迹与退出后 suspended 状态分别记录，三个先前 fixture/采样失败 run 原样保留并在摘要中索引。

`lifecycle-linux-preview19.json` 绑定 preview.19 包的 Linux 启动器/TUN 隔离运行 `d2a5f6b1b8dafb7146edf2e01cebb14e`。重复实例返回 3 且原网卡/标记/配置不变，15 字节网卡名实际创建成功，SIGTERM 返回 143 并清理，旧标记恢复通过；缺失 TUN 的负向场景即使 Mihomo 打印 ready，启动器也返回 1 并关闭端口。8 个 IPv4/IPv6/Fake A/AAAA TUN TCP/UDP 场景有 TUN 与出口抓包，两种回退和负向目标/路由检查通过，宿主基线未变化。它不是宿主自动路由或 WAN 验收；preview.18 的超长网卡名失败保留在 `runs/43be83d1e63034cef82fcfa0d62514cc/remote-result.json`。下面的 preview.17 及更早记录仍绑定原版本。

`wan-native-preview17.json` 是 preview.17 包的原生 Mihomo 代理 WAN 摘要，绑定 run `b5e027d27b1e07dddd617a86e96b0ba6` 和包清单中的 Linux BFP/Mihomo/代理模板 SHA-256。新加坡→洛杉矶三场（正常 UDP、运行中 UDP→TCP、初始 UDP 阻断→TCP）每场 TCP/UDP 均为 12/12；运行中保持同一 Session、generation 1→2，目标 TCP 连接只建立一次。随机探测无应用响应、无新增目标连接，测试进程/运行目录清理和双机基线比较通过。原始结果及当时的脚本快照保留在 `runs/b5e027d27b1e07dddd617a86e96b0ba6/`；本轮实际业务负载为 1020 字节/次，摘要说明原始负载元数据中的 1024 字节误差。此记录覆盖原生代理模式，不覆盖 TUN、系统 DNS/路由、IPv6 WAN 或生产验收。

`lifecycle-preview17.json` 是 preview.17 包的 Windows 原生回环生命周期证据。`wan-preview17.json` 是独立根协议包的 WAN 证据，不能替代原生出站记录。preview.23 的源码与程序清单见 `dist/BFP-Mihomo-0.1.0-preview.23/release-manifest.json`。下面保留的 preview.16 及更早记录按各自版本解释。

`session-dns-preview14.json` 记录本次原生 Session Fake-IP 归属和原生分类配置入口变更：配置检查（含 network/port/domain-suffix/behavior）、定向 DNS 跨会话失效回归、分类解析单测和真实 Mihomo process/application 分类回归、相关 Go 测试/vet 和包 SHA-256。它不替代原生 TUN、系统 DNS、WAN 或生产安全验收。

`dist/BFP-Mihomo-0.1.0-preview.16/release-manifest.json` 是历史 preview.16 的源码/程序/文件清单；`session-dns-preview14.json` 是此前 Session Fake-IP 归属和原生分类配置入口变更的配置、定向回归和 SHA-256 记录。`lifecycle-preview16.json` 是历史 preview.16 Windows 启动器的运行级生命周期证据。`release-result.json`、`package-check-preview8.json`、`windows-native-preview8.json` 和 `runs/754be1714e539c0f51bfb76b94d5e60a/remote-result.json` 保留旧包的原生运行基线，不能当作当前包的 WAN/TUN 验收。

`wan-preview16.json` 绑定历史 preview.16 根协议包 Linux 二进制的真实新加坡→洛杉矶小流量结果。正常 UDP 和初始 UDP 阻断后 TCP 接管通过；运行中 UDP→TCP 保持同一 Session 和目标流，但 UDP 12 次中有 1 次未完成，因此整轮严格 FAIL。该失败、随机探测、清理和两端快照结果均保留在摘要及其 raw run 中。

程序包依赖 gVisor 构建标签并禁用 Tailscale 出站。原生适配选定测试、分类解析单测和真实 Mihomo process/application 分类回归、3 个包与库 vet 通过；这些包源码从选定测试到当前包未变化。主程序新增完整初始化后的 runtime-ready 提示，由两平台本包程序实际验证。

Linux 通过范围为原生 mixed SOCKS、8 个 IPv4/IPv6/fake A/AAAA TUN TCP/UDP 场景、初始及运行中 UDP→TCP 回退、未知 Fake A 拒绝、移除测试路由后的阻断和正常退出 TUN 删除。TUN 使用 owned UID 路由而非产品样例自动路由。完整矩阵、Windows 系统 TUN、系统 DNS/会话生命周期与异常恢复仍未验收。

`build_tool_image.py` 在洛杉矶创建独立、带标签的工具镜像；`run_linux.py --package <包路径> --image <镜像哈希>` 仅在 owned network-none 容器中运行。公共程序按 SHA-256 缓存，实际配置和凭据不缓存。所有失败 run 独立保留，没有重写成通过。

## preview.14 保留的 Linux owned TUN 运行基线

preview.14 已在洛杉矶测试机 `192.0.2.10` 的 owned `network=none` 容器中完成一轮原生验证。运行编号为 `44bb2d84fb410062a2a10f487ac54daa`，工具镜像为 `sha256:3d824652b974f035ca4198a245d7a3dbd0bff08435831a79eab2feb24d2205df`。完整原始记录见 [`remote-result.json`](runs/44bb2d84fb410062a2a10f487ac54daa/remote-result.json)，摘要已写入 [`session-dns-preview14.json`](session-dns-preview14.json)。

通过范围是：原生 mixed SOCKS TCP/UDP 与 Fake-IP DNS；数值 IPv4、数值 IPv6、Fake A、Fake AAAA 的 TCP/UDP 共 8 个 TUN 场景；运行中 UDP→TCP 回退保持同一 Session 和原目标 TCP socket；初始 UDP 被阻断时可用 TCP；未知 Fake-IP 被拒绝；删除 owned UID 路由后请求被阻断；Mihomo 正常退出后 TUN 被清理；owned 容器、临时目录和接收机快照均完成清理/保持不变。验证器使用的 IPv6 Fake-IP 池是 `fd42:6266:7000::/96`。

这是一条可运行的 Linux 隔离验证切片，范围不扩大为 preview.16 的新二进制结果、Windows 系统 TUN、生产路由、系统 DNS、长时间稳定性或新加坡→洛杉矶 WAN 验收。

## preview.16 Windows 启动器生命周期证据

`lifecycle-preview16.json` 使用 preview.16 包内 Windows 程序和启动脚本，在临时本地凭据、回环无效 endpoint 和独立 runtime 目录中完成一轮受控检查。结果为：`proxy` mixed port 成功监听；第二个同模式启动器被单实例互斥拒绝；受控终止 Mihomo 子进程后 launcher 返回并关闭 mixed port；runtime 中没有留下启动器生成的 TUN 配置、marker 或其他 owned artifact；非管理员分支清理了严格匹配的 stale marker 后才拒绝 TUN。临时凭据、进程和 runtime 已删除。

这条证据只证明启动器的本地进程生命周期，不证明管理员权限下真实 Wintun 创建、系统路由/DNS 修改与恢复，也不替代 preview.14 的 Linux 隔离 TUN 或新加坡→洛杉矶 WAN 验收。

