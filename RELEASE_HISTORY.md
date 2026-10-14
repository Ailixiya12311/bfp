# BFP 独立代理协议

当前 Windows 客户端为 [preview.6](dist/BFP-Client-Windows-0.1.0-preview.6.zip)，原生程序为 [preview.35](dist/BFP-Mihomo-0.1.0-preview.35.zip)。本机直接运行 [已配置客户端](credentials-client-ready/BFP%20客户端/BFP客户端.cmd)，选择“应用代理”并启动；应用使用 HTTP/SOCKS5 `127.0.0.1:17890`，或点击接管系统代理。2026-10-13 的当前包实际 HTTPS 出口为洛杉矶 `192.0.2.10`，停止回收通过，见 [当前代理记录](verification/product-windows-tun/proxy-preview6-real.json)。公开 ZIP 不含凭据，本机私有目录保留原配置；preview.5/preview.4 保留供回退。

全局 TUN 尚不能作为日常联网模式交付。preview.35 修复 PowerShell 数组 `Address()` 方法与端点字段碰撞，以及 `Find-NetRoute` 混合返回对象导致的就绪失败。真实 TUN 已达到 `ready=true`，网卡、路由、DNS、服务器出口检查通过；后续 HTTPS 请求仍因 TLS 握手失败而未通过，正常恢复了本机网络基线。见 [实机 attempt03](verification/product-windows-tun/windows-tun-real-attempt03.json)；前两次失败记录保留。后台流量出现资源上限，但尚未证明它是该 TLS 失败的唯一原因。当前任务仍是修好全局联网，再完善稳定性和四类需求验收。

以下内容保留各历史版本的实现和证据，不将它们当作 preview.6/preview.35 的新运行结果。

当前交付：[独立协议包 preview.23](dist/BFP-0.1.0-preview.23.zip)和 [原生 Mihomo 应用包 preview.33](dist/BFP-Mihomo-0.1.0-preview.33.zip)。包内包含 Windows/Linux amd64 程序、冻结源码、运行说明与 SHA-256 清单。

Windows 单独使用另有 [独立客户端包 preview.4](dist/BFP-Client-Windows-0.1.0-preview.4.zip)，包含控制窗口、程序、冻结源码与许可证，公开 ZIP 不含密钥。当前电脑已配置好的入口为 [独立客户端启动](credentials-client-ready/BFP%20客户端/BFP客户端.cmd)，目录受当前用户权限保护；停止后可搬动整个目录，无需修改原项目路径。本客户端包使用原生 preview.33 的二进制。此前 preview.1 在中文及空格路径的实际启动、公网检查与回收记录保留在 [便携客户端实测](deploy/runs/66af4a892648df0a6249d6af3947af68/portable-client-real.json)，不作为 preview.4 的新运行记录。

preview.4增加“应用代理 / 全局 TUN”模式选择、当前账户 UAC 启动与恢复、服务器地址排除和出口网卡绑定、完整本机就绪判断、按精确网卡身份清理，以及监督器强杀后的子进程回收。真实 Windows 接管和恢复验证以本轮实机记录为准；详见 [Windows 全局 TUN](docs/Windows全局TUN-v0.1.md)。域名承载和不同出口网卡仍不在该版本支持范围，长期成熟度未完成。

此前 preview.3增加“接管 Windows 系统代理”和“恢复原代理设置”。启动后可让遵循Windows系统代理的应用直接使用BFP，停止时恢复接管前的存在性、类型及完整值；独立监控进程在启动器强制结束后恢复。原设置先写入受当前用户和SYSTEM ACL保护的私有日志，遇到用户或其他软件变更则保留当前设置并释放接管；这不是全局TUN。真实默认系统代理HTTPS及正常/强杀恢复记录见 [系统代理实测](deploy/runs/66af4a892648df0a6249d6af3947af68/system-proxy-real.json)。

本轮修复 TCP 首包重放仍返回应用响应、已提交握手对篡改 CONFIRM 返回缓存 READY 两个准入缺口，并在 LIGHT 填充中增加随机桶尾，消除普通 UDP ACK 恒为112字节及常见固定模64余数的特征。wire3、凭据格式、UDP优先和TCP回退方式不变。首包防重放仍为最多4096条、约1分钟的内存窗口，不能宣称永久静默；时序整形、完整安全审计和系统 TUN 仍未完成。准确合同见 [线上格式](docs/wire-v0.1.md)。新程序已升级到双机部署及本机配置目录；Windows与新加坡公网 HTTPS 出口均为洛杉矶，Windows检查后已停止并释放资源。源码检查、软件包绑定和本次实际交付范围见 [preview.32交付记录](verification/product-obfuscation/release-preview32.json)。

直接使用本机客户端：双击 [BFP客户端.cmd](BFP客户端.cmd)，在控制窗口点击“启动”，应用填写 HTTP 或 SOCKS5 `127.0.0.1:17890`，点击“检查出口”确认联网。控制窗口可以关闭，客户端继续运行；再次打开后可点击“停止”。也保留 [启动BFP.cmd](启动BFP.cmd)、[停止BFP.cmd](停止BFP.cmd)、[状态BFP.cmd](状态BFP.cmd) 和 [检查BFP.cmd](检查BFP.cmd) 四个命令入口。远端实例管理和重启见 [双机部署说明](deploy/README.md)；服务器状态使用 `python deploy/pilot.py status --via-receiver` 查询。

Windows 客户端和新加坡发送端到洛杉矶的真实公网 HTTPS 已通过，出口查询均为 `192.0.2.10`；项目 Windows 启动/检查脚本已通过，关闭启动器后代理端口释放。2026-10-12 08:27 UTC 核验两台服务器进程均在运行，Windows 客户端已在核验后停止，双击入口即可重新启动。当前配置属于独立的私有试用目录，公共 ZIP 不含密钥；凭据已在一次诊断输出暴露后完整轮换，旧接收端已撤销。保留实例尚无开机自启。

已有可运行雏形：独立客户端/服务端、认证会话与多流、默认 UDP 和 TCP 回退、SOCKS5 TCP/UDP、原生 Mihomo 出站、Session DNS/Fake-IP。四类当前为 **2 类核心实现、2 类部分实现、0 类完成最终验收**，尚未达到生产成熟度。

preview.22 / 原生 preview.31 支持共用 `client.json.classification`，并增加 `keygen -classification-profile low-bandwidth`，用于当前新加坡慢链路的分类/调度。Mihomo YAML classification 若存在，会整体替换 JSON 策略，不合并。详细阈值与支持字段见 [产品说明](PRODUCT.md)。

历史 preview.24 的包内 demo 和 Windows 原生回环运行通过：持续 TCP 从 Normal→Bulk→Normal，Interactive TCP/Normal UDP 各 42 次往返，同一 Session 和原目标连接保留。运行/清理证据见 [preview.24 运行](verification/product-mihomo/lifecycle-preview24-attempt02.json)，源码/ZIP 绑定见 [原生包校验](verification/product-mihomo/package-check-preview24.json) 和 [根包校验](verification/product-mihomo/package-check-root-preview18.json)。preview.24 曾在新加坡→洛杉矶做低带宽 WAN：三场 TCP/UDP 均 4/4；本机低负载不证明饱和公平性或长期稳定性。详见 [preview.24 WAN](verification/product-mihomo/wan-native-preview24.json)。

preview.31 修复 Windows 原生启动器的实例锁和子进程生命周期：proxy 与 TUN 共享一个 package-instance mutex，Go 监督器在启动器被强制结束时会回收 Mihomo 子进程和临时 TUN 状态；根包 preview.22 同步把 `demo` 自检扩展到初始 UDP→TCP。新包完整性、demo、共享锁和启动器强制结束回收检查见 [preview.31 记录](verification/product-mihomo/release-preview31.json)。

最新原生 preview.31 另有独立小流量 WAN 记录：新加坡→洛杉矶三场（正常 UDP、运行中 UDP→TCP、初始 UDP 失败→TCP）各 TCP/UDP 4/4，间隔 2 秒；同会话恢复、随机输入无应用响应、实验清理和基线比较均通过。原始记录见 [preview.31 WAN](verification/product-mihomo/runs/ae65df87c5eeaf90312c2bd2044b1310/native-wan-result.json)。

已有公网记录保留各自版本：[根 preview.17 WAN](verification/product-mihomo/wan-preview17.json)、[原生 preview.17 WAN](verification/product-mihomo/wan-native-preview17.json) 和 [preview.19 TUN WAN](verification/product-mihomo/wan-tun-preview19.json)。下文及历史进度按对应版本解释，不把旧二进制结果当成新包验证。

## 运行当前交付包

在解压包目录执行：

```powershell
.\bin\bfp-windows-amd64.exe version
.\bin\bfp-windows-amd64.exe demo
```

Linux 使用 `chmod +x ./bin/bfp-linux-amd64`，再运行 `./bin/bfp-linux-amd64 demo`。

成功输出 `"event":"demo_pass"` 表示真实通过认证 UDP 会话完成了 SOCKS5 TCP 转发和 UDP 数据收发，并用第二个临时客户端验证了初始 UDP 被阻断时自动使用 TCP（输出 `"fallback_carrier":"tcp"`）。这个自检只使用本机回环地址，不访问公网，不生成凭据文件。

## 源码与打包

根目录是可修改的 Go 项目。交付包另带同一份冻结源码，位于 `source/`。需要 Go 1.26 或更新版本。

```powershell
go build -o .\bin\bfp-dev.exe ./cmd/bfp
.\bin\bfp-dev.exe demo
.\build.ps1 -Version 0.1.0-preview.6
```

打包脚本在冻结源码副本中构建 Windows/Linux amd64，检查编译退出码，生成源码/文件 SHA-256 清单和同名 ZIP。输出已存在时使用新的版本号或输出目录。包不包含部署凭据和历史实验缓存。

## 四类需求状态

| 要求 | 当前状态 |
|---|---|
| 认证复用 | 已有核心实现：会话复用、密钥更新、Ticket 刷新和承载恢复 |
| 混淆与防主动探测 | 已有基础实现：加密内部结构、首包准入、防重放、长度填充、无效探测不返回应用数据 |
| 协议内分流 | 部分完成：根协议分类器、行为降级、调度和类别纠错策略已接入，Mihomo 已能从 YAML 解析端口/网络/域名后缀规则；完整原生适配和混合负载验证仍有工作 |
| 短时会话网络 | 部分完成：临时地址、目标连接、根模块 DNS A/AAAA/Fake-IP 和原生 Mihomo Session Fake-IP 归属已接入；旧会话地址会失效且新会话单调换址；完整 TUN/路由生命周期和 IPv6 WAN 未完成 |

仍是 **2 类已有核心实现、2 类部分实现，0 类完成最终验收**；`acceptance_complete=false`、`production_ready=false`、`released=false`。认证复用不取消记录完整性和重放校验。当前混淆不能隐藏公网 IP、端口、UDP/TCP 类型、包长与时序。

## 会话 DNS A/AAAA

客户端可配置本机 DNS 入口。同域名的 A 和 AAAA 共用一条映射、原始到期时间和 Session 所有权；IPv6 地址在开流时还原成域名。原生 Mihomo 配置使用 `dns.fake-ip-session-proxy: BFP` 显式指定归属，旧 Session 终止后旧地址不能进入新会话，下一次 DNS 查询取得新的临时地址。普通 EDNS(0) 查询已接入，dig 可以使用默认选项，无需 `+noedns`。根模块的传统 DNS/EDNS 实际路径已通过；原生 Session DNS 的配置检查和跨会话失效回归已通过，公网 DNS、完整系统 DNS/TUN 和 DNSSEC 验证仍未完成。

## 验证记录

2026-10-10 已有两轮小流量新加坡→洛杉矶 WAN 矩阵：正常 UDP、运行中 UDP→TCP、初始 UDP 阻断→TCP 三场的 TCP/UDP 均为 12/12；运行中恢复保留同一 Session 和原目标 TCP socket。第二轮跨原 12 秒 Ticket 有效期并观察到刷新安装。两轮对应的历史 Linux 二进制 hash 与本次带版本元数据的打包二进制分别记录，不能混用。

此前运行中切换场 UDP 11/12 失败继续保留，两轮新样本通过不证明旧失败已定位。当前源码本地完整测试通过，随后仅修改了 Session 的一个超时测试文件，该包复查和 vet 通过。Linux 完整 race run `f6ed5ded65d1df8f150bfc063e42409f` 的其他包通过，但 Session 的旧 60ms 用例在握手阶段失败；原始整体失败保留。真实握手与地址创建阶段分开后，仍按原 60ms/150ms 限制验证，Session race run `a5492c93e31274a21a3acf9df99b4a4a` 通过。其余源码字节未变，合并记录覆盖 22 个包，详见 `verification/product-edns/linux-race-coverage.json`；这不是一次新的完整 race 运行。两个运行的临时资源均已清理，接收机基线未变化。

- [产品说明](PRODUCT.md)：当前能力、运行入口、四类状态和证据边界。
- [两台机器部署](docs/成品运行与部署-v0.1.md)：Linux 实际命令、配置分配和 SOCKS 使用。
- [实现进度和历史记录](docs/实现进度.md)：保留旧候选的通过与失败。
- [协议设计](docs/协议技术设计-v0.1.md)：独立协议的设计目标。
- [preview.17 WAN 原始结果](lab/runs/fcc4afa13f17944db9547f86cb565a8b/wan-result.json)。
- [preview.17 原生 Mihomo 代理 WAN 原始结果](verification/product-mihomo/runs/b5e027d27b1e07dddd617a86e96b0ba6/native-wan-result.json)。
- [历史 preview.16 WAN 原始结果](lab/runs/da3756d8e2b26883c53178fec3c18b92/wan-result.json)。
- [Ticket 生命周期 WAN 原始结果](lab/runs/bc730c12581cd4a49a1a9050fff27af4/wan-result.json)。

完整 TUN 平台与路由生命周期、IPv6 WAN、完整 Mihomo/sing-box 平台矩阵、长期稳定性、混合负载与纠错收益，以及独立安全审查仍未完成。



