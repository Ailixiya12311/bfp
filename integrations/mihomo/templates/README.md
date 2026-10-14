# BFP 原生 Mihomo 接入包

本包包含独立 BFP 客户端/服务端和带原生 `bfp` 出站的 Mihomo CLI。应用入口、规则、DNS 和 TUN 由 Mihomo 处理，目标 TCP/UDP 直接进入 BFP Session；默认 UDP，失败时使用同服务器 TCP 承载。

Mihomo 基于 v1.19.32 的固定提交 `88dcbf7f1614a67c3b36b848ee3592dfa92ada36`，使用 `with_gvisor,no_tailscale` 构建。BFP 和 TUN/gVisor 已包含；该构建未启用 Mihomo 的 Tailscale 出站。Windows 的 Wintun 组件由所用 sing-tun 依赖嵌入程序，TUN 模式仍需要管理员权限。

## Windows 全局 TUN 接管和恢复

Windows 启动器为每次 TUN 分配独立网卡，记录 GUID 和恢复信息，在自动路由中排除 UDP/TCP 服务器 IP，并绑定启动前的出口网卡。网卡、路由、DNS和进程全部就绪后才报告 TUN ready。当前服务器配置需使用数字 IP，两个承载端点需使用同一出口。纯 IPv4 主机不会被要求创建 IPv6 路由。

TUN 需要管理员权限。程序异常退出后保留未完成的恢复记录；下一次管理员启动可继续恢复。清理只处理记录对应的网卡及 PnP 实例，不卸载共享驱动、不重置其他网卡。Windows supervisor 的 Job Object 在被强杀时会终止已加入的 Mihomo；强杀整个进程组后可能需再次管理员启动来恢复。运行期 strict-route 不提供退出后的持久断网保护。管理员实机接管和恢复结果以对应本轮验证记录为准。

## 生成配置和启动

在包目录生成一次临时网络的认证配置：

```powershell
.\bin\bfp-windows-amd64.exe keygen -out .\credentials -server-listen 0.0.0.0:51880 -server 192.0.2.10:51880 -tcp-server 192.0.2.10:51880 -classification-profile low-bandwidth
```

`server.json` 放洛杉矶出口端，`client.json` 放发送端的 `credentials/`。包不含实际凭据。洛杉矶运行 `./bfp-linux-amd64 server -config ./server.json`；发送端可运行本包原生 Mihomo，无需另起 BFP SOCKS 客户端。

`low-bandwidth` 适用于当前新加坡慢链路：UDP 53、TCP 22 固定为 Interactive；其他流从 Normal 开始，累计至少 32 KiB 且持续满足 8 KiB/s 阈值时归为 Bulk，持续低于 2 KiB/s 后恢复。4 秒观察窗口、3 秒高速持续期、8 秒恢复持续期、活动间隔和冷却时间共同控制切换。预设只改变分类和调度，不限制网速，也不改变流可靠性或 FEC 协商。省略参数或指定 `standard` 保持原兼容配置。

独立客户端和本包原生出站共用 `client.json.classification`。YAML 中若显式设置 `proxies[].classification`，它会替换 JSON 中的整个策略，不合并规则。公共加载器仍不支持 JSON 的 `options`、`socks_metadata`、`datagram_fec` 和 `dns` 字段；出现这些字段会拒绝加载，即使值是 null 或空对象。

Windows 普通代理模式：

```powershell
.\start-native.ps1 -Mode proxy
```

应用使用 HTTP/SOCKS5 `127.0.0.1:17890`。UDP 需要支持 SOCKS5 UDP ASSOCIATE 的应用。使用 TUN 时，在管理员 PowerShell 中运行 `start-native.ps1 -Mode tun`。

控制台出现 `Mihomo runtime ready` 后再启动应用请求；这表示路由和代理组初始化完成，端口监听日志可能更早出现。

Linux：

```sh
chmod +x ./bin/* ./start-native.sh
./start-native.sh proxy
# 使用 TUN 时以 root 运行：
./start-native.sh tun
```

Linux 启动器需要 `flock`（util-linux）；TUN 模式还需要 `ip`（iproute2）和 root 权限。两种模式共用一个实例锁，重复启动返回错误且保留正在运行的实例。TUN 网卡创建成功后另输出 `BFP TUN interface ready`；启动器收到 SIGTERM 时会停止子进程，再清理本实例。Linux 入口最终进入包内 BFP 的进程监督器；入口被 SIGKILL 后，内核向 Mihomo 发送 SIGTERM，锁持续保持到 Mihomo 实际退出。每次 TUN 使用空闲的临时路由表和规则范围，写入私有 network journal；完整初始化通过管道通知监督器，路由归属记录后才提示 TUN ready，不依赖日志级别。子进程异常退出后按记录清理；整组进程被 SIGKILL 时，下一次 proxy 或 tun 启动持锁恢复旧记录、标记和配置。恢复记录绑定系统启动和网络命名空间；身份不匹配、文件损坏或清理失败会拒绝覆盖旧记录。自定义 auto-redirect 的防火墙状态、宿主/Windows 系统网络和完整 DNS 异常矩阵仍在验证。

Linux network journal 保存内核返回的完整规则消息，包括 goto、nop、规则来源及其他选择条件。清理时匹配完整记录并保留其他规则，网卡消失产生的内核状态标记不会阻止恢复。当前记录格式为 version 2；未通过验收的 preview.21 使用 version 1，新包应使用独立目录，旧格式记录不会被自动改写。

TUN 模式会创建接口并调整系统路由/DNS 数据路径。停止时由 Mihomo 清理所管理的接口与路由；持久 kill-switch、宿主异常退出后的系统恢复、完整平台矩阵仍需逐项验证。配置中的 DNS 上游可按使用环境修改；BFP 服务器为域名时，`proxy-server-nameserver` 用于建立承载前的解析。当前样例使用数字服务器地址。

## 检查与源码

```powershell
.\bin\bfp-windows-amd64.exe demo
.\bin\mihomo-bfp-windows-amd64.exe -v
.\bin\mihomo-bfp-windows-amd64.exe -t -d .\runtime -f .\configs\native-proxy.yaml
```

配置检查需要先生成凭据，不建立 BFP 会话。`source/bfp` 和 `source/mihomo` 是构建本包的冻结源码，模块替换使用相对路径，可在其他目录重建。需要 Go 1.26 或更新版本和 Python 3；首次构建会按固定的 go.mod/go.sum 下载依赖。

样例配置中的 `dns.fake-ip-session-proxy: BFP` 将 Fake-IP A/AAAA 映射绑定到 BFP 的实际 Session。首次查询按需建立 Session；UDP 承载切换到 TCP 时沿用同一映射和地址租约。Session 终止后旧地址立即失效，下一次查询才会建立新 Session，并从单调地址空间取得新地址。不要把该映射写入 `profile.store-fake-ip`，也不要把这个地址池用于其他出站。

```sh
python source/build-mihomo.py --version 0.1.0-local --output-root ./dist
```

`source-manifest.json` 和 `release-manifest.json` 记录源码/程序/文件 SHA-256，Mihomo 的 GPL-3.0 许可证位于 `licenses/`，上游源码中保留原有版权与许可说明。

当前属于可运行集成预览版，完整 TUN/系统 DNS/路由生命周期、跨平台异常恢复、原生 sing-box、混合流量分类与纠错效果和长期稳定性仍在完善。传统 SOCKS 入口的既有通过记录不能替代原生 TUN 的验收。
