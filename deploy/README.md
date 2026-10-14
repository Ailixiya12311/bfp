# BFP 双机试用部署

2026-10-13 推荐 Windows 入口为 `credentials-client-ready/BFP 客户端/BFP客户端.cmd`，当前 preview.7 / native preview.36。应用代理真实 HTTPS 和停止恢复已有通过记录，出口为 `192.0.2.10`。两台现有 BFP 实例此前已升级到 preview.36，配置与密钥保留；新加坡历史单次检查取得 207 字节 HTTPS，出口同为洛杉矶，本轮没有使用新加坡或刷新远端运行状态。全局 TUN 最新管理员实机 attempt07 使用私有 debug-tun07，ready 后 HTTPS 仍失败，30.84 秒后结束；最终网卡、物理 DNS、默认路由和客户端资源恢复，清理通过，本机诊断客户端已停止。未进入强杀恢复场景。仅一条会话结束早于 stop 日志创建，对应 outbound 1 / owner 1：业务上下文结束、控制上下文未结束、无关闭意图，来源仍缺失，根因尚未确认。当前实机结论见 `verification/product-windows-tun/windows-tun-real-attempt07.json` 与 `windows-tun-real-attempt07-audit.json`；旧结果、公开发行包保持不变，下方旧版本说明按其原核验日期解释。

这份工具把根协议包作为保留运行的服务，把原生 Mihomo 包作为 Windows 应用入口。当前固定角色是洛杉矶 `192.0.2.10` 接收/出口，新加坡 `198.51.100.20` 发送。配置使用 `low-bandwidth`，出口最多 4 条并发连接、4 个 Session；客户端 SOCKS 只监听回环。

preview.3已提供系统代理接管与恢复。启动后点击“接管 Windows 系统代理”，支持该设置的应用即可使用；停止时恢复原设置，独立监控处理启动器强杀。原设置的敏感备份只保存在受保护的 `deploy/runs/<实例>/system-proxy`，公开状态不返回原值；用户或其它程序变更时保留当前设置并归档旧备份。此功能不等于全局TUN，默认仍需主动点击接管。`credentials-client-ready/BFP 客户端-preview.2` 保留作回退。

当前实例已经准备并启动，日常使用不需要重新执行 `prepare`。在项目根目录双击 `BFP客户端.cmd`，在控制窗口中点击“启动”，将应用的 HTTP 或 SOCKS5 代理设置为 `127.0.0.1:17890`，点击“检查出口”，结果应为 `192.0.2.10`。控制窗口可关闭而保留客户端运行，之后重新打开可查看状态、检查或停止。

独立客户端也已交付：`credentials-client-ready/BFP 客户端/BFP客户端.cmd` 是本机已配置入口；整个目录可在停止后移动，程序不依赖项目 `current.json` 或原有部署绝对路径。私有目录只增加本机现有客户端的 `client.json`，不包含服务端管理配置或 SSH 凭据；目录 ACL 限定当前用户和 SYSTEM。可分享软件包为 `dist/BFP-Client-Windows-0.1.0-preview.4.zip`，里面没有私有配置。两种入口共用本机代理端口，同机一次只运行一份客户端。

本机客户端升级为 preview.4 / 原生 preview.33，加入 Windows 全局 TUN 的管理员启动、接管和恢复；当前 TUN 实机结果以 verification/product-windows-tun 的记录为准，使用说明见 [Windows 全局 TUN](../docs/Windows全局TUN-v0.1.md)。本轮不升级远端，也不使用新加坡。

此前升级为根协议 preview.23、原生 preview.32、独立客户端 preview.3。两台机器已替换为新 Linux 程序并重启，原配置和密钥保留；Windows 常用目录仍是 `credentials-client-ready/BFP 客户端`，旧 preview.1 目录保留为 `credentials-client-ready/BFP 客户端-preview.1`。新客户端实际启动、HTTPS 洛杉矶出口检查和停止回收通过，新加坡只进行一次207字节响应的公网检查。当前 Windows 客户端已停止，两台服务器进程保持运行。此次修复准入防重放与确认校验、增加 LIGHT 随机桶尾；没有重新运行完整 WAN 矩阵或系统 TUN 验收。汇总见 [本轮交付记录](../verification/product-obfuscation/release-preview32.json)。

可重建独立包：`powershell.exe -NoProfile -ExecutionPolicy Bypass -File deploy/build-client.ps1 -Version 0.1.0-preview.4 -NativePackage dist/BFP-Mihomo-0.1.0-preview.33`；加入 `-IncludeCurrentProfile` 会在公开包生成完毕后，另建受保护的本机私有副本。已有输出不会被覆盖，重建时选择新的版本号或输出目录。构建固定复制发布清单内的原生程序和对应源码，单独冻结控制窗口源码，并保留许可证。

2026-10-12 09:10 UTC 新独立目录搬到中文、空格路径后的实际启动、代理归属、公网 HTTPS 和停止回收全部通过；旧目录已不存在，本机代理端口与监督器锁已释放。公开 ZIP 的 1312 个清单文件逐项核对路径、大小和 SHA-256，通过无密钥/无运行记录检查。结果分别是当前实例目录中的 `portable-client-real.json` 与 `portable-package-check.json`。本次还修复 PowerShell 5.1 在替换旧启动记录时把空备份路径绑定成空字符串的问题，并补上便携记录恢复与 PID 复用保护。

命令窗口方式仍可使用：双击 `启动BFP.cmd` 并保持启动窗口运行；`停止BFP.cmd` 停止属于当前实例的客户端，`状态BFP.cmd` 查看本机状态，`检查BFP.cmd` 查询公网出口。停止本机客户端后，两台服务器的试用进程继续运行。

客户端启动记录仅保存进程身份等公开字段。停止入口使用进程创建时间、可执行文件、完整启动命令摘要和已绑定的进程句柄核对身份，再等待监督器释放资源。状态区分“本机代理已监听”和“公网出口已验证”；检查请求只会使用归属已核实的本实例代理。启动日志保存在当前 `deploy/runs/<实例编号>`，控制窗口可查看最近一次日志。Windows 界面与这些日常操作不需要 Python；服务器管理命令仍需要 Python。

本机命令接口也可用于排障：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File deploy/windows-client.ps1 -Action status -Json
powershell.exe -NoProfile -ExecutionPolicy Bypass -File deploy/windows-client.ps1 -Action stop -Json
```

2026-10-12 08:46 UTC 新入口实际验证通过：启动当前发布包并确认 Mihomo → 监督器 → 启动器归属；重复启动被拒绝且原实例不变；`NO_PROXY=*` 下公网 HTTPS 检查仍使用 BFP，出口为洛杉矶；停止后代理端口与监督器锁释放；重复停止成功。六项结果保存在 `deploy/runs/66af4a892648df0a6249d6af3947af68/desktop-lifecycle-real.json`。界面另完成无窗口渲染和中文布局检查；这次记录不扩大为全局 TUN 或长期稳定性验收。

本地归属与误停保护另有 Windows PowerShell 5.1 的 13 项聚焦检查全部通过：创建时间不符、命令摘要不符时拒绝停止，错误 owner 不删除记录，重复启动不覆盖原实例。脚本为 `deploy/test_windows_lifecycle.ps1`，结果为 `deploy/runs/lifecycle-a9d647e1560d470b82665f8d9bb8ba69/result.json`；它使用本地测试启动器，真实代理与监督器的正例以以上六项实际记录为准。

2026-10-12 08:27 UTC 实际核验：洛杉矶接收端和新加坡发送端均在运行；Windows 启动入口和新加坡 SOCKS 均完成公网 HTTPS 请求，出口均为 `192.0.2.10`。新加坡检查响应仅 207 字节，没有进行带宽压测。Windows 检查结束后已停止客户端，验证其代理端口释放。记录位于 `deploy/runs/66af4a892648df0a6249d6af3947af68/desktop-entrypoint.json` 和 `sender-public-https.json`；运行状态随时间变化，可用下方 `status` 命令重新查询。

在项目目录使用已有 Python、Paramiko 和 cryptography：

```powershell
python deploy/pilot.py status --via-receiver
```

远端机器重启后，用同一份配置恢复：

```powershell
python deploy/pilot.py start --role receiver
python deploy/pilot.py start --role sender --via-receiver
```

只有在尚无实例的全新项目目录，才先运行 `python deploy/pilot.py prepare`。它生成受当前 Windows 用户 ACL 保护的 `credentials-pilot-<实例编号>` 目录，输出其中 Windows 客户端的位置。Windows 客户端与新加坡使用不同私钥。Windows 直接连接洛杉矶，无需经过新加坡。新加坡客户端 SOCKS5 入口是该服务器的 `127.0.0.1:1080`。

`--via-receiver` 仅让新加坡的 SSH 管理连接经过洛杉矶，两层 SSH 都验证已固定的主机密钥，凭据留在本机；BFP 业务流量仍然由新加坡直接发往洛杉矶。使用此选项是因为本机直连新加坡 SSH 超时，已经验证经洛杉矶管理可用。

停止命令是：

```powershell
python deploy/pilot.py stop --role sender --via-receiver
python deploy/pilot.py stop --role receiver
```

`stop` 验证 owner、PID、starttime、可执行路径、命令摘要和进程组后才处理本实例，并删除其远端目录；本地私有配置保留供重新启动。同一实例 `start` 会识别已经运行的进程，SSH 不可达时保留原状态和错误，不创建另一个实例。公开状态保存在 `deploy/current.json` 指向的 `deploy/runs/<实例编号>/state.json`，其中没有私钥。

管理命令有本机互斥锁，避免同一目录中的并发启停。`status` 和 `stop` 不依赖本地发布包是否还在。Session 信息来自日志采样：接收端是最新一次 30 秒采样，发送端是初次连接记录，不能把它当作实时承载状态。已有进程的 `start` 不热加载配置；改配置或轮换密钥需先停止再启动。

远端只使用带 owner 标记的 `/tmp/bfp-lab-<实例编号>` 和现有公开程序缓存。日志每 30 秒取一次 Session 状态；没有设置开机启动，重启或 `/tmp` 清理后需要重新执行 `start`。工具不安装 systemd unit，不修改现有服务、防火墙、全局路由、DNS 或系统代理。端口被占用会拒绝部署。

本地私有目录包括服务端管理配置和客户端私钥，不应打包分享；公共 `dist` ZIP 不包含这些配置。当前是供实际使用和逐步修 bug 的预览版，Windows TUN 生命周期、长期压力、真实丢包纠错收益和完整安全审查仍待完成。
