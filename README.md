# BFP 独立代理协议

BFP 是 Go 实现的独立会话协议，默认使用 UDP，承载失败后切换到 TCP。会话拥有流、临时地址和目标连接，客户端通过 SOCKS5、HTTP 代理或 Mihomo TUN 接入普通应用。

**当前能使用的是 Windows 应用代理预览版。全局 TUN 已能启动和恢复，但 HTTPS 仍失败，尚未完成。整个项目仍在开发，不是成熟发布版。**

源码仓库的构建方法、配置准备与本地证据边界见[仓库说明](docs/仓库说明.md)。

## 直接使用

本机已配置入口：[BFP 客户端](credentials-client-ready/BFP%20客户端/BFP客户端.cmd)。

1. 双击入口，选择“应用代理”，点击“启动”。
2. 在应用填写 HTTP 或 SOCKS5 `127.0.0.1:17890`，也可以在窗口点击“接管 Windows 系统代理”。
3. 点击“检查出口”，应显示洛杉矶 `192.0.2.10`。
4. 点击“停止”回收资源。窗口关闭后客户端仍运行，重新打开即可停止。

当前私有目录使用 Windows **preview.7** / native **preview.36**，包含本人客户端配置，不适合分享。`credentials-client-ready/BFP 客户端-preview.6` 和更早版本保留供回退。移动目录前先停止客户端。

可分享软件包：

- [Windows 便携客户端 preview.7](dist/BFP-Client-Windows-0.1.0-preview.7.zip)：控制窗口、Windows 程序、冻结源码和许可证。
- [原生 Mihomo 包 preview.36](dist/BFP-Mihomo-0.1.0-preview.36.zip)：Windows/Linux amd64 程序、启动脚本和冻结源码。

公开 ZIP 不含凭据。另一台电脑使用时，将获服务端授权的客户端配置放入 `client/credentials/client.json`。软件包不需要安装 Python、Go 或系统服务。

## 当前实机状态

2026-10-13 用当前 preview.7 程序完成 HTTPS 应用代理检查，实际出口为 `192.0.2.10`；停止后端口、锁和临时资源释放。见 [应用代理实测](verification/product-windows-tun/proxy-preview7-real.json)。

本次修复状态查询与启动的短时系统代理锁竞争；Session 的控制状态预算现在覆盖原有 4096 个累计流状态，超预算控制不再发送缺少 revision 的报文。32 条同时存活流的默认上限没有改变。这两处缺陷已经验证，但尚不能认定为 TUN 的 TLS 根因。

Windows TUN 就绪检查的两个脚本缺陷已经修复：数组 `Address()` 方法与端点字段碰撞、`Find-NetRoute` 混合返回对象。2026-10-13 最新管理员实机 attempt07 使用已冻结的私有 debug-tun07，达到 `ready=true` 后 HTTPS 仍返回 curl 35 / TLS 握手失败，30.84 秒后结束；网卡库存、物理 DNS、默认路由及客户端资源均恢复到测试前状态，最终清理通过。因为 HTTPS 失败，本次没有进入强杀恢复场景。见 [TUN attempt07](verification/product-windows-tun/windows-tun-real-attempt07.json)和[失败日志核对](verification/product-windows-tun/windows-tun-real-attempt07-audit.json)。此前 attempt03 至 attempt06 的原始结果保留。

attempt06 已包含本地/对端正常关闭来源，但仍报告 `context_end_without_cancel`，根因未确认。三条结束事件中仅第一条发生在停止操作前，另外两条发生在停止后；不能据此认定是 Fake-IP flush 或对端主动关闭，也不能把不同 owner 的后续 OPEN 当成同一个 Session 仍然存活。开发源码进一步补充 Client parent 取消调用位置、进程内 outbound/owner 序号及四个固定生命周期布尔值。诊断不等于修复，不修改冻结 preview.7 / preview.36。当前暂用应用代理；TUN 需要管理员权限，域名承载、不同出口网卡和完整 IPv6 公网场景尚不支持或未完成验收。

两台现有 BFP 实例已同步到 preview.36，配置和密钥保留。角色仍为洛杉矶接收/出口、新加坡发送；先缓存程序再切换实例，新加坡仅执行一次 207 字节 HTTPS 响应检查，出口为洛杉矶。见 [升级记录](deploy/runs/66af4a892648df0a6249d6af3947af68/upgrade-preview36.json)与[发送端实测](verification/product-windows-tun/sender-preview36-real.json)。

[原交付记录](verification/product-windows-tun/release-client-preview7.json)记录包哈希、可用范围和未完成项；[attempt05 补充记录](verification/product-windows-tun/release-client-preview7-tun-attempt05.json)与[attempt06 补充记录](verification/product-windows-tun/release-client-preview7-tun-attempt06.json)分别保留对应运行，不覆盖旧失败或冻结包。[包核对记录](verification/product-windows-tun/package-check-preview7.json)只证明包、清单和冻结文件绑定。

私有 debug06 在不接管本机网络的代理模式下完成 IPv4/IPv6 Fake-IP 路径的两次真实 HTTPS，以及一次有有效回复的 UDP DNS，未出现停止前的会话结束事件，停止后资源清理通过。见[原生代理诊断](verification/product-windows-tun/native-mixed-debug06.json)。其中 SOCKS 握手计数不代表出口 OPEN 成功；IPv6 Fake-IP 恢复为域名后仍使用洛杉矶 IPv4 出口，也不代表公网 IPv6 验收。该结果没有修复或验证全局 TUN。

私有诊断副本 `credentials-client-ready/tun-debug07` 已从冻结的 1286 个本地源码文件构建，二进制与源码清单绑定通过。普通权限 DNS/HTTPS 应用代理观察通过，见[debug07 观察审计](verification/product-windows-tun/proxy-debug07-real-audit.json)；原观察器的版本日志误判记录保留。attempt07 已实际使用该程序接管全局 TUN：第一条停止前异常属于 `(outbound=1, owner=1)`，`business_ended=true`、`control_ended=false`，两个关闭意图字段均为 false，来源仍未记录；后两条结束事件发生在停止后。这组观测尚未对应到根因，不能归因 Fake-IP flush、对端关闭或父取消。开发源码正在补齐 raw business cancellation 边界与普通权限本地转发复现；没有修改已冻结的 debug07 或公开包，也没有确认修复 TUN。

开发源码另已修复失效 Session Fake-IP 租约的无效重试：同一旧租约不再最多拨号十次，立即返回原错误；普通临时错误仍可重试。实际 retry 函数的聚焦检查通过，见[源码修复记录](verification/product-windows-tun/session-fakeip-retry-source-fix.json)。这项变更尚未编入公开包或已冻结的 debug07，也未证明是 TUN TLS 根因。

TUN 日志整理工具已兼容 debug07 的来源、出站/会话序号和生命周期字段，并按实际控制结果计算 HTTPS 与强制终止覆盖；只读复核保留了 attempt06 的全部原始记录，见[解析工具修复记录](verification/product-windows-tun/capture-parser-source-fix.json)。停止前后比较使用最早 stop 日志的文件创建时间作为近似界线，不能据此认定关闭根因。

## 四类需求

| 需求 | 当前实现 | 仍需完善 |
|---|---|---|
| 认证复用 | Session 复用、多流、密钥更新、Ticket 刷新、承载恢复 | 长时间恢复、资源压力、异常与安全审查 |
| 混淆与防主动探测 | 加密内部结构、首包准入、防重放、长度填充、无效探测不返回应用数据 | 时序策略、专项安全审查；公网 IP、端口、包长和时序仍可观察 |
| 协议内分流 | 端口/协议/域名分类、行为降级、调度和类别纠错策略 | 混合负载公平性、背压和真实丢包下的纠错收益 |
| 短时会话网络 | 临时地址、目标连接、Session DNS/Fake-IP 归属与失效 | 完整 Windows TUN 联网与恢复、系统缓存生命周期、IPv6 公网 |

当前为 **2 类核心实现、2 类部分实现，4 类均未完成最终验收**。认证复用仍包含每条记录的完整性和重放校验。

## 开发

项目根目录是可修改的 Go 模块，需 Go 1.26 或更新版本。

```powershell
go build -o .\bin\bfp-dev.exe ./cmd/bfp
.\bin\bfp-dev.exe demo
```

`demo` 用本机临时凭据完成加密 UDP 会话的 TCP/UDP 转发与初始 UDP→TCP 回退；它只访问回环地址。原生接入源码位于 `integrations/mihomo/source`，Windows 客户端源码位于 `deploy`。每个交付包另有对应冻结源码和 SHA-256 清单，后续源码修改不会自动改变已冻结包。

## 文档

- [协议技术设计](docs/协议技术设计-v0.1.md)：设计目标与会话模型。
- [线上格式](docs/wire-v0.1.md)：实际协议字节合同。
- [产品说明](PRODUCT.md)：能力、限制和详细历史证据。
- [双机部署](deploy/README.md)：服务器角色、管理入口与停止恢复。
- [Windows TUN](docs/Windows全局TUN-v0.1.md)：权限、接管和恢复设计；当前实机结论以上述 attempt06 为准。
- [发布与验证历史](RELEASE_HISTORY.md)：各旧版本的通过和失败；旧版本记录不当作当前程序的新验收。
