# Windows 全局 TUN 客户端

Windows 客户端在应用代理之外提供全局 TUN 模式。当前公开客户端为 preview.7 / native preview.36，使用原生 Mihomo BFP 出站和 gVisor/Wintun 接入普通 Windows TCP/UDP 流量。线上仍是 BFP 的独立会话协议，默认 UDP，失败后使用 TCP 承载。

2026-10-13 最新管理员实机 attempt07 使用冻结的私有 debug-tun07，TUN 就绪后 HTTPS 仍返回 curl 35 / TLS 握手失败，30.84 秒结束；最终网卡库存、物理 DNS、默认路由及客户端资源恢复通过。没有执行强杀恢复场景。日志仅有一次会话结束早于 stop 日志创建，属于 outbound 1 / owner 1；业务上下文结束、控制上下文未结束、没有关闭意图，但来源仍未记录。根因尚未确认，不能称 TUN 已修复。结果见 [实机 attempt07](../verification/product-windows-tun/windows-tun-real-attempt07.json)和[时间线核对](../verification/product-windows-tun/windows-tun-real-attempt07-audit.json)。旧失败记录继续保留。

## 使用

1. 双击 `BFP客户端.cmd`。
2. 先停止正在运行的客户端，再选择“全局 TUN（需要管理员授权）”。
3. 点击“启动”，在 Windows UAC 中使用当前账户确认管理员授权。
4. 等待“全局 TUN 已就绪”，再点击“检查出口”。检查直接发送 HTTPS 请求，不使用显式应用代理，确认普通系统网络路径的实际出口。
5. 点击“停止”并确认需要的管理员授权，等待本次网络资源回收。

应用代理模式保持可用。其系统代理接管适用于遵循 Windows 当前用户代理设置的应用。运行时不能热切换模式；先停止，再启动另一模式。关闭控制窗口会保留客户端运行。

命令行入口为 `deploy/windows-client.ps1 -Action start -Mode tun`。启动、停止和恢复 TUN 需要管理员 PowerShell；`status` 为只读。便携目录包含客户端凭据时只供本人使用，公开 ZIP 不含配置密钥。

## 接管与就绪

启动器在接管前读取 UDP 和 TCP 服务器地址的现有出口，生成对应 `/32` 或 `/128` 排除前缀，并把承载 socket 绑定到该出口网卡。两个承载地址必须使用同一出口；此版本要求服务器配置采用数字 IP 地址，域名承载的引导解析和地址变化尚未接入。

每次启动生成独立的 `bfp-tun-<随机编号>` 网卡，并记录预期 GUID、实际进程身份和恢复信息。DNS 设置只写入本次 TUN 网卡。就绪判断同时检查 Mihomo 初始化、存活进程、网卡身份、自动路由、TUN DNS 和服务器的原出口路径。代理端口已监听不能代替 TUN 就绪。

`runtime/bfp-windows-tun-journal.json` 是恢复记录，不包含 BFP 密钥。清理失败时必须保留它，不能删除记录来绕过恢复。日志查看按钮包含启动器及原生监督器的诊断。

## 退出与恢复

Windows 监督器将 Mihomo 加入 Job Object；成功加入后，监督器被强制结束也会结束 Mihomo。Mihomo 启动时先挂起，加入 Job 后才恢复线程。创建成功到加入 Job 之间仍有极小窗口：监督器在该窗口被强杀可能留下挂起进程，该进程不能初始化 TUN。这一窗口尚未消除。

停止会等待子进程结束，并核对本次网卡的名称、GUID 和完整 PnP 身份。若网卡仍残留，只移除该设备，不卸载共享 Wintun 驱动，不重置其他网卡 DNS，不批量删除系统路由。身份不一致或清理失败会返回错误并保留恢复记录。

若启动器和监督器同时被强杀，下一次管理员启动或点击停止会继续恢复。原生 `strict-route` 的 WFP 规则仅在进程运行期间生效，不提供退出后的持久断网保护。当前停止路径允许有界等待后强杀子进程，不宣称优雅关闭。

## 交付和验证边界

公开源码、程序和脚本以 native preview.36、Windows client preview.7 包内清单为准。管理员实机验证脚本位于 `verification/product-windows-tun/verify-real.ps1`，计划检查直接出口、普通停止、监督器与启动器强杀后的恢复，并比较原网卡 DNS和默认路由；某一运行在 HTTPS 失败后可能提前退出，实际覆盖范围以该运行 JSON 为准。

私有 `credentials-client-ready/tun-debug07` 已从冻结输入编译，新增 Client parent 取消调用位置、进程内 outbound/owner 关联及四个固定生命周期布尔值；构建记录绑定源码清单和二进制 SHA-256。普通权限下的一次 DNS/HTTPS 应用代理观察与退出清理通过，原检查器的版本日志误判保留在 [原始观察](../verification/product-windows-tun/proxy-debug07-real.json)，版本和构建绑定核对见 [补充审计](../verification/product-windows-tun/proxy-debug07-real-audit.json)，没有重复网络请求。该副本已用于 attempt07 全局 TUN，实测失败和恢复成功分别保留；它包含本机凭据，不用于分享。后续开发源码补齐原始业务取消边界，尚不能据此确认 TLS 根因或全局 TUN 修复。

隔离状态测试、语法检查和 Job Object 进程测试只能证明对应实现行为。真实 Windows TUN 接管及恢复的结果必须查看本轮实机 JSON；没有该记录时不能宣称已经通过。整个项目的四类需求和长期稳定性仍未完成最终验收。
