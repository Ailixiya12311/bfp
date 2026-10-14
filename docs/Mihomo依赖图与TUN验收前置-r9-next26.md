# Mihomo 依赖图与 TUN 验收前置（r9-next26）

日期：2026-10-10。

## 依赖图修复候选

Mihomo 的 `config.validateDialerProxies` 只读取 `ProxyInfo().DialerProxy` 来建立 `dialer-proxy` 依赖图。此前 BFP 继承基础 `ProxyInfo`，没有上报自己配置的 detour，因此缺失引用、自引用和循环 detour 不能由主机配置校验器可靠拒绝。

独立候选 [mihomo-next26-proxy-graph](../.staging/mihomo-next26-proxy-graph/) 只改动原生 fork 的一个生产文件并增加两个测试文件：BFP 保存配置阶段的 `DialerProxy`，`BFP.ProxyInfo()` 复制基础信息后报告该边。测试走真实 `adapter.ParseProxy`、真实 AutoClose wrapper、真实 `validateDialerProxies` 和真实 `parseProxies`，覆盖缺失引用、自引用、两节点和三节点 BFP 循环、BFP/SOCKS 混合循环，以及 DIRECT、无环 BFP/SOCKS 链。

候选 `local-attempt02` 结果：17 个顶层、53 个叶子、61 个 pass events，3 个原生包，测试与 vet 均 exit 0；Windows/Linux amd64 主程序 `-trimpath` 构建均 exit 0。冻结 next25 的 199 个 BFP 路径与 1057 个 native 基线未变，候选 native 为 1059 个文件；go.mod/go.sum、离线模块和 `CGO_ENABLED=0` 约束未变。首次 `local-attempt01` 的快照误把 next25/lab 证据计入源码而失败，保留在原目录，不能覆盖修正后的证据。

这仍是独立原生候选，尚未合入根目录，也没有声称 TUN、Linux runtime、WAN 或发布验收通过。候选摘要见 [status.json](../.staging/mihomo-next26-proxy-graph/verification/local-attempt02/status.json)，源变更见 [source-change-manifest.json](../.staging/mihomo-next26-proxy-graph/verification/source-change-manifest.json)。

## 洛杉矶 TUN 前置检查

在不触碰新加坡机器的前提下，对授权洛杉矶接收机做了只读主机快照，并在缓存镜像中运行了一个一次性 `--network none`、`--cap-drop ALL`、`no-new-privileges`、只读根文件系统的 shell 探测。主机为 Debian 12、Linux 6.1、amd64；缓存镜像以完整 digest `sha256:ded31c...af4452` 绑定，Go 1.27.0 可用；宿主机存在 `/dev/net/tun` 字符设备。

镜像内只有 Python 3，未提供 `ip`、`ss` 或 `tcpdump`。随后新增的自包含 Go 探针在单个 owned、`--network none` 容器中显式传入 `/dev/net/tun`，仅增加 `NET_ADMIN`/`NET_RAW`，成功创建并关闭临时 TUN；容器、进程和目录已清理，洛杉矶主机快照无变化。这只证明设备和最小能力可用，尚不能声称业务 TUN、系统 DNS 或 IPv6 通过。后续仍需自包含 netlink 配置、TUN 抓取和真实 Mihomo/BFP 业务矩阵；不得在线安装、使用 host network、修改宿主机永久路由，或把同一 namespace 的直接 echo 当成 TUN 通过。

前置证据：[preflight-receiver.json](../.staging/r9-next25/verification/tun-next26/preflight-receiver.json) 和 [tun-probe.json](../verification/tun-next26/tun-probe.json)。前者包含脱敏后的监听器、容器、默认路由、防火墙和 nftables 配置摘要；后者记录设备创建、capability、owned cleanup 和快照比较。业务负载为零，既有主机服务和 Tailscale 不变。第一次 runner 参数错误的失败保留在同一阶段记录中，未覆盖成功结果。

## 四类状态

这两个结果增加了原生配置图和环境边界证据，但不改变当前功能计数：认证复用、基础伪装与防主动探测为 2 个核心实现；协议内分流、短时 Session 网络为 2 个部分实现；最终验收仍为 0，`acceptance_complete=false`、`production_ready=false`、`released=false`。
