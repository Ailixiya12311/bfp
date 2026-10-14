# 受信本地元数据桥接：r9-next17

日期：2026-10-09

源码候选位于 `C:\Users\developer\Desktop\bfp\.staging\r9-next17`，由 `r9-next16` 独立复制建立。该阶段只实现 Go 进程内的 adapter-neutral 本地元数据桥接，不声称已经实现 Mihomo、Clash 或 sing-box 原生 outbound。

## 目标和边界

普通 wire/JSON/SOCKS Target 只提供结构目标。`NewLocalMetadataBridge` 会清除 `Target.Domain`、`Target.RuleTag` 和 `Target.Class`，并把初始类别恢复为 `Normal`。只有调用方显式提供受控来源时，桥接才会增加本地信任：

- `WithTrustedDomain`：校验 ASCII DNS 名称后启用本地域名规则；
- `WithTrustedRuleTag`：校验本地规则标签后启用标签规则；
- `WithTrustedApplication`：校验最多 128 字节的 ASCII opaque ID，并写入 `Metadata.Application`。应用身份不写入 `protocol.Target`，因此不会出现在 OPEN 的 JSON 中。

应用规则使用新增的本地 `classification.Rule.Application` 选择器。`Application` 与 `ApplicationTrusted` 只在本地 classifier 内部使用，peer 端从 OPEN 解码出的 Target 不会自动获得该字段或信任。

Bridge 每次返回 Metadata 时复制 `Delivery`、`FEC` 和 `Hint`，避免调用方通过可变指针改写桥内部状态。桥接合同只约束同进程适配器调用方，不能防止同进程恶意代码直接伪造兼容 API 的 trust bool。

SOCKS 的 `socks_address` 来源在非法域名、Unicode、空标签、超长标签或其他格式错误时立即返回 `classification.ErrMetadata`；不会调用 `DialMetadata`、旧 `DialContext` 或建立目标连接。合法域名仍只来自真实 SOCKS ATYP=3，UDP 业务目的地址不会继承 UDP ASSOCIATE 控制请求的 ATYP。

## 验证

冻结清单和证据索引：

- manifest：`9a6d248422f46de9945b22fb0b4de514855666d6b5015a555b525cab8fecbd79`，146 个 Go/module 文件；
- 本地 gate：[local-summary.json](../.staging/r9-next17/verification/r9-next17/local-gate-attempt01/local-summary.json)；
- 有限 fuzz：[fuzz/summary.json](../.staging/r9-next17/verification/r9-next17/fuzz/summary.json)；
- 证据索引：[evidence-index.json](../.staging/r9-next17/verification/r9-next17/evidence-index.json)；
- 洛杉矶 Linux race：[race-result.json](../.staging/r9-next17/lab/runs/ff1b5a528f0e23ac0dde3921e53a2b07/race-result.json)。

本地 gate 结果为 17 个包、475 个顶层测试通过，`go vet ./...` 通过，Windows amd64 和 Linux amd64 构建通过。修订后的分类器、SOCKS 和真实加密 Session 测试分别证明：应用规则只影响本地 TX；peer 不继承本地信任；应用身份不会出现在 OPEN Target；非法 SOCKS 域名不会触发后端拨号。5 秒、2 worker 的 repair-parser fuzz 通过且源码清单未变。洛杉矶 race 使用同一清单和 Linux 二进制关联哈希，exit 0、无 `DATA RACE`、owned 容器/目录已清理、接收机快照 unchanged。

## 不应从本阶段推导的结论

该桥接不包含 Clash/Mihomo/sing-box 的 `ProcessInfo`、`RouteRule`、`RouteOutbound` 解析或稳定映射，不包含原生 BFP outbound、PacketConn、TUN、fake-IP/reverse-NAT、客户端 DNS 代理、IPv6 矩阵或第三方软件运行验证。四类状态仍为 **2 类主体实现、2 类部分实现、0 类最终验收**；`acceptance_complete=false`、`production_ready=false`、`released=false`。本阶段也没有新加坡到洛杉矶 WAN 业务测试。
