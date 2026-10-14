# 分类器 CLI 与本地适配器接入方案

日期：2026-10-07。状态：**只读差距审查与下一阶段设计，尚未实施**。本次只新增本文，不修改主 Go、staging、wire 或历史验收结果，不执行远程实验。

本方案以已合入主源码的 [分类器接线实现-r8](分类器接线实现-r8.md) 为 API 基线。r8 独立验收以 [验收记录](验收记录-v0.1-r8.md) 为准，本文不宣布尚未登记的 race/WAN 结果。早期 [接入方案与版本边界](接入方案与版本边界.md) 第 7 节和 integrations README 尚有“Session 未接分类器”的历史描述，不能据此回退 r8 已实现 API，也不能据 r8 推导原生集成完成。

## 1. 直接阻塞与本轮决策

| 已核对的差距 | 为什么阻塞接入 | 固定处理 |
|---|---|---|
| CLI Config 没有 classification，sessionConfig 只转 lifecycle options | Go 已支持，但 CLI 无法传策略；只补一端会漏另一方向 | client/server 共用 DTO/转换器，分别传自己的 Config；probe 复用 client 转换 |
| nil Go Config 与显式 Config{} 含义不同 | 直接 JSON 解码核心 Config，{} 会变成 Interactive 默认且行为关闭 | CLI 从 DefaultConfig 覆盖存在的字段；{} 是默认，null 是错误 |
| Decoder 禁未知字段但默认允许重复键 | 重复 enabled/class 会静默采用后值；RawMessage 子对象须单独解码 | 新子树拒绝重复/未知/null/错类型；根新增同名键也查重复 |
| SOCKS Backend 只有 DialContext，两处只传 address | 保留目的字符串，却没有来源与可信标记 | 可选 DialMetadata 能力、统一拨号 helper；旧 Backend 兼容 |
| loopback SOCKS 是无认证入口 | 本机可访问者能任意声称名字，不能证明应用或域名所有权 | 默认 ignore；明确 opt-in 后仅接受实际 ATYP=3 名字参与本地调度 |
| server 不信任 wire Domain/RuleTag | server 配域名规则也不会自动按 client 域名分类下载 | server 独立 network/port/default 生效，不增加 wire 信任 |
| UDP cache 以 address 为 key，保存首个 encoded | 每包改类/redial/改 key 会改变流和回包身份 | 仅 cache miss 创建 metadata，保留现有 key/encoded/生命周期 |

范围分 C1（CLI 策略解析）、C2（SOCKS 域名桥）。不依赖阶段 B，不含原生补丁、TUN、carrier dial hook、UDP PacketConn 或每设备策略映射。

## 2. JSON 位置、缺省与兼容

client.json/server.json 新增顶层 classification；只有 client.json 可有 socks_metadata。两者与 options 平级，不修改凭据和生命周期字段。

| 输入 | 合同 |
|---|---|
| 省略 classification | 传 nil，核心 DefaultConfig；旧配置行为不变 |
| classification={} | 从 DefaultConfig 构造完整非 nil 策略；不使用 Go 零值 |
| 部分字段、behavior={} | 只覆盖提供项，其余保留默认 |
| enabled=false、restore=false | 保留显式 false，不视为省略 |
| cooldown="0s" | 有效显式零，不替换成默认 5s |
| 新子树、数组或任何提供字段为 null | 错误，不等于省略 |
| rules=[] | 空规则表，不清掉默认类别/行为 |
| 省略 socks_metadata 或 {} | domain_source=ignore |
| server.json 提供 socks_metadata | 未知字段错误，无本地 SOCKS 来源 |

旧二进制会拒绝新增字段，属于明确配置不兼容。keygen 继续省略新字段以保留旧默认文件，不能升级时自动打开域名信任。读取保留 private config、64 KiB 上限、尾随检查；错误给路径如 classification.rules[2].ports[0].last，不打印输入域名/tag/原配置/凭据。

### 2.1 精确字段与默认

类别只接受小写 interactive/normal/bulk，映射核心 0/1/2；不接受数字或 download 等展示名。

| 分类字段 | 类型 | 默认 | 限制 |
|---|---|---|---|
| default_class | class string | normal | 固定枚举 |
| highest_allowed | class string | interactive | normal 允许 Normal/Bulk；bulk 仅允许 Bulk |
| rules | array | [] | 至多 128 条，顺序保留 |
| behavior | object | 默认行为完整对象 | 逐字段覆盖 |

| rule 字段 | 类型与默认 | 限制 |
|---|---|---|
| name | 必填 string | 有效 UTF-8，1–128 字节，无控制字符，同配置唯一 |
| class | 必填 class string | 省略必须错误，不能默认为 Interactive |
| priority | signed integer，0 | -2147483648..2147483647 |
| locked | boolean，false | 仍受 highest_allowed |
| network | 可选 tcp/udp | 省略为空 selector，显式空串错误 |
| ports | 可选非空 array | 至多 64 个 first/last 对象，两值必填 1..65535，last>=first；单端口填相同值 |
| domain/domain_suffix | 可选非空 string | ASCII DNS、非 IP、最多 253 字节/标签 63，互斥；核心归一化 |
| rule_tag | 可选非空 string | 有效 UTF-8，最多 256 字节，无控制字符，仅可信本地 tag 匹配 |

每条至少有一个 selector。多个 selector 为 AND，ports 内范围为 OR。可信 Hint → metadata 规则 → target 规则 → default；只在同组按 Priority 降序，同 Priority 保留配置顺序，不能把两组混排。

| behavior 字段 | 类型 | 默认 |
|---|---|---|
| enabled | boolean | true |
| window/bucket | Go duration string | 4s / 250ms |
| min_total_bytes | unsigned decimal integer | 1048576 |
| bulk_bytes_per_second | unsigned decimal integer | 262144 |
| bulk_sustain/activity_gap | Go duration string | 3s / 1s |
| restore | boolean | true |
| restore_bytes_per_second | unsigned decimal integer | 65536 |
| restore_sustain/cooldown | Go duration string | 8s / 5s |

duration 必须能由 time.ParseDuration 精确解析；只有 cooldown 可零，其余为正，不接受空串、数值纳秒、1d、负值或溢出。三个计数字段为 1..18446744073709551615，以原始十进制整数字面量直接解码 uint64，不经 float64，不接受小数、指数或数字字符串。

完整参数须满足 window<=1min、window 是 bucket 整数倍、桶数 2..1024、activity_gap>=bucket、bulk_sustain>activity_gap、restore rate<bulk rate，以及核心 rate×window 不溢出。CLI 即使 enabled=false/restore=false 也校验完整参数；禁用用布尔，不用零阈值。可用副本临时 Enabled=true/Restore=true 调 classification.New 复用语义验证，然后返回原开关，不另写算法约束。

### 2.2 Draft 2020-12 新子树 Schema

下面是须合并进现有 client/server schema 的定义片段。default 为注解，parser 按 presence 覆盖；自定义 format、字节长度、重复键、整数原始表示、跨字段关系由 Go 验证，通用 JSON Schema 不能独自验证全部合同。

~~~json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$defs": {
    "class": { "type": "string", "enum": ["interactive", "normal", "bulk"] },
    "duration": { "type": "string", "minLength": 1, "format": "bfp-go-duration" },
    "u64": { "type": "integer", "minimum": 1, "maximum": 18446744073709551615 },
    "portRange": {
      "type": "object", "additionalProperties": false, "required": ["first", "last"],
      "properties": {
        "first": { "type": "integer", "minimum": 1, "maximum": 65535 },
        "last": { "type": "integer", "minimum": 1, "maximum": 65535 }
      }
    },
    "rule": {
      "type": "object", "additionalProperties": false, "required": ["name", "class"],
      "properties": {
        "name": { "type": "string", "minLength": 1, "maxLength": 128 },
        "class": { "$ref": "#/$defs/class" },
        "priority": { "type": "integer", "minimum": -2147483648, "maximum": 2147483647, "default": 0 },
        "locked": { "type": "boolean", "default": false },
        "network": { "type": "string", "enum": ["tcp", "udp"] },
        "ports": { "type": "array", "minItems": 1, "maxItems": 64, "items": { "$ref": "#/$defs/portRange" } },
        "domain": { "type": "string", "minLength": 1, "maxLength": 253, "format": "bfp-ascii-domain" },
        "domain_suffix": { "type": "string", "minLength": 1, "maxLength": 253, "format": "bfp-ascii-domain" },
        "rule_tag": { "type": "string", "minLength": 1, "maxLength": 256 }
      },
      "not": { "required": ["domain", "domain_suffix"] },
      "anyOf": [
        { "required": ["network"] }, { "required": ["ports"] },
        { "required": ["domain"] }, { "required": ["domain_suffix"] }, { "required": ["rule_tag"] }
      ]
    },
    "behavior": {
      "type": "object", "additionalProperties": false,
      "properties": {
        "enabled": { "type": "boolean", "default": true },
        "window": { "$ref": "#/$defs/duration", "default": "4s" },
        "bucket": { "$ref": "#/$defs/duration", "default": "250ms" },
        "min_total_bytes": { "$ref": "#/$defs/u64", "default": 1048576 },
        "bulk_bytes_per_second": { "$ref": "#/$defs/u64", "default": 262144 },
        "bulk_sustain": { "$ref": "#/$defs/duration", "default": "3s" },
        "activity_gap": { "$ref": "#/$defs/duration", "default": "1s" },
        "restore": { "type": "boolean", "default": true },
        "restore_bytes_per_second": { "$ref": "#/$defs/u64", "default": 65536 },
        "restore_sustain": { "$ref": "#/$defs/duration", "default": "8s" },
        "cooldown": { "$ref": "#/$defs/duration", "default": "5s" }
      }
    },
    "classification": {
      "type": "object", "additionalProperties": false,
      "properties": {
        "default_class": { "$ref": "#/$defs/class", "default": "normal" },
        "highest_allowed": { "$ref": "#/$defs/class", "default": "interactive" },
        "rules": { "type": "array", "maxItems": 128, "default": [], "items": { "$ref": "#/$defs/rule" } },
        "behavior": { "$ref": "#/$defs/behavior" }
      }
    },
    "socksMetadata": {
      "type": "object", "additionalProperties": false,
      "properties": {
        "domain_source": { "type": "string", "enum": ["ignore", "socks_address"], "default": "ignore" }
      }
    }
  }
}
~~~

client 根新增 classification 引用 #/$defs/classification、socks_metadata 引用 #/$defs/socksMetadata；server 仅前者。根继续 additionalProperties=false。

### 2.3 仅说明新字段的配置片段

片段省略地址/凭据/既有字段，当前 r8 CLI **尚不能使用**。

客户端明确接受 SOCKS 地址域名影响本地上行规则，不创造 Hint：

~~~json
{
  "classification": {
    "default_class": "normal",
    "highest_allowed": "interactive",
    "rules": [
      { "name": "local-call", "domain_suffix": "call.example.test", "class": "interactive" },
      { "name": "large-transfer-port", "network": "tcp", "ports": [{ "first": 8443, "last": 8443 }], "class": "bulk" }
    ],
    "behavior": { "enabled": true, "cooldown": "0s" }
  },
  "socks_metadata": { "domain_source": "socks_address" }
}
~~~

服务端独立下行策略，不接受客户端类别或域名信任：

~~~json
{
  "classification": {
    "default_class": "normal",
    "highest_allowed": "normal",
    "rules": [{ "name": "server-udp", "network": "udp", "class": "normal" }],
    "behavior": { "enabled": false }
  }
}
~~~

客户端 Interactive、服务端 Normal 可同时成立。为得到对称类而信任 OPEN.Domain/Class 会破坏既定边界。

## 3. SOCKS 可信来源与最小桥

DomainTrusted 只表示管理员接受该来源影响本地分类，不证明域名所有权、应用/进程、DNS、包内容或授权。同机其他可连接 loopback 的程序也能声称名字；影响仍受 client cap 和 server 出口 Policy 限制。

| 内容 | Domain / DomainTrusted | Tag / Hint |
|---|---|---|
| 默认 ignore | 空/false，Address原样 | 空 tag/false，Hint=nil |
| opt-in + 实际 ATYP=3 合法 ASCII DNS | 请求原名/true，核心仅归一化匹配 | 空 tag/false，Hint=nil |
| ATYP=1/4 IP | 空/false，不 reverse DNS/sniff | 空 tag/false，Hint=nil |
| ATYP=3 文本 IP | 空/false，走IP/port规则，不送DNS validator | 空 tag/false，Hint=nil |
| opt-in 非法 DNS/Unicode U-label | 明确失败，不降为无信任规避规则，不OPEN | 不伪造来源 |
| probe target、普通 DialContext 域名 | 没有 SOCKS ATYP 来源，不自动信任 | Hint=nil |
| 未来进程内 route/sniff snapshot | 本地配置固定来源，尚未桥接 | 稳定tag/显式Hint另设计 |
| 解密 peer OPEN | server保持不可信 | wire Class不创建Hint |

本轮不加 IDNA 依赖；ASCII punycode 可用，Unicode U-label 在 opt-in 模式失败。ignore 保留原解析路径，不偷偷 DNS/sniff/转写。域名大小写/末尾点的分类归一化不改 Address；分类不改目标或端口，gateway 仍验证实际 Address 的全部 DNS 答案并拨 numeric peer。

保留 Backend.DialContext，增加可选能力：

~~~go
type MetadataBackend interface {
    DialMetadata(context.Context, classification.Metadata) (net.Conn, error)
}
~~~

socks.Config 新增 typed DomainSource（ignore/socks_address），zero 为 ignore。启用域名模式但 Backend 不实现能力时，New 在 Listen 前失败，不静默回退并声称策略生效。Config 不接受每请求 class/tag/process/trusted 字段。

统一 private dialTarget(ctx, network, address, atyp)：

1. ignore 调现有 DialContext，无 Hint。
2. opt-in 构造 Target{Network,Address,Class:Normal}；Normal 仅是结构值，Hint仍nil。
3. 仅实际 ATYP=3 host 可成为域名；文本 IP 例外。非法可信域名在核心 OPEN/ID 分配前失败。
4. 调 DialMetadata，不经 DialClass(Normal)，禁止 NormalTrustedHint 覆盖规则。
5. TCP 原返回 conn 保留 CloseWrite/deadline，错误走现有 SOCKS reply 1。

CONNECT 使用 request[3]；UDP 使用业务包 buffer[3]，不使用 UDP ASSOCIATE 控制请求的接收地址。readAddress 返回的 encoded[0] 已保留 ATYP，可不破坏编码合同地传给 helper。标准 SOCKS 没有 Clash tag/进程/class；不能从域名/端口/payload 伪造这些来源。

### 3.1 UDP 有界缓存

仅 udpControl.target cache miss 创建 metadata 和 Flow；cache hit 复用原 baseline，后续行为观察自然调整。保留 address key 和首次 encoded 回包封装，不每包 redial/改 OPEN。

完全相同地址复用；大小写/末尾点使原 Address 不同时，仍按旧规则占不同有界 target，不为 hint 归一化合并真实身份。文本 IP ATYP3 与 IP ATYP1/4 解析成同 Address 时复用并保持首次封装，均无可信域名。

保留 MaxUDPTargets、source IP/port 绑定、FRAG丢弃、控制关闭清理、空报/16KiB上限；不加无界 map、长期域名缓存或重试。无热更新；改来源配置须重建 adapter/Client，不能承诺旧连接迁移到新 Session。

## 4. 本地 metadata 与原生集成

公共桥只让本地已知目的名参与本地分类，不提供远端信任、类别公告或路由引擎。未来进程内层须复制目的、fake-IP恢复、sniff、route snapshot 并固定来源优先级；不是默认信任任意 context。

不得把 RouteOutbound、SpecialRules、route 显示字符串当稳定 RuleTag；只有管理员的有限映射生成 tag/显式 Hint，缺映射留空。它们不来自 wire，且不加入进程身份到 OPEN。

server CLI domain/tag 规则合法但无可信本地来源时不匹配 peer 声称值。本轮不放宽信任来让这些规则“生效”；未来 gateway 事实到 Session 的本地来源须另设计。

| 模式 | 本轮范围 | 仍待 |
|---|---|---|
| 应用→loopback SOCKS | CLI策略、可选ATYP桥、仓库回归 | 第三方版本/平台矩阵 |
| Mihomo/sing-box现有socks outbound | 与标准SOCKS来源相同 | 指定版本实测；不是原生bfp |
| Mihomo原生bfp | 本轮不实施 | parser/type/outbound、routecontext、carrier hook、PacketConn、TUN/fake-IP与支持矩阵 |
| sing-box原生bfp | 本轮不实施 | option/registry/outbound、context、carrier hook、PacketConn、TUN/fake-IP与支持矩阵 |

SOCKS丢域名时不从IP反推应用；fake-IP须上游先恢复，缺记录失败。固定UDP Flow不是PacketConn，本桥不实现UoT。[原生接入文档](../integrations/README.md) 的上游tag/SHA只是计划基线，不是运行通过证据。

## 5. 有界实施清单

C1：新增 cmd/bfp/classification.go/test 做 presence DTO、strict decoder、类型/限额/语义转换；main.go 添加 RawMessage 顶层字段与新根键重复检查；options.go 两角色各传 Classification。client.validateOptions 同时校验 socks_metadata，错误早于 Connect/Listen。keygen继续省略新字段，probe不因target字符串生成来源。无热加载、CLI覆盖或新wire。

C2：adapter/socks/server.go 新 typed来源、可选接口、New能力校验、single helper和CONNECT ATYP；udp.go只在cache miss传业务ATYP，保留key/encoded/cleanup；CLI向socks.New传domain_source，不改核心算法/信任。假记录backend查envelope，真实Client/Server/SOCKS验证实际规则与目标。

可分别隔离实施与记录 manifest，只在各自验证后更新支持状态；不修改r8历史证据，不继承其远程结论。

## 6. 必要测试矩阵

| 组 | 覆盖 | 判定 |
|---|---|---|
| 兼容/presence | 旧keygen、省略/{}、rules=[]、false/0s、null各层 | 默认Normal+行为on；false/零保留；null拒绝 |
| strict JSON | 重复/未知/尾随/错类型/非法UTF8 | 字段路径错误，无输入或凭据泄漏 |
| 数值/额度 | uint64极值/溢出/指数、小数，priority32bit，129rule/65range | 无float丢精度，限额拒绝，合法数再核心验证 |
| 规则 | 缺name/class、重名、空selector、domain互斥、端口逆序、同Priority | 错误明确/顺序稳定，不缺class→Interactive |
| 行为 | disabled/restorefalse非法dormant值、桶/窗口/迟滞关系 | 完整校验，不以disabled逃逸 |
| 双角色/probe | 两端不同策略，probe共用client配置 | 不漏映射、不让probe目标产生SOCKS信任 |
| 构造时序 | occupiedSOCKS Listen+旧Backend开启来源；非法分类+不可达服务端 | 优先配置/能力错，无socket/目标dial |
| 默认桥 | 旧Backend、TCP/UDP域名 | 无Hint/tag/DomainTrusted，port规则有效 |
| opt-in CONNECT | ATYP3 DNS、大小写/点、文本IP、ATYP1/4 | 仅真实DNS来源，Address不改 |
| 域名错误 | 控制/空/超长/Unicode/IP伪装、punycode | opt-in错误不OPEN；合法punycode命中 |
| UDP来源 | 控制ATYP和业务ATYP不同组合 | 只用业务目的来源 |
| UDP缓存 | 重复/多目标、ATYP别名、首回包、target cap | 不每包dial/改OPEN，旧额度/身份保留 |
| 信任 | 伪造tag/class/process、cap、clientDomain与server域名规则 | 不创造Hint/tag，server不继承client信任 |
| 授权 | 声称域名而实际私网/IP/受限端口 | gateway按实际Address拒绝 |
| 生命周期 | 半关闭/deadline/cancel、source/FRAG/controlclose | 不回退现有传输清理合同 |
| 真实runtime | SOCKS→真实Client/Server→TCP/UDP目标与分类Snapshot | 上行命中，下行独立，目标/字节不变 |
| 交接 | source/hash、test/vet、独立race、支持矩阵 | 只记实际运行，不把SOCKS填进native单元格 |

不重复把阶段A已有唯一字节/恢复测试当新来源接入证据；新桥经过这些路径时保留必要回归，结果绑定同一source修订。

## 7. 只读审查证据

读取 cmd/bfp/main.go:28/43/146（Config/read/SOCKS），options.go:103/111（双角色）；adapter/socks/server.go:206/290（CONNECT/解析）、udp.go:114/124/140（cache/dial/首encoded）；核心规则/行为与r8 DialMetadata。关键SHA256如下：

| 文件 | SHA256 |
|---|---|
| cmd/bfp/main.go | ebec05dfc454e17a92326e783643a5489e61912b4de0f54ec4e5d2367d0759ad |
| cmd/bfp/options.go | 462d455d28dfb2d7b280ec07d09dd5021ea8e424dea419bcea37303bbdf945d3 |
| adapter/socks/server.go | 8bb16b3499395c6b0d2b9bb3a1dcc10b1af84cebeb624c2ea8f996ed19509221 |
| adapter/socks/udp.go | 749fc1bcd9377c54287624331ba7b513e0b9defc8630a901c5757f43359bcf35 |
| session/client.go | 130e49cd590a3e507bd39f86634bbb1b13ac12e3eca23122f5febb047932f73f |
| session/session.go | b403a74cc63b9c89ef6a6e2d29a632811a7351215f8009eaafcfc68d8665e5ee |

本文是设计审查。Schema/示例只做JSON语法核查，无新CLI/adapter实现、运行测试、原生构建或远程支持声明。
