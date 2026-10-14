# BFP 实验 wire v0.1

日期：2026-10-07；准入与LIGHT说明更新：2026-10-12（preview.23 / 原生preview.32）。本文描述 `protocol/`、`security/` 与 `session/` 当前 Go 实现的线上合同，供测试、抓包与后续规范冻结使用。它不是已审计密码规范或稳定互操作承诺；修改字段时必须同步源码、测试向量与本文版本。设计目标详见技术草案，实现差异详见实现进度。

本文件前八节保留早期实验 wire 的基线，不能替代后续 r9 的 PacketAck、ControlReceipt、ResumeDone 或 wire3 分类公告合同。当前实验构建以 [r9 技术文档](C:/Users/developer/Desktop/bfp/docs/BFP协议技术文档-v0.1-r9.md) 的相应修订为准；next10 对既有 19/20 的关闭合同明确化见第 9 节。

## 1. 整体结构

首次接入和恢复先使用准入密钥保护的 bootstrap envelope。在 bootstrap 内执行 Noise 消息和带挑战的加密确认。完成会话提交及 ready 后，两端使用新承载的方向密钥发送活动记录。

```text
首次/恢复：admission envelope(JSON bootstrap(Noise / confirmation record))
活动 UDP：opaque handle || protected(epoch, record_no) || AEAD body
活动 TCP：directional authenticated length envelope(activity record)
活动 body：record payload length || LIGHT length/padding envelope(frames)
```

所有整数采用网络字节序。UDP 一个数据报最多一个记录，外层 UDP payload 上限 1200 B，不包括 IP/UDP 头。TCP 是独立认证长度 envelope 的顺序字节流。应用 UDP 数据报需要在活动帧内分片，不依赖 IP 分片。

会话 ID、临时逻辑地址、流编号、目标、类别、帧类型和恢复秘密不以明文外部字段发送。公网端点、传输类型、包长、时序和随机句柄阶段性关联仍然可见。

## 2. 准入与 TCP 外部 envelope

bootstrap 与活动 TCP Framer 共用封装函数、使用不同用途标签与密钥：

| 顺序 | 大小 | 含义 |
|---|---|---|
| salt | 32 B | 每份 envelope 独立密码学随机材料 |
| protected length | 20 B | u32 body ciphertext 长度经 ChaCha20-Poly1305 封装，含16B tag；AAD为salt |
| body ciphertext | 可变，最少20 B | u32 payload长度 + payload + 可选随机填充，经AEAD封装并含tag；AAD为前52B |

最小总开销 72 B。先读取并认证固定 52 B 前缀，校验长度后才为主体分配。bootstrap 输入最大 16384 B，客户端 UDP/bootstrap发送仍限制1200 B；body随机填充最多255 B且不突破整体上限。TCP Framer最大内层record 16384 B，outer最大16456 B，无额外随机body填充。

密钥使用 HKDF-SHA256：`info = "bfp-experimental-v0.1/" + purpose`，secret为准入秘密或该方向Noise密钥，salt为随机32B材料；length/body分别使用 `bootstrap/length`、`bootstrap/body` 或 `tcp-frame/length`、`tcp-frame/body`。各派生用途的AEAD nonce为12B零值；其安全前提是随机salt未重复且用途分离。该自有构造仍需专项评审。

网络读取、握手候选与重放缓存有独立限额；读取失败结束TCP承载，不能跳过损坏数据继续解析。UDP无效输入静默丢弃，TCP无效输入没有应用错误响应。

## 3. Bootstrap JSON 与握手

以下 JSON 只存在于已认证的准入 envelope 内。字节数组按Go JSON的Base64表示；短字段名属于当前实验格式。

| 字段 | 类型 | 含义 |
|---|---|---|
| `v` | integer | 当前1 |
| `a` | string | `init`、`reply`、`confirm`、`ready` |
| `m` | string | init的`new`或`resume` |
| `i` | string | 128-bit随机尝试ID的32位hex形式 |
| `g` | uint64 | 恢复预期承载代次；new为0 |
| `t` | string | resume使用的不透明内存ticket |
| `h` | bytes | confirm的16B承载句柄 |
| `n` | bytes | Noise握手消息，或加密confirm/ready记录 |
| `p` | bytes | 无业务语义的初始请求及UDP确认填充 |

首次使用 `Noise_IK_25519_ChaChaPoly_SHA256`，客户端固定服务端静态公钥，服务端检查客户端静态公钥授权。恢复使用 `Noise_NNpsk0_25519_ChaChaPoly_SHA256` 和独立32B resume secret；ticket本身不能授权。Noise prologue为：

```text
bfp/v1/<new|resume>/<udp|tcp>/<attempt_id>/<expected_generation>
```

Noise响应的加密payload为sessionInfo：

| 字段 | 含义 |
|---|---|
| `s` | 随机会话ID |
| `c` / `r` | 客户端/服务端临时逻辑地址 |
| `t` | 不透明ticket |
| `k` | 独立32B恢复秘密 |
| `g` | 承载generation，初始1，接管递增 |
| `h` | 该承载16B随机句柄 |
| `q` | 服务端32B新鲜挑战 |
| `u` | 独立单调 Ticket serial；不等于承载 generation |
| `e` | 当前 Ticket 剩余毫秒，正值且最多 30 天 |
| `l` | 首次创建时固定的最大会话寿命剩余毫秒；恢复不能延长 |

客户端用Noise新方向密钥发送confirm记录，明文JSON为 `{ "q": challenge, "b": channel_binding }`。服务器验证挑战、Noise binding、候选、源端点和授权后提交Session/承载。ready是同一新密钥下加密的字节串`ready`，放在bootstrap的`n`中返回。确认前禁止OPEN、目标拨号和业务写入；当前无业务0-RTT。

初始请求通过内部JSON的`p`字段填充；UDP的confirm也使用该填充，TCP的confirm不增加此字段。当前confirm字段长度固定时，UDP confirm的最小总长度为1121 B，外层随机padding只使用剩余空间，总长度不超过1200 B。当前ready不增加JSON填充，其内层记录为53 B，整体bootstrap长度为209–464 B；因此每次合法UDP confirm，包括重新使用新salt的重试，都足以容纳最大ready。

同一合法重试使用稳定attempt ID、新准入salt和经库允许的消息内容。服务器协调“授权设备+尝试ID”或“Session ID+尝试ID”，Ticket 是有截止的定位符，刷新 alias 不会将同一个恢复操作拆组。UDP与TCP共享已认证bootstrap原始密文的防重放缓存，最多4096条，记录保留约1分钟；在缓存保留期间，相同密文不会获得重复应用响应或分配新候选。缓存到期或服务端重启后，不保证旧INIT完全静默；INIT本身没有可信时间戳，重新封装同一Noise首消息也不属于原始密文去重。即使再次进入候选阶段，也必须完成新的challenge确认才能建立会话或打开目标连接，不能将这项有限窗口防护宣称为永久防重放。

所有UDP bootstrap应答，包括已经验证confirm之后的ready，仍要求应答长度不超过对应输入数据报；confirm填充提供响应预算，没有放宽服务器的防放大限制。ready按候选缓存；已经提交的候选只接受与首次合法CONFIRM完全相同的Message密文重试，空消息或篡改消息不返回缓存READY。不能依赖独立随机padding恰好使未填充的重试请求足够大。严格到期检查同样适用于缓存 INIT、缓存 READY 与 actor 执行 attach 的时刻；没有到期后的 retry-only 例外。

Noise方向split keys从flynn/noise的`CipherState.UnsafeKey()`复制，后续不再使用原CipherState加密活动流量；这是显式库接口选择，不是已审计的通用exporter。恢复需原Session仍在内存并保留出口连接，服务器重启不能据ticket重新拨号冒充旧连接。

## 4. 活动加密记录

| 字段 | 大小 | 说明 |
|---|---|---|
| opaque handle | 16 B | 当前承载随机查找标识；参与AAD |
| protected header | 12 B | epoch:u32 + record_no:u64，经header mask XOR |
| ciphertext | 可变 | AEAD加密 `payload_length:u32 || payload` |
| tag | 16 B | ChaCha20-Poly1305 tag |

不计额外padding时开销48B。`epoch`与`record_no`为nonce的12B内容；AAD为handle与未掩码header。header mask是HMAC-SHA256(header key, ciphertext前16B)的前12B。body/header密钥使用Noise方向master、`handle||epoch` context和用途分离HKDF标签`record/body`、`record/header`。

每方向独立计数，从0开始；同一epoch最多2^32条记录，不能复用key/handle/epoch/record_no。每次重传逻辑帧使用新记录号重新封装。新承载具有新Noise密钥与随机句柄；流偏移不会因切换归零。

接收最多尝试当前和一个前epoch，不根据未验证header无限派生密钥。防重放窗口4096记录，只在AEAD和结构验证成功后更新。前epoch在当前epoch接收4096条记录或调用RetirePrevious后退役；Session另按更新后的有限时间退役。计数与epoch溢出拒绝。

KEY_UPDATE是经过旧epoch认证的逻辑控制。接收方向只接受明确的+1更新，发送方向在相应确认后采用新epoch；旧秘密的HKDF更新不自动提供泄露后安全恢复。TCP额外长度envelope使用独立标签和方向key，内层RecordCipher仍承担防重放。

## 5. LIGHT与内部帧

Record payload先经过LIGHT envelope：`true_length:u16 || frame_bytes || cryptographic_random_padding`。长度与填充全部位于AEAD内部。尽可能按64B桶填充并随机选择额外桶，再均匀增加0到min(63,剩余填充预算)字节的随机桶尾；总开销包括2B长度不超过256B，不突破承载plaintext预算。反馈使用独立的66B总开销上限，单范围PACKET_ACK的实际UDP record由原固定112B变为112–166B，实际字节计入反馈预算。接近上限且没有剩余空间时仍可能没有随机桶尾。纯PACKET_ACK是否有padding不改变它不诱发包确认的语义。该机制减少包长的固定余数特征，不提供时序整形或TLS外观仿真。

解填充后是0–64条完整frame，编码plaintext上限16384B；当前Session通常每记录只发一条frame。每条头28B：

```text
kind:u8 | flags:u8 | data_length:u16 | flow_id:u64 | offset:u64 | value:u64 | data[data_length]
```

`flags`在ResumeState/ResumeDone中为0表示状态消息、为1表示逻辑确认；其他帧没有已冻结的扩展语义。方向通过发送/接收端上下文隐式区分，不在frame内另设direction字段。未知kind、截断头或越界data length导致解析失败；当前不实现草案中的未知可选帧跳过机制。

### 当前消息编号

| 编号 | Kind | 使用字段与语义 |
|---|---|---|
| 1 | PacketAck | offset=record_no，value=被确认方向key epoch；单记录确认，无ranges/delay |
| 2 / 3 | Ping / Pong | value=探测关联值 |
| 4 | Open | flow=流号，data=Target JSON |
| 5 | OpenResult | flow=流号，data=`ok`、`failed`或`limit` |
| 6 | StreamData | flow=流号，offset=该发送方向字节偏移，data=字节块 |
| 7 | StreamAck | flow=流号，offset=连续接收偏移 |
| 8 | MaxFlowData | flow=流号，value=绝对最大接收字节偏移 |
| 9 / 10 | Fin / FinAck | flow=流号，offset=方向最终偏移 |
| 11 / 12 | Reset / ResetAck | flow=流号；终止整条流，当前不编码详细错误 |
| 13 | Datagram | flow=流号，offset=message_id，value高32位=整报长度/低32位=片段偏移，data=片段 |
| 14 | ClassUpdate | flow=流号，value=类别0/1/2；当前无类别版本 |
| 15 | ResumeState | flow=流号，value=承载generation；flags=0时data为恢复快照JSON，flags=1为对应状态确认 |
| 16 | ResumeDone | flow=快照总流数，offset=承载generation；flags=0时value为累计会话接收信用，flags=1为完成确认 |
| 17 / 18 | KeyUpdate / KeyUpdateAck | value=后续key epoch |
| 19 / 20 | SessionClose / SessionCloseAck | 不可逆会话关闭／业务资源已终止的确认；flags、flow、offset、value 均为 0，data 为空。next10 的有界控制语义见文末 |
| 21 | MaxSessionData | value=累计唯一字节绝对信用 |
| 22 | TicketRefresh | 仅服务端→客户端；flags=0、flow=0，value=Ticket serial、offset=权威剩余毫秒，data=32字符hex定位符 |
| 23 | TicketRefreshAck | 仅客户端→服务端；flags=0、flow=0、offset=0、data为空，value=已安装serial；PacketAck不能替代 |

类别编号：0 INTERACTIVE、1 NORMAL、2 BULK。类别更新不能修改原OPEN目标、network、domain、rule_tag或原始提示。类别影响调度，UDP不会因此获得TCP可靠语义，TCP也不会因此允许丢弃业务字节。

服务端先在内存注册新 Ticket，再经已经完成双向同步的活动承载发出刷新；客户端先安装再确认。未确认操作的定位符、serial 和绝对截止固定，UDP/TCP 均作会话级重传。重复同 serial 不能延长客户端本地 monotonic 截止；同 serial 不同 locator 为冲突，旧 serial 不回退凭据。每 Session 至多当前与一份过渡 alias，旧 alias 截止为原 expiry 与首次轮换时刻加 overlap 的较早值。过期 Ticket 不能恢复，健康业务可继续刷新；设备撤销、Session 关闭与服务器重启使相关资格失效。恢复秘密保持 Session 作用域不变。详细规则见[会话凭证生命周期](会话凭证生命周期.md)。

新增 `u/e/l` 为必需字段，22/23 为必需帧。当前 wire 是实验格式，双方应使用同一修订构建；r3 与后续生命周期构建没有跨修订协商，不应混用。

## 6. OPEN与可靠流

Target JSON：`network`必须为`tcp`或`udp`，`address`为host:port，`class`为0–2；可选`domain`与`rule_tag`是适配元数据，不是独立权限凭证。服务器按会话流号登记幂等操作再拨号；相同OPEN返回原结果，改变元数据属于错误。同一Session流号不复用，生命周期OPEN记录有上限。

只有目标socket建立后返回`ok`。网关只解析一次域名，先校验所有解析结果，再固定numeric peer拨号；允许策略和类别互不替代。UDP流也固定一个numeric peer。

可靠流每方向具有独立send/receive偏移、连续ACK、信用和FIN。STREAM_ACK说明字节被连续接收且由当前存活Session保留，可释放发送缓冲；PACKET_ACK用于本承载拥塞/RTT/丢失，不能独自释放跨承载恢复数据。两种确认都不代表目标事务已经执行。

单流信用按最大偏移单调增加；Session信用按累计唯一字节单调增加。重复字节不重复消耗信用。接收消费或RESET丢弃时归还资源/会话信用。旧的普通STREAM_ACK可忽略，不回退进度；恢复快照声明低于已释放进度时视为状态不一致。

FIN只终止一个方向；反方向继续工作。最终偏移不能改变，前序字节与接收消费规则仍需满足。RESET中止整条流并清理排队字节/重组/目标拨号和socket，保留有界终止状态防重复副作用。

## 7. 恢复同步与UDP数据报

同一会话的新承载generation提交后，旧承载业务记录丢弃。每端为本次承载激活建立逐流ResumeState集合；同一Carrier重复activate不追加快照。ResumeState的value必须等于当前generation，flags=1只确认本端实际生成的对应flow状态。当前ResumeState JSON字段：`i`流号、`r`连续接收偏移、`m`单流信用、`o`OPEN结果、可选`f`FIN最终偏移、可选`x`RESET标记。

每端按100ms重试节奏有界入队快照，每轮成功入队最多16项；未得到逐项逻辑确认的状态仍须重试，queue满或PACKET_ACK不能代替逻辑确认。全部本端状态取得确认后才发送ResumeDone：flow为快照总数，offset为当前generation，flags=0时value为累计会话信用。接收端对flow去重，状态集合和声明总数上限均为4096；只有收齐声明数量才设置对端同步完成并发送flags=1的完成确认，重排到来的Done不能越过缺失状态开放业务。

正常业务发送同时要求“对端状态集合完整”和“本端Done取得完成确认”两个门槛；收到完成确认只在本端全部快照已确认后产生进度。达成双方同步后，可靠流从对方连续接收偏移补发本端仍保留的字节。重复状态、逻辑确认和Done维持幂等；同一generation的复杂快照冲突和跨实现规则仍需后续冻结。

无承载或恢复尚未完成时，Session受固定RetainTimeout约束，默认30秒。首次暂停或未完成接入设置计时起点；反复attach、activate、重复READY或新候选握手不会刷新这个起点。只有两个同步门槛均完成才清除此期限；到期关闭Session及其所属流和出口资源，不因控制记录仍在到达而无限续命。

当前简化同步不是完整的分页快照事务或冻结的跨实现恢复规范；FIN恢复、unknown/缺失流、同步结果丢失与部分失败须继续按测试和后续规范完善。恢复不能重新拨号已丢失的目标连接，也不能把业务操作作为恢复payload再次执行。

UDP应用整报上限16KiB，当前分片数据最多900B。message_id按每流每方向单调递增且不复用；相同整报长度必须一致，偏移/片段长度须在界内。完整重组后只交付一次，缺片、冲突、超限或到期整报丢弃。每流重组最多8条，整报从首片起以本机monotonic time计时；message_id去重窗口退役后旧消息不可重新建表。重组内存受会话预算限制。

UDP数据报不做协议级业务重传；承载的PACKET_ACK不改变这个语义。切换时不补发原路径已提交且到达状态未知的旧整报，未完成旧代次重组丢弃。TCP Framer中仍保留整报边界，但TCP可靠性和队头阻塞会改变延迟/丢包表现，不能承诺与UDP承载等效实时性。

## 8. 验证与版本边界

UDP confirm预算回归通过透明中继观察真实的新建与恢复握手，验证最小封装1121 B覆盖ready最大464 B且实际不超过1200 B。该回归和本地Runtime回归在单次握手配置为1秒的条件下连续10轮通过；完整Session包另连续10轮通过。1秒是本地测试配置，生产默认HandshakeTimeout仍为3秒，调用者context可以进一步收紧期限。具体原始记录与最终全包结果见r3验收记录；这些结果不代表所有WAN丢包和时延条件下都能在1秒内完成握手。

当前Go实现的解析、密码、owner和恢复测试属于同实现验证。真正冻结wire前还需给出确定性测试向量、完整错误/状态规则、能力协商、未知字段策略以及独立实现互操作测试。依赖版本、二进制摘要、测试平台和具体结果必须在实现进度/验收记录中关联。

本稿没有SHAPED、COVER、FEC、TLS/HTTPS外观仿真、主动UDP回切或跨进程连接恢复消息编号；不应由草案中的名称推定当前线上存在这些能力。

## 9. next10 的 wire3 会话关闭合同

`SessionClose`（19）和 `SessionCloseAck`（20）使用既有头格式，`Flags/Flow/Offset/Value` 均为零，`Data` 为空。认证后出现非零语义字段属于协议错误，本地直接终止，不产生成功关闭确认。编号和编码未改变，实验 wireVersion 保持 3。

一次 Session 只有一项不可逆终态决定。首次本端关闭或首次合法对端关闭固定原因、起点和绝对截止；后续 API 调用、重复请求、普通帧或 ACK 均不延长它。业务 context 和恢复资格立即失效，登记目标、DNS scope、Flow 缓冲和业务控制表先清理，再允许发送 CloseAck。Close 所在 record 后续普通帧不再产生业务副作用。

只有同一当前认证 carrier 上、canonical 的 CloseAck，且本端已经完整写出自己的 Close，才能确认本端请求；PacketAck、TCP 写成功、尚未完成的写或旧 carrier 消息均不等价。重复 Close 必须用新的认证 record number，密文原样重放仍被原 AEAD/replay 规则拒绝。CloseAck 表示对端已决定业务终态并完成登记业务资源清理，允许其控制 actor 在固定期限内继续回应重复 Close。

默认控制期限 3 秒，并受既有 Session lifetime 与暂停保留期限的较早截止约束。请求最多 5 次写尝试，回应最多 8 次，失败或短写仍消耗次数和字节预算；单份认证 record 保守上界 332 B、每 Session 总计 4316 B，排除 TCP framer 与 TCP/UDP/IP 开销。全部尝试使用 LIGHT 随机填充。普通业务队列、cwnd/pacer、operation table 或恢复同步门槛不阻塞这项独立小预算，也不因此获得额外业务额度。

`Session.Close/Client.Close` 等待共享的首次有界结果；本端资源终止与“对端确认”分别表示。无 carrier、写失败或截止时缺少确认返回 `ErrCloseUnconfirmed`；重复调用返回相同结果。首次决定来自对端时，后续应用 Close 只等待原 responder 收束，不再升级为新请求。双方本端先作出决定时分别处理两向通知/ACK。

完全丢失所有通知时，对端未知关闭意图，仍沿原默认 15 秒 watchdog、30 秒暂停保留期收束；不能由本端 3 秒返回推断远端已经清理。父 context、设备撤销、寿命和服务端关闭可直接中止控制存活。非合作自定义 Backend/Conn 及共享 UDP socket 极端阻塞的实际退出时间仍是验证边界。实现与实际证据见 [next10 实现记录](C:/Users/developer/Desktop/bfp/docs/会话有界关闭实现-r9-next10.md)；旧构建一次性 ACK 与新构建不具有相同丢包保证，跨构建互操作未验收。
