# BFP 会话有界关闭实现与失败门禁记录 — r9-next10

日期：2026-10-09。工作源码：`C:\Users\developer\Desktop\bfp\.staging\r9-next10`。

**next10 已冻结，完整本地 gate 为 FAIL。** 冻结清单为 117 个 Go/module 文件，SHA256 `870e95b74c60358cf3cd594c41d1e0c54c67027aaa7b31bb3bcf7eb411714e60`；运行前后源码一致。Go test exit 1，14 包、193 个顶层测试通过；vet 与 Windows/Linux 构建通过。Session 包 panic 提前结束，三个 gateway 行政终态用例在客户端清理步骤失败。next10 未执行 Linux race 或 WAN，修复放入新的 next11 边界，不修改冻结源码或原始失败结果。`acceptance_complete=false`、`production_ready=false`、`released=false`。

正式结果见 [local-summary.json](C:/Users/developer/Desktop/bfp/.staging/r9-next10/verification/r9-next10/local-gate/local-summary.json)，原始日志见 [go_test.log](C:/Users/developer/Desktop/bfp/.staging/r9-next10/verification/r9-next10/local-gate/go_test.log)。原 summary 的 `failed_tests` 只收集具名 fail 事件，漏掉了导致包提前结束的 panic；[failure-coverage-audit.json](C:/Users/developer/Desktop/bfp/.staging/r9-next10/verification/r9-next10/local-gate/failure-coverage-audit.json) 单独补记，保留原 summary 不变。

本轮两个具体回归是：关闭控制对缺少 cipher 状态的合成 TCP carrier 调用 `RecordCipher.Seal`；旧行政清理 helper 假定 `Client.Close()` 在 1 秒内返回 nil，与新的最多 3 秒远端确认等待及 `ErrCloseUnconfirmed` 合同不一致。三个 gateway 用例的原 DNS 缓存清空和目标 socket 关闭观察已通过，失败发生在客户端 teardown；不能据此把整个测试改判成功，也不能放宽原 1 秒资源观察。

冻结完整套件实际执行并通过默认黑洞与三个新增真实 DNS 关闭场景，为这些场景补充最终源码绑定证据。Session 包由于 panic 没有完成全部新增 Close 测试；前面的局部 19 组通过不等于本次完整 gate 已覆盖。

[最终源码只读审查](C:/Users/developer/Desktop/bfp/.staging/r9-next10/verification/r9-next10/final-close-source-audit.md) 另确认：候选握手 context 取消尚未关闭其 socket I/O；停止 Session 的有界 incoming/commands/backend 引用未完全收束；共用 Server UDP 长时间阻塞写入的严格墙钟退出界未证明。正文中的逻辑门禁、固定尝试和字节预算不能扩大成这三项保证。

本文对应 [会话有界关闭实施方案](C:/Users/developer/Desktop/bfp/docs/会话有界关闭实施方案.md)。next9 的冻结源码、原始失败和先前实网结论继续独立保留。

## 1. 已实现的生命周期

Session 的业务寿命与关闭控制寿命已经分开。`Session.ctx` 继续约束目标拨号、DNS scope、Flow 和恢复；同一父 context 派生的 `controlCtx` 供 actor、认证 reader 和关闭回应使用。`terminating()` 表示不可逆业务终态，`closed()` 仍只表示 `done` 已关闭、控制 actor 已停止。

首次关闭决定通过生命周期写锁发布不可变 `closeIntent.started`，随后立即取消业务 context，并同步调用 once-protected backend scope cleanup。actor 清理登记目标、Flow 等业务状态后，才 publication 关闭确认。控制 actor 可以继续存活至固定截止，为重复的合法 Close 发送有限 ACK；终态不能恢复为 active，也不能取得新的票据或 carrier。

本地应用首先请求关闭时，`localClose=true`；首先收到合法 peer Close 时，`localClose=false`。**首次原因固定，后续应用 `Close()` 不把 peer-first 终态升级成另一项本地主动请求。** 两边均在收到 peer Close 前发布本地意图，才构成同时主动关闭。重复调用不重设起点、deadline 或预算。

关闭清理取消登记 dial、失败并唤醒 Flow、清空其读写缓冲和 datagram/重组状态、关闭登记目标、释放 scheduler、普通 operation/latest-control/classification 表及恢复快照引用，并清除 Session 的恢复凭证引用。代码没有为了发送关闭控制伪造普通 flight、cwnd 或 pacer 可用量。

这表示权限与登记状态失效，不表示 Go 内存已经被取证意义上的覆写，也不能保证任意忽略 context 或永久阻塞 `Close()` 的自定义 Backend、factory cleanup、resolver 或 `net.Conn` 在固定 wall-clock 时间内结束。内置 gateway/net 路径与任意第三方回调必须分别说明；迟到结果只能释放资源，不能填充缓存、登记目标或重新返回业务成功。

## 2. wire3 合同与关闭结果

`wireVersion` 仍为 **3**，既有 Kind 19/20 不变。两种合法关闭帧的语义字段必须为以下 canonical 值：

| 字段 | SessionClose | SessionCloseAck |
|---|---|---|
| Kind | 19 | 20 |
| Flags | 0 | 0 |
| Flow | 0 | 0 |
| Offset | 0 | 0 |
| Value | 0 | 0 |
| Data | 空 | 空 |

畸形但已认证的 Close/Ack 走本地 abort，不能形成成功确认。未认证记录继续由既有 AEAD/准入逻辑拒绝；当前 carrier 与 replay 校验保持。逻辑重试重新 Seal，使用新 record number；同一 ciphertext 的重放不重新清理或生成额外回应。

只有本端主动关闭已经在当前认证 carrier **完整成功写出**，随后收到同一当前 carrier 上合法 CloseAck，才能记录 `localAcked`。enqueue、Seal、短写、PacketAck、Pong 和旧 carrier 的输入均不是该 publication/确认依据。收到合法 Close 后，该 record 的后续普通业务帧受终态门禁约束。

`Session.Close()` 等待共享的 actor 完成，并返回固定最终结果。本地主动请求得到有效 ACK 时返回 nil；无可用 carrier、发送错误或截止前没有有效 ACK时返回 **`ErrCloseUnconfirmed`**。该错误表示本地已经结束，而远端关闭尚未得到本地确认。peer-first 被动关闭没有新本地请求，返回 nil 表示该被动终态已完成，不意味着另一次不存在的请求得到了远端确认。

`Client.Close()` 使用 `sync.Once` 共享首次 Session 结果和 recovery worker join；后续并发或重复调用不能提前返回一个不同的 nil。该 API 结果不能替代远端所有 worker、router tombstone 已消失的证明。

## 3. 固定期限与资源界

| 项目 | 当前实现 |
|---|---|
| `CloseTimeout` 默认值 | 3 秒，独立于业务故障检测和恢复保留期 |
| 有效截止 | 首次起点加 CloseTimeout，再与不可变 Session lifetime、既有 suspended retention 截止取早者 |
| 本地主动请求 | 最多 5 次物理写尝试，包含失败或部分写 |
| peer 回应 | 最多 8 次物理写尝试；重复输入合并到单个 pending 位，回应间隔至少 200ms |
| 请求间隔 | 200ms、400ms、800ms、1000ms 封顶；不因普通 actor tick 重复发送 |
| record 成本 | `HeaderSize 28 + MaxOverhead 256 + RecordOverhead 48 = 332 B` 上界 |
| 每 Session 关闭控制成本 | `(5+8)×332 = 4316 B`，失败 I/O 也先扣预算；不补充预算 |
| TCP write | 既有 2 秒单次界与关闭绝对剩余时间取早者；首次意图收紧已阻塞的私有 TCP write |
| shared UDP socket | 不设置某个 Session 的写 deadline，避免影响其他 Session |

**4316 B 是关闭认证 record 的累计尝试上界，排除 TCP framer、TCP/UDP/IP 及链路层开销。** 它也不包含关闭意图发布前已准入的普通业务记录或 bootstrap 握手成本。ordinary queue、operation table、同步门槛、cwnd/pacer 不负责这项独立控制预算。

父 context 取消、Server 关闭、设备撤销、寿命/既有保留期终止可以直接 abort，不因 ACK drain 延长权限或服务停机。默认 `UDPFailureBudget=15s`、`RetainTimeout=30s` 未增加；原 8 秒恢复业务和 35 秒 WAN 场景期限未重写。较短测试配置只是新场景的显式配置。

所有 Close 请求均被丢弃时，远端尚未知道关闭意图，不能承诺它在本地 3 秒内销毁。所有 ACK 丢弃时，远端已经收到 Close 并清理业务，但本端仍必须返回未确认。两种黑洞边界保持区分。

## 4. 准入门禁与锁顺序审查

| 路径 | 当前门禁与保留规则 |
|---|---|
| Client 当前 Session 复用 | `closed/terminating` 检查；显式 Connect 可以建立全新的 Session，旧流不迁移 |
| recovery sample/allowed | actor 内生命周期读锁与终态检查；每次握手绑定 Session 业务 context 取消 |
| 迟到 establish/attach/merge | 未转移 carrier 关闭；attach 的实际 actor 提交受读锁保护；已转移 carrier reader 保留供控制 drain，终态拒绝 merge/activate |
| live/overlap tickets | use-time 检查立刻拒绝终态，资格失效不等待 maintenance |
| cached INIT/READY | 加入 owner/共享 group Session 终态检查；读锁保护有限缓存提交 |
| 兄弟初始候选 | 即使 `pending.session=nil`，同组已提交 `group.session` 的终态也拒绝候选 |
| snapshot/rotateTicket | actor snapshot 与 rotate commit 使用生命周期读锁；失败 snapshot 返回零值，不导出恢复凭证 |
| DNS/late numeric socket | scope valid guard 使用终态；取消/cleanup once；actor 提交检查终态，迟到 socket 关闭 |
| Flow/Dial/Datagram | `businessCall` 让有限准入提交与首次 intent 串行；终态拒绝新配额与队列提交 |
| 普通接收业务 | Close/Ack 走单独 handler，其他帧有限 actor 提交持读锁并检查终态 |
| maintenance 和旧回调 | 可能完成首次终态前已准入的有限观察/统计变化；enqueue/send 门禁阻止新的业务 publication，不宣称所有字段在 intent 后立刻冻结 |
| UDP router | 已提交且 actor 未 `closed` 的当前认证 route 留至 drain 结束；源地址、carrier 和 AEAD/replay 绑定继续有效 |

Server 的既有锁顺序仍为 `pending.mu → group.mu → authority.gate → Server.mu`。cached INIT 采用 `pending → group → lifecycle read → Server.mu`；cached READY/final READY 采用 `pending → group → authority → lifecycle read → Server.mu`。rotateTicket 采用 `lifecycle read → Server.mu`。Session 首次 intent 的 lifecycle writer 不持 Server.mu，发布后释放 writer，再取消业务和清资源。

**不能在持生命周期读锁时等待 actor.call/attach。** confirm 先完成 actor attach，再为有限本地 READY commit 加读锁；snapshot/merge 的读锁在 actor callback 内取得。Server.mu 不等待 actor/group/pending；candidateValid 的 group Session 要么由调用线程锁定，要么在调用线程持 group 锁等待 actor guard 时保持不变。

maintenance 在 `owner.closed()` 时移除 Session 及其 handles；仅 `terminating()` 不提前移除已提交 UDP responder。终态 pending/group/ticket 恢复索引和 cached reply/ready/handshake/secret 引用在 maintenance 中收束，路由仍保留其 carrier 和 Session ID。停止后的 registry 删除有一秒 maintenance 周期；权限失效已经即时发生，两者不能混为一件事。

审查发现并已核对修复：maintenance 可能先通过初次 guard，再在 rotateTicket 的生命周期门禁输给关闭意图；该 `ErrClosed` 现在直接返回，避免把正常关闭 drain 改成直接 abort。该精确竞争仍缺一个独立定向复现测试。

审查发现并已核对修复：`RevokeDevice` 原来在持 Server.mu/authority.gate 时调用 owner.cancel；next10 cancel 会同步运行 backend scope cleanup，可能让自定义 cleanup 在锁内阻塞或重入 Server。当前源码先在锁内发布 revoked、收集 owner 并删除 locators，解锁后取消全部 owner，再等待 done。新增定向回归以真实授权 Noise 创建 scope，阻塞 actor 后调用实际 RevokeDevice，cleanup 内分别 TryLock 两把锁证明外部行政取消发生在解锁后；断言 cleanup 一次、Revoke等待actor停止、重复撤销不重做cleanup。

## 5. 已读取的局部测试证据

所有下表记录均为本地局部测试；其中测试源码可能继续变化，尚未绑定统一最终 manifest。

| 证据 | 实际结果与范围 |
|---|---|
| [close-admission attempt01](C:/Users/developer/Desktop/bfp/.staging/r9-next10/verification/close-admission/targeted-summary-attempt-01.json) | 3 个顶层 PASS，exit 0，3.17s；4 个 owned 文件运行前后 SHA 相同 |
| [close-admission-revoke attempt01](C:/Users/developer/Desktop/bfp/.staging/r9-next10/verification/close-admission-revoke/targeted-summary-attempt-01.json) | 1 个新增顶层 PASS，exit 0，3.262s；4 个绑定文件运行前后 SHA 相同，验证撤销 cleanup 不持 Server.mu/device.gate并清理一次。不是全源码冻结 gate |
| [close-dns attempt01](C:/Users/developer/Desktop/bfp/.staging/r9-next10/verification/close-dns-attempt-01/summary.json) | exit 1；正常 UDP 的固定 1s 资源观察失败，目标与原缓存尚未终止；TCP及 responder 全丢场景 PASS。原始失败保留 |
| [close-dns attempt02](C:/Users/developer/Desktop/bfp/.staging/r9-next10/verification/close-dns-attempt-02/summary.json) | 3 个顶层 PASS，exit 0，3.78s；真实加密 UDP/TCP→数值 TCP echo，正缓存清空/target exactly-once/旧 cached与uncached hostname拒绝；UDP responder 全丢返回未确认 |
| [close tests attempt01](C:/Users/developer/Desktop/bfp/.staging/r9-next10/verification/close-tests-attempt-01.jsonl) 与 [attempt02](C:/Users/developer/Desktop/bfp/.staging/r9-next10/verification/close-tests-attempt-02.jsonl) | FailedBuild，未当作场景通过；原始输出保留 |
| [close tests attempt03](C:/Users/developer/Desktop/bfp/.staging/r9-next10/verification/close-tests-attempt-03.jsonl) | 14 个顶层 PASS，unassociated ACK 后实际 echo 出现 context deadline FAIL；失败保留。当前注入 helper 已改用普通 UDP publication 路径，避免人工 record hole |
| [close tests attempt05-bound](C:/Users/developer/Desktop/bfp/.staging/r9-next10/verification/close-tests-attempt-05-bound/summary.json) | 15 个顶层、合计 36 个具名 case PASS，exit 0，10.942s，summary 记录 source_unchanged=true；是局部 suite 通过，不是完整验收 |
| [close tests attempt06-supplement](C:/Users/developer/Desktop/bfp/.staging/r9-next10/verification/close-tests-attempt-06-supplement/summary.json) | 4 个新顶层 PASS，exit 0，3.934s，source_unchanged=true；旧carrier ACK、lifetime/retention不延长、无可用carrier、截止前后延迟ACK的局部补充 |
| [default-blackhole attempt01](C:/Users/developer/Desktop/bfp/.staging/r9-next10/verification/close-default-blackhole/targeted-summary-attempt-01.json) | 默认3s/15s/30s真实UDP黑洞生命周期测试程序exit 0、48.571s，**source_unchanged=false，期间ticket.go变化**；程序行为结果与严格源码绑定分开，不能称为最终冻结源码验收 |

close-dns 的新场景显式设置 750ms CloseTimeout，继续使用原 5s business context、1s resource observation。TCP场景只在该 fixture 内将首次 UDP握手 timeout 设为500ms，以验证先尝试 UDP后建立 TCP。没有改变默认 watchdog 或既有 WAN期限。

默认黑洞记录的一个实际起始形态为 flight=0、active 的idle blackout，正常probe随后建立未确认在途记录：约0.800s首次在途；本地默认3s Close返回未确认；约15.800s观察到watchdog suspension，距首次在途约15.000s；约45.800s观察到原DNS缓存/target终止，测得retention约29.9998s。观察间隔100ms，不覆盖其他起始形态或WAN。该程序通过的记录仍保留源码绑定失败，不重复运行来改写原记录。

### 已有具体场景

| 实施矩阵关注点 | 目前对应测试与界限 |
|---|---|
| publication 与错误 ACK | `AckRequiresCompletePublication` 覆盖未 publication ACK、短写计账；`UnassociatedAckDoesNotCloseSession` 用实际 echo 证明仍可业务通信 |
| 份数、字节、截止、record number | `VirtualFloodHasFixedBudgetAndDeadline` 用虚拟时钟覆盖 5请求+8回应、最多4316 record B、重复不续期、到期后不复活；不是 wall-clock/WAN 性能证明 |
| canonical字段 | Close/Ack 的 flags/flow/offset/value/data 逐项畸形，在实际加密 UDP fixture 中 abort；没有对应 TCP逐字段矩阵 |
| 普通预算/同步饱和 | `ReserveBypassesBusinessSaturationAndSync` 联合设置 flight=cwnd、pacer=0、queue填满、operation表满、未同步；未独立填满所有 retry/ledger容量 |
| 首次原因 | `FirstPeerIntentIsNotUpgradedByApplication` 验证后来应用 Close 不生成新请求 |
| 已阻塞 TCP write | `ClampsAlreadyBlockedTCPWrite` 用真实 net.Pipe deadline，150ms测试CloseTimeout；不是任意不合作 Conn 保证 |
| 正常与首次丢失 | UDP/TCP、两端发起正常关闭；UDP/TCP首次Close或ACK丢失，在控制relay中恢复并核对capture |
| 全ACK/全Close丢失 | UDP分别验证已经远端清理与尚未远端清理，固定结果和尝试界；没有TCP全丢矩阵 |
| 同时关闭、重放 | UDP双向本地意图、单向/双向ACK丢失；同ciphertext replay不重复cleanup/ACK |
| 同record后续业务 | 当前覆盖 Close→OPEN→StreamData；无后续目标拨号/OpenResult。未覆盖同record ResumeState/TicketRefresh/ClassUpdate组合 |
| 准入、凭证、恢复身份 | actor阻塞时已发布intent，aliases/cached INIT/READY/兄弟CONFIRM/snapshot/rotation拒绝；并发ClientClose共享；新Connect获得fresh身份 |
| DNS/目标实际联动 | 正常UDP/TCP及UDP所有responder record丢弃时，原DNS缓存与实际TCP target清理一次、旧scope拒绝重新解析/拨号 |
| 旧carrier/无carrier/旧资格截止 | attempt06补充覆盖旧carrier pointer拒绝、相同认证record只在当前carrier接受；缺失/已关闭/不支持carrier无publication；lifetime或既有retention取早、不延长 |
| 延迟ACK | UDP实际capture在截止前注入与停止后注入；对应attempt06，不能替代WAN延迟分布或TCP整套延迟矩阵 |
| 行政撤销cleanup锁顺序 | 新增 `RevokeScopeCleanupOutsideRegistryLocks`，实际Revoke、actor barrier、cleanup TryLock、once与done证明；不包含全部drain/revoke竞争组合 |

## 6. 尚未具备的证据与完成边界

至少以下项不能因上述局部通过而视为完成：

- 已完成冻结 manifest、Windows/Linux build 和完整本地 tests/vet 的绑定；本地 tests 为 FAIL，须在新边界修复后重新建立完整门禁。next10 的独立 Linux race 未运行。
- 原实施方案中的所有关闭矩阵组合，尤其真实Server router在drain内/后、容量/洪泛、多轮fresh Session和registry完整收束；单独最大ledger/retry容量；完整suspended竞争和默认黑洞的不同起始形态。旧carrier ACK/无carrier已有局部补充，不能扩大其scope。
- 关闭与实际TCP establish/attach/activate/merge的各阶段竞争；目前静态门禁及actor-barrier测试不能替代完整现实竞争矩阵。
- 正在查询/忽略取消的resolver、数值dial迟到成功、自定义Backend迟到结果，在graceful-close场景中的完整联合验证；next8/next9相关证据不自动等于next10关闭矩阵。
- revoke/lifetime/Server parent cancellation/retain截止与正在drain竞争的完整验证；RevokeDevice锁内cleanup已修复并有一次独立回归，其余组合不能据此宣布通过。
- 最终冻结源码下的原15s UDPFailureBudget、30s retention默认黑洞绑定，以及有在途/无在途/已suspended等不同起点；已记录的单个真实默认形态程序通过但source_binding失败，短测试配置也不能替代该证据。
- 新加坡发送、洛杉矶接收的关闭诊断WAN。本文没有新加坡负载、实网速率或正式验收结论；后续管理上传继续压缩有界，业务串行，保留慢网约束。

整个BFP还须继续完成稳定原8s内活动UDP→TCP恢复、协议分流WAN收敛/公平性/可靠性与FEC策略、TUN/fake-IP/客户端DNS/IPv6接入和独立安全审查。实现这一项关闭阶段，不把四个大类或全目标改成完成。
