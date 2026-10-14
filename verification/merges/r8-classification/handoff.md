# r8 分类阶段 A：Session 接线交接

状态：staging 源码稳定，本地验证通过，等待 root 只读审查、合并与独立验证。本文不代表 r8 发布验收。

工作目录：`C:\Users\developer\Desktop\bfp\.staging\r8-classification`。

## 范围和基线

本阶段从 v0.1-r7 的 56 个 Go/module 文件冻结基线开始，将已有纯分类器接入实际 Session。本次只改 staging；交接时逐项核对主目录 56 个基线文件，全部 SHA256 一致。

- staging 现有 61 个 Go/module 文件。
- 5 个新文件，8 个修改文件，没有删除。
- `protocol`、`security`、`carrier`、`bootstrap` 与 Go module 没有变化。
- 没有远程测试、部署、发布包，也没有改写 r5/r6/r7 的历史结果。

确切文件清单与旧、新 SHA256 位于 [source-changes.json](/C:/Users/developer/Desktop/bfp/.staging/r8-classification/verification/phase-a/source-changes.json)，完整 61 文件清单位于 [source-manifest.json](/C:/Users/developer/Desktop/bfp/.staging/r8-classification/verification/phase-a/source-manifest.json)。审查或复制必须以这些文件为依据，不能把整个 staging 当作已经验收的发布目录。

## 实现合同

### 本地配置与信任

`ClientConfig.Classification`、`ServerConfig.Classification` 接受 `*classification.Config`。nil 使用 `classification.DefaultConfig()`；显式非 nil 的零值配置保留自身语义，包括 Interactive 默认类与禁用行为观察，不能再套默认值。

NewClient/NewServer 在创建生命周期与监听资源前验证并复制规则，后续只保留不可变编译器；调用者修改原配置不会改变运行时规则。配置错误返回 `classification.ErrConfig`。

Client 与 Session 都提供 `DialClass`、`DialMetadata`。默认 `DialContext` 走规则分类，且不创建可信 Hint。显式 `DialClass` 将 `Target.Class` 作为本地可信 Hint，但仍受本地 `HighestAllowed` 限制。`DialMetadata` 只接受本地适配器/API 的信任声明，并在提交 actor 前复制 Hint；不把这些信任标记发送给对端。规则端口列表也由纯分类器复制。

服务器解析 OPEN 时，客户端的 `Target.Class`、Domain、RuleTag 不会成为可信策略来源。服务器用自身规则确定其发送方向的类别，保存原始 OPEN target 供重复 OPEN 身份比较。结构错误仍按现有 Session 协议错误路径处理。

### 独立发送方向与唯一应用字节

每条生产流持有本地 TX `classification.Flow`。客户端统计其上传，服务器统计其目标出口返回的下载，两端不相互覆盖。

- TCP：实际接纳进 Session chunks 的字节计一次。等待流控、没有接纳的尾部、超时取消不计数；部分提交返回准确的 n。
- UDP：完整分片批次成功接纳后，整包字节计一次，随后推进 messageNext。空包保留消息边界并推进编号，增加字节为 0。
- UDP 的 oversize、deadline、messageNext 耗尽、任意 queue quota 拒绝均不耗编号、不计字节、不留下分片。
- UDP 会话未就绪仍保留旧有 best effort drop 返回行为；虽然 Write 可返回完整长度，被丢弃的包不进入分类统计。
- 记录头、padding、ACK/控制帧、重传、恢复重新排队、桥接重复观察均不计入应用字节。

维护 timer 在 actor 实际执行时采样 classNow，不使用积压 ticker 的旧时间；没有写入时仍 Tick，让窗口过期并按滞回恢复 baseline。锁定类不受行为调整。发生非单调时间错误时取消 Session；正常生产时钟使用 Go time.Now 的单调时间分量。

### 查询与恢复

`Session.FlowClassification(ctx, id)` 与 `Flow.Classification(ctx)` 在 actor 内返回快照副本，不调用 Tick，也不修改观察时间。快照包括 ID、Network、LocalTX、Terminal。

未知 ID 返回 `ErrFlowUnknown`；会话关闭返回 `ErrClosed`；没有 classifier 的合成/拒绝 tombstone 返回 `ErrState`。查询取消返回调用者 context 错误。

carrier attach/recover 保留原 Session、Flow、classifier、baseline、应用字节累计和时间 origin。分类维护在 suspended 状态也会运行，因此恢复后的当前类别可能因真实空闲恢复而改变。测试冻结分类时钟只用于区分恢复替换状态与正常 idle 演变，不能把测试中的类别保持解读为生产暂停分类维护。

### 调度和线端兼容

只有 STREAM_DATA、DATAGRAM 使用本地流类别；OPEN、FIN、credit、RESET、同步与换钥等控制帧保留 Interactive。congestion、pre-sync、record retransmit 三个重新排队分支使用 `classForFrame`，不再把控制帧套用流的数据类别。

已有排队项保留项目类别和同一 flow 的 FIFO。没有调用会整体改写数据与控制项的 ReclassifyFlow。控制类保持 Interactive 不表示它能够越过同 flow 中较早的数据。

阶段 A 不发送新的分类声明，也不相信旧 CLASS_UPDATE 对本地发送策略的修改。legacy CLASS_UPDATE 作为兼容 no-op 消费；OPEN 结构、帧版本和恢复格式没有改变。需要发送者版本化声明时，必须进入阶段 B 并单独协商；本阶段没有偷偷增加未知帧。

`scheduler.PushBatch` 对全局、每 flow、每 class 的 bytes/items 与 flow cardinality 一次性验证；累加成本有溢出检查。拒绝发生于任何 ring、cursor、value 或计数的变动之前。成功提交依赖现有 actor confinement，queue 本身不是并发安全容器。

## 本地验证证据

环境：Go 1.27.0，windows/amd64，CGO_ENABLED=0。

| 检查 | 结果与证据 |
| --- | --- |
| `go test -json ./... -count=1 -timeout 45s` | 退出 0；11 包通过，167 个顶层测试，含 subtest 共 312 个 pass event；无 fail event |
| `go vet ./...` | 退出 0；go-vet.log 无诊断 |
| `go build -o verification/phase-a/bfp-stage-a.exe ./cmd/bfp` | 退出 0；这是 staging 验证构建，不是发布交付 |
| 主目录冻结基线检查 | 56/56 SHA256 与 baseline-manifest.json 一致 |

完整运行日志：[go-test.jsonl](/C:/Users/developer/Desktop/bfp/.staging/r8-classification/verification/phase-a/go-test.jsonl)。机器可读摘要：[local-summary.json](/C:/Users/developer/Desktop/bfp/.staging/r8-classification/verification/phase-a/local-summary.json)。日志中的 pass event 数含嵌套子测试，不等于 312 个独立顶层测试。

新增回归覆盖：

| 入口 | 实际验证 |
| --- | --- |
| `TestClassificationRuntimeLocalRulesHintsAndWireTrust` | 实际 NewServer/NewClient，普通 Dial 走规则，可信 Hint cap，本地 Domain 规则，客户端配置修改不污染编译策略，peer 元数据无信任，真实加密 legacy 更新不改本地类，快照副本，重复 OPEN 不 redial |
| `TestClassificationRuntimeDirectionsAndIdleTick` | TCP 真实上下行独立累计；人为延迟 ticker 时间不能回退 classifier 时间，idle 恢复不加字节 |
| `TestClassificationRuntimeAtomicDatagramAdmission` | 1800 字节分片与空包完整往返；flow/class bytes 与全局/flow/class items 拒绝保留旧项、预算、编号和计数 |
| `TestClassificationRuntimeTCPPartialAdmissionAndDeadline` | 1800 字节 Write 只接纳 900，随后 timeout；仅累计 900，恢复 credit 后补写只增加余下字节 |
| `TestClassificationRuntimeRecoveryPreservesDirectionState` | 初始 UDP，实际 Client recovery 到 TCP；保留 classifier/origin/baseline、待恢复数据只计一次，原目标仅 dial 一次 |
| `TestClassificationRuntimeRealClockIdleRestoreAndLockedHint` | 实际生产 10ms actor timer，无手动 maintain；持续传输变 Bulk，空闲恢复，可信 locked hint 不降级 |
| `TestClassificationInvalidConstructorPolicyPrecedesListen` | occupied TCP listen 地址情况下优先得到 ErrConfig；nil 与显式零配置语义分别验证 |
| `TestClassificationRuntimeInvalidMetadataDoesNotAllocate` | 无效可信域名/tag/hint 不分配 ID、不增加 Opened、不 dial target |
| `TestClassificationRuntimeHintCopiedBeforeQueuedCommand` | channel receive/re-publish 建立 Hint 复制后的 happens-before，调用者修改不影响待执行 owner command |
| `TestClassificationRuntimeDatagramBoundsAndNoAdmissionSideEffects` | 16 KiB 上界实际往返；oversize、expired、max message ID、peerDone=false 的未接纳包不产生统计/队列副作用 |
| 既有 UDP deadline transport 回归 | 真实 carrier Write gate 阻塞 actor 时，超时 UDP 除不耗编号外也不改变 classifier 字节计数 |
| `TestClassificationControlRequeueRetainsPriorityBudgets` | 无 sockets 的串行 state fixture 执行三个实际 requeue 分支，借各 class quota 验证控制预算为 Interactive，并保持 flow FIFO |
| `TestPushBatchRejectsEveryLimitWithoutChangingPendingState` | 所有 quota 拒绝的旧 value/ring/cursor/类别计数一致；invalid cost/class、溢出和 mixed-class FIFO 另测 |

真实 runtime 覆盖使用本机 loopback TCP/UDP 目标、真实安全握手/record 与生产 bridge；类别预算和特定 admission 隔离使用 owner test seams，以免假数据从测试队列发出。此证据不替代 WAN、Linux race、长时间运行或资源压力测试。

## 尚未实现与边界

1. 本阶段尚未做 race 检测，也没有在远程网络执行 r8 验证；由 root 在稳定源码审查后安排独立检查。r7 WAN 历史结果不能继承为 r8 结果。
2. CLI JSON 暂未暴露分类配置字段；当前可经公开 Go Config/API 配置。现有 CLI 使用默认策略。
3. phase B 的版本化发送者分类声明、peer 展示值，以及 phase C 更完整适配器/每设备策略映射仍待后续。本阶段没有自动信任 SOCKS/Clash 传来的域名/tag。
4. 行为分类仅改变调度类别；没有改变 TCP/UDP 交付语义、拥塞/流控或自动选择 FEC。流量混淆与防主动探测沿用冻结基线的既有实现和验证边界。
5. r7 固定 Write deadline snapshot 与提交 guard 保留。动态提前/延后/清零 deadline、等待 writeMu 时可取消，仍不是本阶段的保证。读写同时压力仍可能依赖现有 TCP carrier 写超时释放；没有宣称任意压力下永不阻塞。
6. terminal flow 停止 Tick；被 limit 拒绝且未建立 classifier 的 tombstone 查询为 ErrState。观察器没有增加长期稳定身份。
7. 分类 Tick 遍历当前 stream state，单个行为窗口受纯分类器 2..1024 桶上界限制；尚未做最大流数配置下的 CPU 基准。

root 可按 source-changes.json 的明确文件清单审查、合并；完成独立测试后再决定 r8 的冻结与 WAN 验收。此交接不包含发布授权推断。
