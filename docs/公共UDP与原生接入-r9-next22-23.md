# 公共 UDP 与真实原生接入：r9-next22 / next23

日期：2026-10-09。主目录仍是历史 r8；本文描述独立开发目录和两个真实上游 fork，不改变既有失败结论。新加坡链路较慢，本阶段未新增上传或 WAN 业务测试。

## 候选与证据

next21 已完成相同 181 个 Go/module 文件的本地 18 包、578 顶层测试、vet、Windows/Linux 构建、有限 repair-parser fuzz 和洛杉矶 Linux race。对应统一索引位于 `.staging/r9-next21/verification/r9-next21/evidence-index.json`。原 next21 attempt01、next20 attempt02、next19 WAN 严格失败保留。

next22 从 next21 attempt02 的精确源码建立，并加入公开 `clientconfig` 和冻结的 `adapter/packet`、公共 Session/Flow 生命周期 API。192 个 Go/module 文件的完整本地检查通过：20 包、608 顶层测试，vet 和 Windows/Linux 构建通过，源码未变，238.998 秒。记录位于 `.staging/r9-next22/verification/r9-next22/local-gate-attempt01/local-summary.json`。next22 尚未执行自己的 Linux race、fuzz 或 WAN，不能继承 next21 的通过结论。

next23 在独立目录保留 next22 父源码，并增加精确目标的本地 metadata hook。三项定向测试通过；完整本地检查已通过，摘要记录 20 包、611 顶层测试、vet 和 Windows/Linux 构建，源码未变，但摘要的总 `pass=false` 仍表示独立 race/WAN 未运行。next22 的验证对象保持不变。

## 公共 PacketConn

`packet.New(ctx, owner, config)` 固定一个 Session；后续目标通过该 owner 开流，不保存 Client，不暗中新建 Session。`packet.Connect` 只选择一次 Session。支持真实多目标 `WriteTo/ReadFrom`、空数据报、16 KiB 上限、首次同目标并发拨号去重、限额、idle、deadline、取消和 Close。默认最多 16 个目标、32 个 pending writes、64 条 receive queue、2 MiB adapter-owned buffers。

`Session.BusinessDone()` 表示业务停止，`Session.Done()` 表示最终 actor 清理完成。`Flow.CloseContext` 提供可取消的 reset 准入；`WriteDatagramContext` 直接取消 gate、recovery 和排队准入，没有另起后台 Write。成功准入仍不代表远端 UDP 送达。

公共分支的最终联合定向记录为 packet 16 顶层、7 子测试，公共 lifecycle 6 顶层、10 子测试。源码及第一轮失败保存于 `.staging/r9-next22-packet/verification`；精确合并记录为 next22 的 `verification/merge/packet-public-additions.json`。

## next23 按目标 metadata

`Config.MetadataForTarget(ctx, address, base)` 是受控本地适配接口。它只在某个具体目标 Flow 首次拨号时运行，使用该目标的 owned dial worker，不持 adapter mutex。默认仍按每个实际目标派生 Domain；宿主可为数值目标附加恢复的域名作为本地分类信息。回调不得改变 Network 或 Address，取消后不拨号；optional policy pointers 在输入输出边界复制。

真实定向测试验证了首个数值目标的可信域名仅影响该目标分类，第二个目标仍走默认类别，回包来源和实际 socket 目标不变；改变 Network/Address 被拒绝且零 backend dial；合作回调在 adapter Close 时收到取消并完成 owned join。回调必须遵守 context，不宣称任意不合作扩展函数都能强行停止。

## 原生 fork

真实上游源码已按固定提交下载和检查：Mihomo `88dcbf7f1614a67c3b36b848ee3592dfa92ada36`，sing-box `af6e64c3b69e6132ebaee0e1a3d24e93903f6709`。完整源码、archive hashes 和清单位于 `integrations/*/upstream-source`，开发 checkout 位于 `.staging/native-upstream`。

两个 fork 均已有 BFP 原生注册、配置和连接包装代码。构造读取受保护的凭据文件并验证，不自动连接。实例共享 Client，物理 UDP/TCP 通过宿主 dialer；UDP source 转换、TCP logical RemoteAddr、connected packet 和半关闭按真实接口处理。sing-box 最终切片已绑定 next23 的 194 个依赖文件并通过 10 个顶层、2 个子测试、vet、Windows amd64 CLI build 和配置 check；完整上游/TUN/WAN 仍未验收。Mihomo native-attempt04 已绑定 next23 源码并通过 8 个顶层 BFP 测试、vet 及 Windows/Linux amd64 CLI build；该结果仍只是原生切片门禁，不代表 TUN、系统 DNS/IPv6、路由排除、race 或 WAN 已通过。

直接调用 outbound 的测试不足以证明真实宿主入口。Mihomo 的 `Metadata.Pure()` 和数值 UDP 发送路径会丢域名，现正增加可选逻辑 UDP metadata/source 接口，保持普通 tracker 的载荷 I/O；sing-box 通用 PacketConn 转换也会丢域名，现正实现其原生 packet buffer 接口并验证 ConnectionManager。每个运行结果必须绑定当时 fork 与 BFP 源码，较早通过不覆盖后续修改。

Mihomo 首次本地完整 package graph 编译达到 240 秒外层预算，记录为未通过；native-attempt02 的 bootstrap fixture 误用 Resolver `Invalid()` 语义并触发测试 range copylock，原始失败日志和源快照保留。native-attempt04 修正 fixture 选择和测试值语义后通过了原生切片门禁，结果位于 `integrations/mihomo/results/native-attempt04`。sing-box 最终 next23 依赖的真实 protocol/include 测试、vet、Windows build 和 CLI check 已通过；其证据明确不覆盖 Linux race、TUN、路由排除、WAN、域名/scoped IPv6 server endpoint 或完整上游测试模块。

## 未完成范围

完整原生 CLI/support matrix、系统 DNS/TUN/IPv6/路由排除、默认和发布 build tags、独立 Linux race、完整故障矩阵、混合分类/FEC 性能、长期资源、安全评审、互操作仍有工作。Mihomo 的逻辑 UDP metadata 映射目前按 owner 限额并采用约一分钟的外层闲置清理；它与 packet.Conn 内部 target 的逐目标退休没有 generation 级绑定，且宿主先 Prepare 后 WriteTo 的取消路径可能留下短时 provisional 映射，这些是下一阶段需要补的事务和生命周期接口，不能宣称已严格解决。`Session.DialMetadata` 的继承清理路径在 actor 永久阻塞且 command queue 满时可能继续等待；已准入 reset 的不合作底层 Close 也不受强制抢占。当前未把这些边界描述为已修复。

本阶段没有新增新加坡上传或 WAN。最近 WAN 仍是 next19：运行中切换 TCP 12/12、UDP 11/12，整轮严格 FAIL。四类数量保持 2 核心、2 部分、0 最终验收；`acceptance_complete=false`、`production_ready=false`、`released=false`。

