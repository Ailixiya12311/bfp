# BFP 关闭回归修复 r9-next11

日期：2026-10-09。工作源码：`C:\Users\developer\Desktop\bfp\.staging\r9-next11`。

**冻结门禁未完成，状态 FAIL。** 120 个 Go/module 文件，manifest SHA256 `b85e96e9d2bdf9c33dcf1b83a72925f72ad7669983fc306d312a2abd12a50a2f`。完整 test 命令在原 240 秒父 helper 预算内未返回；原 capture_output helper 未保存异常中的 partial stdout，原 [local-summary.json](C:/Users/developer/Desktop/bfp/.staging/r9-next11/verification/r9-next11/local-gate/local-summary.json) 的 checks 为空。此证据缺口由 [timeout-audit.json](C:/Users/developer/Desktop/bfp/.staging/r9-next11/verification/r9-next11/local-gate/timeout-audit.json) 单独说明，没有重写原结果。之后只补执行原先未启动的 vet 与双平台构建，均通过且全源码哈希未变，见 [post-timeout-checks](C:/Users/developer/Desktop/bfp/.staging/r9-next11/verification/r9-next11/post-timeout-checks/summary.json)。未启动该版本 race 或 WAN。

一次单独的 Session 包逐行日志诊断在原 180 秒 Go timeout 下失败，188 个顶层先通过；stack 证明 `TestTransportDiagnosticsActorAttachSuspendAndCloseEndOldEpisode/close` 在 `Session.Close` 等待 actor done，而 actor 持续执行，见 [诊断 summary](C:/Users/developer/Desktop/bfp/.staging/r9-next11/verification/session-timeout-diagnostic-attempt-01/summary.json) 和 [完整日志](C:/Users/developer/Desktop/bfp/.staging/r9-next11/verification/session-timeout-diagnostic-attempt-01/go-test.jsonl)。测试的冻结 1970 年传输时钟被关闭 tick 使用，但关闭起点来自现实时间，因此无法到达截止；这个纯 Session 路径不经过新增 Client owners。诊断没有扩大超时，不作为验收重跑。下一边界 next12 分离关闭单调时钟与传输诊断时钟，保持原测试观察及业务 deadline。

本阶段从 next10 冻结的 117 个 Go/module 文件复制，各文件 SHA256 全部一致，证明见 [parent-source-manifest.json](C:/Users/developer/Desktop/bfp/.staging/r9-next11/verification/parent-source-manifest.json)。next10 完整本地 FAIL、panic、三个旧行政清理失败及原始日志全部保留；不修改父版本冻结源码。

## 修复范围

1. 关闭控制在 Seal 前要求当前 carrier 的双向 cipher 及实际发送分支完整。缺少 TX/RX、TCP conn/framer、UDP socket 或共享 UDP peer 时，立即完成本地清理并返回未确认，不分配物理尝试、不发布关闭记录。检查遵循 `writeUntil` 选择共享 UDP 优先于私有 conn 的顺序。这个门禁没有新增服务器 READY 完整写出证明。
2. 新增 `Client.Abort() error`，用于行政销毁本地网络与等待退出。取消建连、恢复和所有仍存活的 Session，等待 actor 与恢复 worker；不发送新的优雅关闭请求，nil 只表示本地 join。它可并发、重复调用，也可中断 `Close`，而 `Close` 继续保留自己的真实确认结果，包括 `ErrCloseUnconfirmed`。
3. Client 追踪被 fresh Session 替换但尚在关闭 drain 的旧 owner；恢复 worker 等其 actor done 后才移除所有权并结束。避免只清 current 而遗漏旧网络。
4. `establish` 在 DialContext 成功后用取消 watcher 关闭仍由握手拥有的私有 socket；每次 INIT/CONFIRM 与 UDP 重试前检查 context。返回成功 carrier 前停止并 join 取消回调、复查 context，避免误关已移交的 socket。
5. 三个旧 gateway 行政终态测试使用明确的本地 Abort 清理；原 5 秒业务、1 秒资源观察和 1 秒 teardown 期限不变。没有把 `ErrCloseUnconfirmed` 转成 nil，也没有改变正常 Close 的远端确认合同。

## 定向证据

| 记录 | 范围和结果 |
|---|---|
| [close-carrier attempt01](C:/Users/developer/Desktop/bfp/.staging/r9-next11/verification/close-carrier-attempt-01/summary.json) | 4 顶层 PASS、source_unchanged=true。后续源级审查指出混合 UDP 字段检查须遵循实际发送分支；原记录保留 |
| [close-carrier attempt02](C:/Users/developer/Desktop/bfp/.staging/r9-next11/verification/close-carrier-attempt-02/summary.json) | 4 顶层 PASS、source_unchanged=true；包括父版本 panic 的原测试与共享 UDP 缺少 peer/私有 conn 非空组合 |
| [bootstrap cancellation](C:/Users/developer/Desktop/bfp/.staging/r9-next11/verification/bootstrap-cancel-attempt-01/summary.json) | 3 顶层 PASS、分配文件哈希不变；TCP INIT/READY 阻塞实际 EOF、UDP 已重试后取消无后续包、成功 UDP/TCP 移交后取消不关闭 carrier |
| [Client Abort / gateway](C:/Users/developer/Desktop/bfp/.staging/r9-next11/verification/client-abort-attempt-01/summary.json) | 6 顶层 PASS、source_unchanged=true；fresh 替换旧 drain 全 actor join、12 并发 Abort 中断丢 ACK Close且保留未确认、pending Connect 取消、旧 3 行政终态清理 |

以上是本地定向证据，完整冻结 gate 的实际结果另记，不能把有限测试累计数作为总体验收比例。

## 尚未完成的边界

停止 Session 的 incoming/commands 缓冲、backend 与其他闭包引用尚未全部统一收束；不能把清 current.keys 描述为完全销毁所有密钥对象或 Go 内存零化。共享 Server UDP 长时间阻塞写入的严格墙钟退出界尚未证明，不能安装一个 Session 的 socket deadline 影响其他 Session。完整 READY/attach/关闭的时序矩阵仍待做。

原 8 秒内活动 UDP→TCP 恢复稳定性、分类专项 WAN 收敛和公平性、分类可靠性/纠错与 FEC、客户端 DNS/fake-IP/TUN/IPv6、长期资源/故障矩阵及独立安全评审仍是全目标未完成项。四类计数保持 2 类主体实现、2 类部分实现、0 类最终验收；`acceptance_complete=false`、`production_ready=false`、`released=false`，不制作发布 ZIP。
