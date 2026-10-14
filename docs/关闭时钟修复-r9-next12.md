# BFP 关闭时钟修复 r9-next12

日期：2026-10-09。源码路径：`C:\Users\developer\Desktop\bfp\.staging\r9-next12`。

本阶段从 next11 冻结的 120 个 Go/module 文件复制，逐项哈希一致，见 [父源码证明](C:/Users/developer/Desktop/bfp/.staging/r9-next12/verification/parent-source-manifest.json)。next11 的 240 秒完整命令超时、180 秒 Session 诊断超时及全部原始失败保留，不修改父源码。

## 具体问题和修复

纯 Session 的旧传输诊断用例冻结 `transportNow` 于 1970 年，以测量 50ms 阻塞 episode；关闭起点却通过 `time.Now()` 获取现实时间。next10 开始加入优雅 Close/ACK drain 后，actor 用该冻结传输时钟检查现实关闭截止，没有 ACK 也无法到期。next10 的更早 nil Seal panic 中止包运行，未在其完整运行中执行到这一问题；next11 的逐行诊断取得了等待 Close 的 stack。

next12 给关闭路径使用独立 `closeTime()`，生产默认 `time.Now()` 保有 Go 单调时间成分。首次 Close、peer Close/Ack、actor wake、flush、maintain 的关闭截止与重试采用同一关闭时钟。传输诊断 episode 清理继续用 `transportTime()`，原 50ms 断言不变。只有没有 actor 的纯 owner 状态转移 fixture 在开始前显式注入独立的虚拟 `closeNow`，继续证明固定次数、字节、截止和旧资格不延长。所有原 5/8/35 秒业务、1 秒资源与 180/240 秒 test/helper deadline 保持不变。

## 验证范围

实际 actor/认证 UDP 无 ACK 时钟回归已通过：冻结过去/跳到未来、无资格截止/未来 lifetime 与 retention 四子场景均约 150.16–150.59ms 返回未确认，实际接收并解密 canonical Close。原虚拟诊断四动作通过，默认关闭场在 3 秒结束，原 50ms episode 断言不变。19 组既有有界关闭测试通过。

新增双端 ACK 测试的首轮 UDP 子场失败：将已工作的 UDP transport clock 回退到 1970，第一条 Close 仍先经过普通 UDP history，因负时间被既有 ErrTime 校验拒绝。这个 fixture 同时施加了非法业务时间输入，不能用它要求生产 history 放行。原 [attempt01](C:/Users/developer/Desktop/bfp/.staging/r9-next12/verification/close-clock-attempt01/summary.json) 为 22 顶层运行、21 通过、1 失败，保留不变。只把该新增 ACK fixture 改为在各 actor 内冻结当前合法 transportTime 后，仅重测修改的一组，UDP/TCP 均通过，见 [attempt02](C:/Users/developer/Desktop/bfp/.staging/r9-next12/verification/close-clock-attempt02/summary.json)。无 ACK 四子场保持过去/未来注入；没有修改生产 receive 或原 diagnostic 用例，没有扩大期限。

源码停止写入后的一次统一冻结完整本地 gate 已通过：121 个 Go/module 文件，manifest SHA256 `a8523fb46443375cc5bc00a8f211f4f92b364bfff035dc91a62880d92de47634`，16 个包、399 个顶层测试 PASS，原始日志没有 panic、失败包或缺少终态的测试事件。vet 和 Windows/Linux 构建通过，全源码运行前后哈希一致，耗时 175.253 秒，原 180 秒 Go / 240 秒 helper 期限没有增加。见 [local-summary.json](C:/Users/developer/Desktop/bfp/.staging/r9-next12/verification/r9-next12/local-gate/local-summary.json)。Linux 二进制 SHA256 为 `292567748129c4305ca9c2ef366e085609030911106f2b314a0ce14ac1fde844`，Windows 为 `c438d0a37bbbdcd342491c2d4bf3b55a72644584eebc7e7e8c31f3facd7f9db6`。新的完整 helper 直接写入原始日志文件，在超时中仍保存已取得的输出。

源清单绑定的独立 Linux race 在洛杉矶完成并通过，run `88bdb7339f7f6593cdd99d3e9269e98c`：Go 1.27.0、GCC 12.2、16 测试包 PASS，程序 exit 0，无 DATA RACE 报告；owned 容器/目录删除，原严格前后快照比较 unchanged=true，298.967 秒。实际上传测试的 121 个源码哈希与本地冻结清单相同，关联 Linux 二进制 SHA256 一致，race 后源码无变化。见 [race-result.json](C:/Users/developer/Desktop/bfp/.staging/r9-next12/lab/runs/88bdb7339f7f6593cdd99d3e9269e98c/race-result.json) 和 [最终证据索引](C:/Users/developer/Desktop/bfp/.staging/r9-next12/verification/r9-next12/evidence-index.json)。快照证明限于前后采样；额外 Xray 端点身份指纹不证明运行期间身份连续，配置指纹 unavailable 也不能写成配置身份已核验。

没有新加坡管理上传或 WAN 业务场景。本地 summary 保留其运行时 race=not_run 和总 pass=false 的原记录，后续 race 状态只追加到证据索引；全目标验收仍未完成，不能将本地/race 通过提升为生产发布。

完整关闭矩阵、最终队列/backend/reader 引用收束、共享 Server UDP 长时间阻塞墙钟界、READY 与终态的时序组合仍未完成。整个 BFP 继续保持 2 类主体实现、2 类部分实现、0 类最终验收；`acceptance_complete=false`、`production_ready=false`、`released=false`，没有发布 ZIP。
