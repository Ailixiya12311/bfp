# BFP 会话资源退役实现 r9-next13

日期：2026-10-09。源码路径：`C:\Users\developer\Desktop\bfp\.staging\r9-next13`。

本阶段从 r9-next12 的 121 文件边界复制，增加 command/incoming 发布门、私有 carrier reader registry、typed dial-result mailbox，以及 backend/DNS scope 的退休时序。父边界证明见 `verification/parent-source-manifest.json`；next13 本地 source manifest 为 125 个 Go/module 文件。

## 实现边界

- `publishGate` 在线程安全的注册点封闭发布；退休先唤醒并等待已登记 publisher，再排空 command/incoming，数据 channel 保持打开，避免迟到 sender 触发 send-on-closed。
- `readerRegistry` 在启动 Read 前登记私有 carrier；退休封闭注册、关闭已登记 carrier、等待 reader 退出，并明确不拥有 Server 的共享 UDP socket。自定义不合作 Conn 仍不具有强制终止保证。
- `dialResultMailbox` 以有界队列保存拨号结果；worker 不捕获 Session/Flow/streamState。退休关闭尚未接管的 Conn，取消后即使 backend 仍返回 Conn 也由 worker 关闭；actor 只有 token、生命周期、授权均匹配时才接管目标连接。
- `backendLifetime` 只保存不可变 context/lifetime/authority 和 terminal 位。首次 close intent 与直接 cancel 都先发布 terminal；watcher 的 stop 结果与 callback 完成分别等待。遵守接口契约的 cleanup 必须同步失效本地 scope，不能等待网络操作。
- `Stats` 遇到 control context 已停止而 actor 尚未关闭 `done` 时等待最终 owner 快照，避免把中间零值暴露给调用方。

## 验证

正式本地 gate：16 个包、404 个顶层测试、vet、Windows/Linux 构建均通过；完整日志和清单在 `verification/r9-next13/local-gate/`。本次 local gate 的 `local_checks_pass=true`，但按总验收合同仍保持 `acceptance_complete=false`。

洛杉矶独立 Linux race：run `09a74805d9f86838c7a6b141dc26eded`，Go 1.27.0/GCC 12.2，16 个测试包 exit 0，无 DATA RACE 报告，owned 容器/目录清理，receiver 前后稳定快照比较通过。关联 source manifest 和 Linux 二进制哈希与本地 gate 相同。证据见 `.staging/r9-next13/verification/r9-next13/evidence-index.json` 与 `lab/runs/09a74805d9f86838c7a6b141dc26eded/race-result.json`。

首次 race 尝试在测试完成后的 SSH 收尾快照阶段遇到 `SSH session not active`；远端 owned 容器和目录随后经只读检查确认已清理。该失败没有覆盖或改写，第二次使用新连接完成。两次尝试均没有新加坡上传、业务 WAN 或协议发布操作。

## 未完成项

本阶段只收口会话资源引用和关闭时序，不能把它等同于四大类整体完成。共享 Server UDP 长时间阻塞的严格墙钟边界、完整 close/recovery/READY 故障矩阵、原 8 秒 UDP 恢复稳定性、分类 WAN/公平性/可靠性/FEC、客户端 DNS/fake-IP/TUN/IPv6 及独立安全评审仍待完成。对任意永久阻塞的外部 cleanup 或自定义 Conn，不宣称 CloseTimeout 可强制终止。四类状态继续为 2 类主体实现、2 类部分实现、0 类最终验收；不制作发布 ZIP。
