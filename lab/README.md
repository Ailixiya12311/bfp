# 双机 WAN 原型验收工具

当前交付构建：**v0.1-r3**，Linux 文件 `bin/bfp-v0.1-r3-linux-amd64`，现场 SHA256 `f3cc45b6818bfc5c91c9bd8c36a28093ef3d92f2f7468ecdf4423abc94b89f5c`。最终源码 race 与 WAN 证据见本文末尾 r3 节；全部 run-owned 远端进程、容器、临时配置和目录均已清理。

这些工具只使用用户指定的两台测试机：新加坡 `198.51.100.20:22` 发送，洛杉矶 `192.0.2.10:22` 接收/出口。SSH 凭据只从原清单匹配的当前行读取；不输出密码、完整行或其他服务器信息。

`remote.py` 加载既有 `known_hosts`，使用 Paramiko `RejectPolicy`。缺失或不匹配的 pin 必须停止，不能自动信任首次连接。未认证指纹发现函数只返回指纹，不保存信任。

运行 Python 需要 Paramiko 和 cryptography。执行命令：

```powershell
python -m unittest discover -s lab -p 'test_*.py' -v
python lab/remote.py prepare
python lab/selfcheck_remote.py
python lab/wan.py --binary C:\Users\developer\Desktop\bfp\bin\bfp-v0.1-r3-linux-amd64
python lab/race.py --binary-sha256 <现场64位SHA256>
```

`prepare` 并行只读检查 OS、CPU、内存、监听、容器、默认路由和防火墙结构。`selfcheck_remote` 创建自己的目录/配置，启动本目录中的 sleep 测试进程，验证归属和精确清理。`wan` 保存本次 ELF 输入副本和 SHA256，上传同一构建，执行正常 UDP、运行中 UDP 黑洞后 TCP 接管、首次 UDP 黑洞后 TCP 接入及随机无认证输入测试。

远端每次使用新随机 runID 的 `/tmp/bfp-lab-<32位十六进制>`，目录 `0700`，测试配置与日志 `0600`，二进制 `0700`。清理只接受自己的 owner 标记，并检查 PID、Linux starttime、命令摘要、可执行文件路径与进程组。任何归属不符都拒绝发信号和删除目录。工具不修改已有服务、路由、防火墙或容器，不自动安装，不重启，不执行 prune。

`lab/runs/<runID>/` 保存脱敏结果、场景证据和前后快照。`wan-result.json` 的 PASS 要求三场结果、Session/目标连接保留、预期承载、无认证探测无应用响应、临时进程与目录清理，以及两台现有服务/路由/防火墙配置一致。协议探测和故障都来自本次创建的进程；不需要修改防火墙。

短测试证明所记录构建和样本的行为，不能证明独立安全审计、所有流量不可识别、长期稳定性或生产性能。当前 probe 的业务样本为单 TCP 长流和一个 UDP association；全局 TUN、Mihomo/sing-box 原生接入及多类公平性需要其他验收。

当前修正版为 `bin/bfp-v0.1-r2-linux-amd64`，Linux SHA-256 `04642601b0bd7ef87cf01bd08179bfbbaff628e2f82b793960f41c0877787de6`。重跑时传该文件的完整路径；旧构建的记录只作历史对照。

`race.py --binary-sha256 <SHA>` 将当前全部 Go 源码与依赖文件复制到新 run 后离线 vendor，随后在洛杉矶已有容器镜像中隔离执行 Linux 竞态测试。只处理本次容器和目录，禁止 pull/网络与全局安装；资源、磁盘和总期限受限。`runs/ee5fb85252c44d3803a03b9319c4b120/race-result.json` 已记录 r2 对应源码的全部 10 包 PASS，以及容器/目录删除和 baseline 一致。较早漏 `internal` 的 runner 失败尝试单独保留，不混作通过。

## 2026-10-07 已执行证据

`runs/a376324849d11ae11a80081904f2c492/wan-result.json`：两机相同 SHA256 `5751f6a578cd4ae92cdf0e8455a42ffa48bc53491b126f3987193967d53bcf80`，三场各完成 TCP 50 次 × 16 KiB、UDP 50 次。

| 场景 | 承载结果 | TCP 目标连接新增 | 业务测试时间 | 最大单次 TCP 操作 |
|---|---|---:|---:|---:|
| 正常 UDP | UDP generation 1，0 次切换 | 1 | 33.194 s | 1.158 s |
| 8 s 后 UDP 黑洞 | UDP generation 1 → TCP generation 2，1 次切换，同一 Session | 1 | 32.633 s | 4.062 s |
| 首次 UDP 黑洞 | 首次 TCP generation 1，0 次运行中切换 | 1 | 26.840 s | 0.805 s |

最大操作时间包含整次业务读写，不能解释为纯切换耗时。探测样本为 16 个随机 UDP 数据报与 8 条随机/空 TCP 连接，应用响应均为 0 字节，目标连接计数保持 3。全部 run-owned 远端进程与目录已清理，现有监听、容器和网络配置摘要前后一致。

## r2 独立证据与失败保留

r2 ELF 的现场 SHA256 为 `04642601b0bd7ef87cf01bd08179bfbbaff628e2f82b793960f41c0877787de6`。原始首版 WAN 不作为 r2 证据。

- `runs/ee5fb85252c44d3803a03b9319c4b120/race-result.json`：完整冻结源码在 LA 已缓存 Go 1.27 / GCC 12.2 镜像中离线执行 `go test -race -p 1 ./... -count=1`，10 包通过，container 与目录已清理，baseline 一致。独立 source manifest 包含 42 个源文件/模块文件。原传入关联摘要误写为 65 位，原报告未覆盖；同目录 `lineage-correction.json` 记录正确现场 ELF 摘要及冻结源码与当前源码逐项一致。race 证明源码测试，不证明错误输入摘要对应某个二进制。工具现已拒绝非 64 位关联摘要。
- `runs/252268aa723dd16798e5fa531b8ca476/wan-result.json`：严格总体 **FAIL**。正常 UDP 与首次 UDP 黑洞后 TCP 接入均 TCP/UDP 50/50。运行中切换 TCP 50/50、同一 Session、UDP generation 1 → TCP generation 2、目标 TCP 仅 1 条；但 UDP 49/50，1 次失败，零丢包门槛未满足。无认证输入样本和精确清理通过，两台 baseline 一致。
- 同目录 `udp-failure-analysis.json`：客户端 iteration 10 仍为 UDP generation 1、重传 84；iteration 11 首次记录 TCP generation 2、重传 147，之后稳定。原进度日志缺少逐次 UDP 结果和消息时间，无法确定那 1 次 UDP 失败属于哪个 iteration，或判定发生在黑洞期间还是 TCP 恢复后。`dropped=0` 是本地计数，不能代表网络/relay 未丢包。

工具保留了两次无效/失败准备尝试：`eef859839c5348b4c07ae0b2033d6f22` 的初次 race 源码包遗漏 internal，build 失败后清理；`762c383f14d5eebdfb3940b17b03900e` 的 WAN 因 SSH 上传中断，未启动协议进程，`cleanup-recovery.json` 记录新连接精确清理完成。后续修复 runner 使用新 runID，原失败报告未覆盖。

上述 r2 结果不能替代后续资源修复构建的验证。每次 Go 源码或二进制改变都应建立新冻结源码/race 证据和新 WAN 证据；既有 FAIL 也不通过重复随机运行或改变门槛转为 PASS。

## r3 最终独立证据

最终 r3 ELF 现场 SHA256 为 `f3cc45b6818bfc5c91c9bd8c36a28093ef3d92f2f7468ecdf4423abc94b89f5c`。

- `runs/9989f863f0b40b8df655b90c1972c6bd/race-result.json`：完整冻结源码的 10 包 Linux race 均通过、进程 exit 0、owned container/目录精确清理成功。原始工具整体 `pass=false` 是洛杉矶现有代理动态 UDP socket 逐项相等检查未通过；它保留原样。`supplemental-baseline-review.json` 记录固定 TCP/其他 UDP、容器、默认路由与防火墙一致，当前动态 socket 属于既有 Xray PID 17883，含 starttime/exe/命令摘要；race 未保存原 pre/post owner，因此旧已消失端点归属无法完全回溯。
- `runs/24520198604416ae92286739b849494f/wan-result.json`：两机上传同一 r3 ELF。正常 UDP、运行中 UDP→TCP、首次 UDP 黑洞→TCP 三个协议场景均 `pass=true`，每场 TCP 50/50 × 16 KiB、UDP 50/50、UDP failed 0。随机输入样本与精确清理通过。工具整体原始 `pass=false` 仅因洛杉矶 Xray 动态 UDP socket 减少；原始结果保留不改。
- WAN 同目录 `supplemental-baseline-review.json` 依据完整保存的前后 `ss` owner 记录，逐一证明 5 个消失的公网 UDP 高端口均属于既有 Xray PID 17883；没有新增未知 listener，固定 TCP/UDP、容器、路由与防火墙一致，新加坡全部 socket 基线一致。补充审查通过，不能将原始逐项 gate 写成 `true`。

| r3 场景 | 业务测试时间 | 最大单次 TCP 操作 | 承载与会话结果 |
|---|---:|---:|---|
| 正常 UDP | 26.538 s | 0.557 s | UDP generation 1，same Session，目标 TCP 1 条 |
| 运行中 UDP 黑洞 | 34.404 s | 4.360 s | 原 Session UDP generation 1 → TCP generation 2，目标 TCP 1 条 |
| 首次 UDP 黑洞 | 30.288 s | 0.888 s | 首次 TCP generation 1，目标 TCP 1 条 |

r3 的逐操作 UDP 遥测完整，运行中切换场没有失败样本；同目录 `udp-failure-analysis.json` 保留观测。一个新样本完成 50/50 不会撤销 r2 49/50 的失败，也不建立尽力交付数据报跨任意网络故障不丢包的保证。全部远端临时凭据、进程与目录已清理。
