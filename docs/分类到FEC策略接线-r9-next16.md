# BFP 分类到数据报纠错策略接线 r9-next16（实验）

日期：2026-10-09。源码候选位于 `C:\Users\developer\Desktop\bfp\.staging\r9-next16`，父边界为 r9-next15，父 manifest 为 `b8e219ea619fe0378f014beaaa3370735568b9026d9337f6ace965c54612bed8`。本文记录“分类结果如何选择 Datagram FEC profile”的实现和证据，不表示四类功能最终验收或生产发布。

## 接线合同

客户端配置新增 `ClientConfig.DatagramFEC *DatagramFECPolicyConfig`。policy 用 `ByClass` 为 `Interactive`、`Normal`、`Bulk` 保存值类型的 `protocol.FECProfile`；构造时校验并复制调用方 map，Session 只发布固定数组和值类型，后续修改调用方配置不会改变已建立的 Session。

自动选择只在以下条件同时满足时发生：目标网络为 UDP、目标没有显式 `Target.FEC`，并且候选类别已经经过本地规则、可信 Hint 和 `HighestAllowed` cap。显式 `Target.FEC`（包括显式禁用）始终优先。选择在 OPEN 分配 Flow 前完成；拒绝不会消耗 Flow 编号、创建目标连接或写入业务字节。

FEC profile 在 OPEN 时固定。行为分类降级、对端类别公告、承载从 UDP 切换到 TCP、Session 恢复，都不会重新选择 profile。服务端使用入站 OPEN 携带的 Delivery/FEC 合同，不依据服务端本地类别重新覆盖客户端选择。TCP 可靠流仍保持原有可靠字节流合同，TCP carrier 不发送 parity。

当 capability 协商没有选中 bit 4 时，自动 policy 回退为普通 Datagram；显式请求 FEC 仍按原严格合同返回未协商错误。`optional` 允许对端不支持 FEC，`required` 要求会话选中 FEC capability；类别仍可独立配置为 `off`，因此 required 表示会话能力要求，不表示每个类别都必须生成 parity。

## CLI 配置

客户端 JSON 可加入：

```json
{
  "datagram_fec": {
    "mode": "optional",
    "by_class": {
      "normal": "xor1"
    },
    "profile": {
      "max_data_shards": 32,
      "shard_size": 900
    }
  }
}
```

`mode` 的含义如下：

| mode | offered capability | required capability | 行为 |
|---|---:|---:|---|
| 省略、空对象、`off` | 原 class capability | 原 class capability | 保持旧默认，不自动启用 FEC；带 `by_class` 或 `profile` 会拒绝 |
| `optional` | class + FEC | class | 对端不支持 FEC 时可建立普通 Session |
| `required` | class + FEC | class + FEC | 对端不支持 FEC 时握手拒绝 |

`by_class` 只能使用 `off` 或 `xor1`。profile 的 `max_data_shards` 范围为 1–32，`shard_size` 范围为 1–900，`MaxBlockSize` 为两者乘积。服务端配置只接受 `mode`，不接受 `by_class` 或 `profile`，因为服务端使用入站 OPEN 的合同。解析器拒绝未知字段、重复字段、大小写别名、null、数组、布尔、数字/小数/指数、越界值、off 模式的 profile，以及没有任何 `xor1` 类却提供的 profile；错误信息不回显用户输入。

profile 越小，单条 FEC 数据报允许的应用数据容量越小。超过 `max_data_shards * shard_size` 的应用 Datagram 会作为整体被拒绝，不会产生部分队列项、message ID 或 parity；应用 Datagram 原有 16 KiB 上限仍然存在。

## 验证证据

- **Focused Session/CLI：** policy ownership、类别 cap、optional fallback、显式 strict、TCP 可靠性、行为降级、对端公告、TCP recovery、真实 JSON → SOCKS → 加密 UDP/TCP runtime 均通过。原始日志保存在 `.staging/r9-next16/verification/r9-next16/focused/`。
- **本地 gate：** 143 个 Go/module 文件，manifest `64aea3d8982f3ff4a827ff347d10bed383477ea1cbdadacac66faf516b67c228`；`go test -json -p 1 ./... -count=1 -timeout=180s` 为 17 个包、471 个顶层测试，`go vet ./...`、Windows amd64 和 Linux amd64 构建通过，`source_unchanged=true`。证据见 [local-summary.json](C:/Users/developer/Desktop/bfp/.staging/r9-next16/verification/r9-next16/local-gate-attempt01/local-summary.json)。
- **有限 parser fuzz：** `FuzzDatagramRepairDecodeCanonical` 运行 5 秒、2 worker，exit 0，源码仍匹配上述 manifest。它不是完整 fuzz campaign 或独立安全审核。证据见 [fuzz summary](C:/Users/developer/Desktop/bfp/.staging/r9-next16/verification/r9-next16/fuzz/summary.json)。
- **洛杉矶 source-bound Linux race：** run `da9e492b398199fcbad740cb28bca91b`，17 个包通过、无 DATA RACE，owned 容器和目录清理，接收机 before/after 快照未变化，上传源码与本地 manifest 一致。证据见 [race-result.json](C:/Users/developer/Desktop/bfp/.staging/r9-next16/lab/runs/da9e492b398199fcbad740cb28bca91b/race-result.json)。
- **小体量双机基线：** run `8f71118b9265c444a242f26066c77e43` 使用同一 Linux 构建；新加坡发送 12 次 × 1 KiB、间隔 1 秒。正常 UDP 为 12/12，运行中 UDP→TCP 为 12/12 且保留同一 Session；初始 UDP 阻断场景为 11/12 并触发 probe deadline，因此整轮严格 FAIL。随机主动探测无应用层响应，两端 owned 清理和快照比较通过。该轮未启用 FEC policy，不能证明 WAN FEC 效果。证据见 [wan-result.json](C:/Users/developer/Desktop/bfp/lab/runs/8f71118b9265c444a242f26066c77e43/wan-result.json)。

## 当前边界

next16 只完成“类别结果到 FEC profile”的配置和开流接线。它没有完成 Clash 规则标签/应用身份的可信桥接，也没有完成混合类别公平性、FEC 开销、goodput、尾延迟、丢包和高 RTT 的 WAN 性能验收。客户端 DNS 代理、fake-IP/reverse NAT、TUN、IPv6、Mihomo/sing-box 原生 outbound、长期资源稳定性和独立安全评审仍在范围外。四类功能仍计为 **2 类主体实现、2 类部分实现、0 类最终验收**；`acceptance_complete=false`、`production_ready=false`、`released=false`。
