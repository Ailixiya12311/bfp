# BFP 按类纠错核心模块 r9-next14（实验）

日期：2026-10-09。源码路径：`C:\Users\developer\Desktop\bfp\.staging\r9-next14\internal\fec`。

本阶段先实现有界、owner 独立的单丢片 XOR repair block。`Profile` 固定 data shard 数、一个 parity shard、shard 大小和 block 总字节上限；`Encode` 只复制并填充 payload，`Recover` 只在恰好一个 data shard 缺失时恢复，并按原始长度裁剪。模块不保存 Session、Carrier、Flow、目标 socket 或后台 goroutine，因此可由上层在 Session/generation/flow/direction/block 生命周期内拥有和销毁。

这不是完整 FEC wire 接入。上层接入前必须把 block 元数据和 repair shard 放进已认证 AEAD 帧，绑定 Session、carrier generation、Flow、方向和 block ID；必须有固定寿命、组数/字节预算、重复/回放检查和能力协商。可靠字节流不能因 class 改变而降级丢字节；该模块当前只为 Datagram 的可选冗余提供核心。

验证：`go test ./internal/fec` 通过，覆盖单丢片恢复、空 payload、满 shard、长度裁剪、profile/count/shape 上限。next14 的正式全模块 gate、Linux race、wire 接入和 WAN 尚未运行；不能把该模块计为第三类最终完成。
