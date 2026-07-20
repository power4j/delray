# 08 — 完成 Windows 人工验收并更新 README

**What to build:** 在 Windows `x86_64` 真机完成完整人工验收；通过后将 Windows 从目标平台升级为支持平台，并只在 README 补充必要的 Npcap、构建和运行说明。

**Blocked by:** 07 — 在 Windows 构建并修正平台行为

**Status:** ready-for-human

- [ ] 记录 Windows、Rust、Npcap、硬件和终端环境，以及全部验收命令和结果。
- [ ] 物理网卡和 Npcap Loopback 均能持续抓取真实流量。
- [ ] TCP、UDP、IPv4 和 IPv6 的接口、IP、进程与未归属统计符合规格。
- [ ] 普通用户和管理员权限分别完成进程归属验证，并记录权限差异。
- [ ] 进程路径、PID + 路径身份、`Last seen`、top-N 和未归属流量符合规格。
- [ ] TUI 概览、进程列表、进程详情、paused 状态、返回操作和终端恢复符合规格。
- [x] plain 和 JSON/JSONL 字段、空值和时间格式符合规格。
- [ ] 持续运行测试没有不可接受的 CPU、内存、丢包或稳定性问题。
- [ ] README 链接 Npcap 官方网站 `https://npcap.com/`，并简要说明 Npcap SDK、运行时、源码构建和权限重点。
- [ ] 人工验收通过后，将 Windows `x86_64` 从目标平台更新为支持平台；未通过时保持目标平台状态。
- [ ] 最终 Standards/Spec 双轴审查没有未处理的阻断问题。
- [ ] `windows-support` 是短期分支，完成后合并回唯一主线，不保留长期 Windows 产品分支。

## Comments

### 2026-07-20 自动化 Windows 验收记录

#### 环境

- 会话：普通用户，`BUILTIN\Users`，Medium integrity。
- Rust：`rustc 1.88.0 (6b00bc388 2025-06-23)`，host 为 `x86_64-pc-windows-msvc`。
- Npcap：Runtime 1.88；SDK 1.16，`D:\runtime\npcap\npcap-sdk-1.16\Lib\x64` 包含 `wpcap.lib` 与 `Packet.lib`。
- 测试流量工具：`temp\iperf-3.21-win64\iperf3.exe`，iPerf 3.21。
- 物理适配器：ASIX USB to Gigabit Ethernet Family Adapter，Npcap 名称为 `\Device\NPF_{CFC6B06D-F53F-4FD8-94DB-50405A44A5A7}`。当前只有 IPv4 地址 `192.168.100.102` 和 IPv4 默认路由；没有全局 IPv6 地址或 IPv6 默认路由。
- Loopback：编号 `13`，Npcap 名称为 `\Device\NPF_Loopback`。编号只在本次设备列表中有效。

#### 构建与自动化检查

构建进程设置 `LIBPCAP_LIBDIR=D:\runtime\npcap\npcap-sdk-1.16\Lib\x64` 后执行以下命令：

| 命令 | 结果 |
| --- | --- |
| `cargo +1.88.0 test --locked` | 通过，130 项测试通过。 |
| `cargo +1.88.0 fmt --all -- --check` | 通过。 |
| `cargo +1.88.0 clippy --locked --all-targets --all-features -- -D warnings` | 通过。 |
| `cargo +1.88.0 build --release --locked` | 通过，生成 `target\release\delray.exe`。 |

#### Loopback TCP/UDP、IPv4/IPv6 与输出

普通用户会话中，Delray 使用完整设备名 `\Device\NPF_Loopback --format json --diagnostics` 运行。iPerf 分别使用 `127.0.0.1` 与 `::1`，在端口 `5201` 至 `5204` 上执行 5 秒 TCP/UDP 测试；4 组客户端均以状态码 0 完成。

Delray 产生 5 帧可解析 JSONL。最后一帧的 `in_bytes` 和 `out_bytes` 均为 `126007252`；10 条 top process 记录中有 9 条已归属 PID，其中 8 条带路径，全部带 `last_seen`。8 个 iPerf 客户端和服务端进程均显示为 `iperf3.exe`，带完整路径和 RFC 3339 `last_seen`。1 条未归属记录保持独立。

使用数字编号 `13 --format json --diagnostics` 重复 Loopback TCP/IPv4 测试，产生 2 帧 JSONL，接口为 `\Device\NPF_Loopback`，入站和出站字节均为 `38748143`，并包含 2 条 iPerf 进程记录。

文件输出使用以下组合验证：

- `\Device\NPF_Loopback --format json --output target\manual-validation\2026-07-20-output\loopback.json --diagnostics`
- `\Device\NPF_Loopback --output target\manual-validation\2026-07-20-output\loopback.txt --diagnostics`

JSON 文件可解析，接口入站和出站字节均为 `40907191`，包含 2 条 iPerf 记录。JSON 中未归属记录的 `pid`、`name` 和 `path` 均为 `null`，9 条记录的 `last_seen` 可解析为 RFC 3339 时间。JSONL 的 5 帧均可解析。plain 文件包含 `Process	PID	Recv	Sent	Total	Path	Last Seen` 列，iPerf 记录含路径和 ISO 8601 `Last Seen`，未归属记录的 PID 与路径均为 `-`。

#### 设备错误与物理 Ethernet 部分证据

`delray.exe missing-interface --format json` 连续两次均快速以非零状态退出，stderr 为 `Failed to open interface: Interface not found: missing-interface`。

物理 Ethernet 使用完整 Npcap 名称运行 `--format json --diagnostics`。当前网络策略拒绝 DNS、HTTP 和 HTTPS 外连；对网关 `192.168.0.1` 的 ICMP 可达，但不能作为 TCP/UDP 验收对端。一次 13 秒观察仍产生 2 帧 JSONL，最后一帧 `in_bytes=80051`、`out_bytes=78466`；diagnostics 显示 `refresh_success=7`、`refresh_failure=0`。这只证明当前物理设备可打开并观察到真实 IPv4 流量，不能替代可控的双向 TCP/UDP 测试。

#### 稳定性烟测与遗留项

Loopback 连续运行 1 分钟并循环生成 TCP/UDP、IPv4/IPv6 iPerf 流量。期间产生 14 帧 JSONL、3 次资源采样和 15,035 bytes diagnostics；工作集从约 10.0 MB 变化到 10.7 MB 与 10.6 MB，句柄从 117 变化到 119，没有异常退出。该结果是短时烟测，不替代持续运行验收。

尚未完成：可控物理 Ethernet IPv4 TCP/UDP 双向流量、物理 IPv6 对端、普通用户与管理员在同一流量下的归属对比、缺少 Npcap 与权限拒绝 VM、TUI 详情与 `Tracking paused` 的人工交互、终端恢复，以及更长时间稳定性运行。Windows 仍是目标平台；README 不更新支持平台声明。
