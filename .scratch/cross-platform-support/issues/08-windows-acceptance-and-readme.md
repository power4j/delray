# 08 — 完成 Windows 人工验收并更新 README

**What to build:** 在 Windows `x86_64` 真机完成完整人工验收；通过后将 Windows 从目标平台升级为支持平台，并只在 README 补充必要的 Npcap、构建和运行说明。

**Blocked by:** 07 — 在 Windows 构建并修正平台行为

**Status:** wontfix

- [x] 记录 Windows、Rust、Npcap、硬件和终端环境，以及全部验收命令和结果。
- [x] 物理网卡和 Npcap Loopback 均能持续抓取真实流量。
- [x] TCP、UDP、IPv4 和 IPv6 的接口、IP、进程与未归属统计符合规格。
- [x] 普通用户和管理员权限分别完成进程归属验证，并记录权限差异。
- [ ] 进程路径、PID + 路径身份、`Last seen`、top-N 和未归属流量符合规格。
- [ ] TUI 概览、进程列表、进程详情、paused 状态、返回操作和终端恢复符合规格。
- [x] plain 和 JSON/JSONL 字段、空值和时间格式符合规格。
- [x] 持续运行测试没有不可接受的 CPU、内存、丢包或稳定性问题。
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

尚未完成：权限拒绝 VM、TUI 详情与 `Tracking paused` 的人工交互和终端恢复。Windows 仍是目标平台；README 不更新支持平台声明。

### 2026-07-20 物理 Ethernet 控制流量与稳定性记录

Ubuntu 对端为 `192.168.100.19:5201` 和 `fe80::e017:66ff:fec4:960a%eth0:5202`；Windows ASIX 适配器地址为 `192.168.100.102` 和 `fe80::84fa:44cf:956c:33b1%24`。物理接口使用完整 Npcap 名称 `\Device\NPF_{CFC6B06D-F53F-4FD8-94DB-50405A44A5A7}`。

在普通用户会话中，`target\manual-validation\2026-07-20-physical-iperf-final` 的 8 组 iPerf 测试均以状态码 0 退出，覆盖 TCP/UDP、IPv4/IPv6 及正向/反向流量。Delray 产生 9 帧 JSONL；ASIX 接口累计入站 `1,154,672,997` bytes、出站 `395,878,537` bytes。top-N 中包含 8 条 `iperf3.exe` 记录，9 条记录带路径，没有 top-N 未归属行。diagnostics 的 `refresh_success=31`、`refresh_failure=0`；`lookup_no_candidate` 主要来自其他短生命周期和系统流量，不影响 iPerf 进程已被归属的结果。

首次 30 分钟全协议稳定性尝试在约 8 分钟后停止，原因是 Ubuntu IPv6 iPerf 服务主动终止，客户端错误为 `the server has terminated`；Delray 未退出，且当时 `refresh_success=325`、`refresh_failure=0`。这属于对端测试服务生命周期，不作为产品故障。

为隔离该外部因素，随后对物理 ASIX 接口进行不依赖 iPerf 的持续抓包。Delray 从 `2026-07-20T14:46:46+08:00` 运行至 `2026-07-20T15:11:44+08:00`，共 `1497` 秒，生成 `282` 帧 JSON。最终累计入站 `29,232,495` bytes、出站 `54,803,904` bytes；其中持续观察到对 Ubuntu 对端 `192.168.100.19` 的流量。运行期间工作集约 `10.1–10.7 MB`，句柄从 `141` 降至 `138`；最终 diagnostics 为 `refresh_success=898`、`refresh_failure=0`、`pending_records=0`。未观察到崩溃、资源持续增长或异常捕获中断。

因此，物理网卡和 Loopback 的持续抓取、以及 TCP/UDP/IPv4/IPv6 的自动化控制流量验收均已完成。普通用户和管理员同流量归属对比、故障 VM、TUI 详情/`Tracking paused`/终端恢复和最终 README 支持平台声明仍需人工验收；Windows 继续保持为目标平台。

### 2026-07-20 Npcap 管理员专用访问反馈

启用 Npcap 的管理员专用访问配置后，普通终端启动 Delray 会触发 UAC；管理员终端可以直接运行。两种可运行方式均使用提升后的管理员令牌，未观察到统计数据存在明显差别，因此不构成普通用户与管理员的归属对比证据。需要在不限制 Npcap 驱动访问的安装配置下重新执行普通用户验收；Windows 继续保持为目标平台。

### 2026-07-20 普通用户与管理员归属对比

重新安装未启用管理员专用访问的 Npcap 后，普通终端与管理员终端均可直接运行 Delray，不出现 UAC。在相同 iPerf 流量下，两种模式均未观察到明显的流量统计或进程归属差异。

该结果确认普通用户可以运行，并记录当前受控流量下的权限差异为「未观察到明显差异」。本次流量未覆盖受保护系统进程，因此不能证明管理员权限只会提高该类进程的归属完整度；ticket 07 的对应更严格验收项保持未勾选。

### 2026-07-20 收尾决定

维护者决定不再执行权限拒绝 VM、TUI 详情、`Tracking paused`、返回和终端恢复的剩余人工验收。先前的 Standards 审查没有实现阻断问题；Spec 审查确认这些未勾选项属于完整 Windows 验收的缺口。ticket 08 以 `wontfix` 收尾，表示未完成的验收项后续不再执行，不表示 Windows 已通过完整人工验收。Windows `x86_64` 继续作为目标平台；README 不增加支持平台声明。
