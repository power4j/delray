# 07 — 在 Windows 构建并修正平台行为

**What to build:** 从最新主干创建短期 Windows 分支，在 Windows `x86_64` 真机配置 Npcap SDK 和运行时，生成可用 `delray.exe` 并修正 Windows 特有问题。

**Blocked by:** 06 — 完成 Linux 共享改造验收

**Status:** ready-for-human

- [x] 从已经合并 Linux 共享改造的最新主干创建 `windows-support` 短期分支。
- [x] 记录 Windows、Rust 1.88、Npcap SDK 和 Npcap 运行时版本。
- [x] 在 Windows `x86_64` 完成锁定依赖的测试、格式检查、Clippy 和 release 构建。
- [x] 生成能够启动并列出 Npcap 设备的 `delray.exe`。
- [x] 数字编号和完整 Npcap 设备名都能够选择网卡。
- [ ] 缺少 Npcap、设备不存在和权限不足时显示明确英文错误。
- [ ] 普通用户可以运行；管理员权限只提高受保护进程的归属完整度。
- [x] Windows 修正复用共享模块，不复制统计、报告或 TUI 业务逻辑。
- [ ] Windows 发现的共享问题具有自动化回归测试，并保持 Linux 测试通过。
- [x] 本 ticket 不制作安装包、不签名、不捆绑 Npcap，也不更新 README 的支持平台声明。

## Comments

### 2026-07-17 Windows 验证记录

### 环境

- 分支：`windows-support`
- 分支来源：`windows-support` 从 `origin/main` 的 `6b5b3e4ccb27790e6274f86a859ebe8094755688` 创建
- 操作系统：注册表报告 `ProductName=Windows 10 Pro`、`DisplayVersion=25H2`、`CurrentBuildNumber=26200`、`UBR=8875`，AMD64
- Rust：`rustc 1.88.0 (6b00bc388 2025-06-23)`，host 为 `x86_64-pc-windows-msvc`
- Cargo：`cargo 1.88.0 (873a06493 2025-05-10)`
- Npcap Runtime：1.88，`AdminOnly=0`
- Npcap DLL：`wpcap.dll` 1.10.6，`Packet.dll` 1.88
- Npcap SDK：未安装或未发现；当前环境没有 `wpcap.lib`，`LIB`、`INCLUDE` 和 `LIBPCAP_LIBDIR` 均未配置

### 首轮命令与结果

| 命令 | 结果 |
| --- | --- |
| `cargo +1.88.0 check --locked` | 通过 |
| `cargo +1.88.0 test --locked` | 失败。MSVC Linker 报告 `LNK1181: cannot open input file 'wpcap.lib'`；测试二进制未生成，自动化测试未运行 |
| `cargo +1.88.0 fmt --all -- --check` | 通过 |
| `cargo +1.88.0 clippy --locked --all-targets --all-features -- -D warnings` | 通过 |
| `cargo +1.88.0 build --release --locked` | 失败。MSVC Linker 报告 `LNK1181: cannot open input file 'wpcap.lib'`；未生成 `target/release/delray.exe` |

### 结论与遗留问题

首轮失败来自本机缺少 Npcap SDK 的 x64 import library，不是 Rust 源码编译错误。仓库已有自动化测试覆盖编号选择、完整 Npcap 设备名选择，以及无效编号和设备不存在的英文错误。由于测试二进制无法链接，这些测试未在本机实际运行，因此相关 checklist 保持未勾选。

本轮没有伪造 `wpcap.lib`、下载 Npcap SDK，或针对环境问题修改、复制统计、报告和 TUI 业务逻辑。release build、`delray.exe` 启动、设备列表、真实设备选择、缺少 Npcap、权限不足，以及普通用户和管理员权限差异均未完成。由于 release build 受阻，本轮未进入 ticket 08 的输出模式和 TUI 人工验收，也未复跑 ticket 06 的 Linux 真机验收。

下一步需要安装官方 Npcap SDK，将其 x64 `Lib` 目录配置到 `LIBPCAP_LIBDIR`，然后重新运行上述命令和 `cargo +1.88.0 build --release --locked`。release build 成功后，再继续 `delray.exe` 启动、Npcap 设备、错误和权限的人工验证。

### 2026-07-17 SDK 1.16 后续验证记录

### 环境

- Npcap SDK：1.16，路径为 `D:\runtime\npcap\npcap-sdk-1.16`；其 `Lib\x64` 包含 `wpcap.lib` 和 `Packet.lib`。
- SDK 随附的 `SDK_CHANGELOG.md` 标明其 libpcap 版本为 1.10.6，与已安装的 `wpcap.dll` 1.10.6 一致；`Packet.dll` 版本为 1.88。
- 构建进程仅设置 `LIBPCAP_LIBDIR=D:\runtime\npcap\npcap-sdk-1.16\Lib\x64`，未设置 `LIBPCAP_VER`，也未修改机器级环境变量。
- 当前验证会话为 Medium integrity，属于 `BUILTIN\Users`，未提升为管理员。

### 命令与结果

| 命令 | 结果 |
| --- | --- |
| `cargo +1.88.0 check --locked` | 通过。`pcap 2.4.0` 和 Delray 均完成 Windows 编译。 |
| `cargo +1.88.0 test --locked` | 通过：122 项测试通过，0 项失败。 |
| `cargo +1.88.0 fmt --all -- --check` | 通过。 |
| `cargo +1.88.0 clippy --locked --all-targets --all-features -- -D warnings` | 通过。 |
| `cargo +1.88.0 build --release --locked` | 通过，生成 `target\release\delray.exe`。 |
| `delray.exe --format json` | 按预期因缺少显式网卡以失败状态退出，并列出 14 个 Npcap 设备，其中包括 `\Device\NPF_Loopback`。 |
| `delray.exe 13 --format json` | 在 Npcap Loopback 上运行 7 秒后主动停止；输出 JSONL，`interface` 为 `\Device\NPF_Loopback`。 |
| `delray.exe \Device\NPF_Loopback --format json` | 在同一设备上运行 7 秒后主动停止；输出 JSONL，确认完整 Npcap 设备名可用。 |
| `delray.exe missing-interface --format json` | 按预期以失败状态退出，并显示英文错误：`Failed to open interface: Interface not found: missing-interface`。 |

两个有界运行都在普通用户会话中完成，并产生 Loopback 的真实流量统计。它们仅用于确认 release 可执行文件能够启动、打开设备和接受两种选择形式；不构成 ticket 08 的完整流量、进程归属或输出模式验收。

### 结论与遗留问题

本机 SDK 缺失导致的 `LNK1181` 已解除，无需设置 `LIBPCAP_VER`，也未发现需要修改 Windows 源码或复制共享业务逻辑的问题。已有自动化测试同时覆盖数字编号、完整设备名和无效选择；本次 Windows 测试二进制也已实际运行。

缺少 Npcap 的错误未通过卸载或破坏运行时验证。权限不足、管理员与普通用户的归属差异、物理网卡、TCP/UDP、IPv4/IPv6 的完整组合，以及 plain、JSON/JSONL、TUI、终端恢复和持续运行仍属于 ticket 08 的人工验收，相关 checklist 保持未勾选。README 支持平台声明未改动；未下载、复制或提交 Npcap、`delray.exe`、构建产物、安装包或签名文件。

### 2026-07-17 Loopback 与 plain 后续验证

在同一普通用户会话中，`delray.exe 10 --output <temporary-file>` 成功打开 Intel Wi-Fi 适配器并写入 plain 报告。5 秒观察窗口内接口统计为零，因此此结果只验证物理设备打开和 plain 输出路径，不作为物理网卡流量归属证据。

`delray.exe 13 --format json` 在 Npcap Loopback 上运行时，由本机生成了 TCP/UDP IPv4 和 IPv6 流量：`127.0.0.1` 与 `::1` 的 TCP/UDP 收发均成功。JSONL 快照显示非零入站和出站字节，包含进程记录、路径、`last_seen` 和未归属流量；这确认了 Loopback 的前台 JSONL 聚合路径可用。Delray 当前使用同一个 `--format json` 参数：前台 stdout 为 JSONL，配合 `--output` 时覆盖写 JSON 文件。

完整物理网卡流量、普通用户与管理员归属率对比、缺少 Npcap 或权限不足错误、完整 TUI 交互、终端恢复和长期运行仍未验收。TUI 已有自动化渲染测试覆盖，但 Windows 终端交互需要人工执行，不能用自动化输入替代。

### 2026-07-17 JSONL 与 diagnostics 后续验证

在同一普通用户会话中，`delray.exe \Device\NPF_Loopback --format json --diagnostics` 以前台模式运行，并将 stdout 和 stderr 重定向到 `target\manual-validation` 下的临时文件。运行期间本机生成 `127.0.0.1` 与 `::1` 的 TCP/UDP loopback 流量。

结果：stdout 产生 1 行 JSONL；最后一帧 `interface` 为 `\Device\NPF_Loopback`，`totals.in_bytes=1577893`，`totals.out_bytes=1578017`，`top_processes` 包含 9 条记录，至少一条进程记录包含 `path` 和 `last_seen`。stderr 输出 diagnostics，例如 `lookup_hits=2663`、`lookup_misses=2158`、`refresh_success=5`、`refresh_failure=0`、`pending_records=8`。

本轮未修改 Rust 源码。Windows 构建问题来自 SDK 链接环境，后续 Windows 验证也未发现需要复制或分叉统计、报告或 TUI 业务逻辑的问题。

### 2026-07-17 物理 Ethernet 输出后续验证

`ipconfig /all` 显示当前连接的默认链路为 ASIX USB to Gigabit Ethernet Family Adapter，IPv4 地址为 `192.168.100.102`。Npcap 设备列表中的编号 `11` 对应该适配器；编号 `10` 的 Intel Wi-Fi 适配器已断开，因此其零流量观察不作为物理网卡验证。

在同一普通用户会话中，`delray.exe 11 --format json --output target\manual-validation\physical-ethernet.json --diagnostics` 运行期间，对 `192.168.0.1` 和 `61.139.2.69` 完成 DNS 查询，并尝试 TCP 连接 `192.168.0.1:80`。最后的 JSON 文件记录 `interface` 为 `\Device\NPF_{CFC6B06D-F53F-4FD8-94DB-50405A44A5A7}`，`totals.in_bytes=216538`，`totals.out_bytes=1720308`，包含 10 条进程记录、1 条未归属流量、至少 3 条带 `path` 的进程记录、带 `last_seen` 的进程记录以及入站和出站 IP 统计。stderr 的最后两次 diagnostics 均为 `refresh_success` 非零、`refresh_failure=0`。

`delray.exe 11 --output target\manual-validation\physical-ethernet.txt --diagnostics` 在同一设备上完成 plain 文件验证。输出包含接口流量、`Process	PID	Recv	Sent	Total	Path	Last Seen` 列和 ISO 8601 `Last Seen` 值，文件大小为 1,653 bytes。

该记录只确认连接中的物理 Ethernet 设备能够抓取实际 IPv4 TCP/UDP 流量并写入 JSON 与 plain 文件。物理 IPv6、管理员权限差异、权限拒绝、TUI 终端交互、终端恢复和长期运行仍未验收。

### 2026-07-17 Windows TUI 输入与接口标签回归修复

普通用户使用 `target\release\delray.exe` 反馈三个 Windows TUI 问题：启动时接口选择器会自动确认；切换接口时一次方向键移动两行；顶部显示底层 Npcap 设备路径而非设备描述。

原因是 TUI 将 Windows 的 `KeyEventKind::Release` 当作普通按键处理，因此方向键的 Press 和 Release 都会移动选择项，`Enter` 的 Release 也可能确认选择器。标题直接使用活动接口的 pcap 名称，未通过当前 `InterfaceInfo` 目录解析描述。

修复后，TUI 忽略 `KeyEventKind::Release`，保留 Press 和 Repeat；顶部优先显示匹配 `InterfaceInfo.name` 的 `description`，缺少描述时回退到设备名。新增 `selector_ignores_releases_and_handles_press_and_repeat`、`header_uses_interface_description_instead_of_pcap_device_name` 和 `interface_label_falls_back_to_pcap_name_without_a_description` 回归测试。

验证结果：`cargo +1.88.0 test --locked tui::tests::` 通过 32 项；`cargo +1.88.0 test --locked` 通过 125 项；格式检查、Clippy 和 release 构建均通过。新的 `target\release\delray.exe` 已生成，等待 Windows 终端人工复测。

### 2026-07-17 Windows 网卡名称与进程名回退修复

Windows 网卡选择器调整为先显示 `InterfaceInfo.description`，再显示完整 Npcap 设备名；宽屏和紧凑布局均保留编号、完整设备名和标记。新增 `selector_renders_friendly_name_before_pcap_name` 渲染测试。

进程表此前丢弃 `listeners::Process.name`，只从进程路径提取显示名。Windows 的 `listeners 0.6` 在路径查询失败时仍通过 Toolhelp 返回稳定的可执行文件名，因此路径为空会被错误显示为 `?`。修复后优先使用路径 basename；路径为空时使用非空的 `listeners::Process.name`。PID + 可选路径统计身份、历史流量和未归属流量语义保持不变；名称和路径都不可用时仍显示 `?`。

新 release 在连接中的 Ethernet 设备 `11` 上进行 JSON 验证：9 条进程记录中，已归属 PID 的 `name: null` 为 0；其中 5 条记录保留 `path: null`，但显示 `GameViewerServer.exe`、`tailscaled.exe`、`cloudflared.exe` 等名称；未归属流量仍为单独记录。新增 `missing_executable_path_uses_listener_process_name` 测试。

验证结果：`cargo +1.88.0 test --locked` 通过 126 项；格式检查、Clippy 和 release 构建均通过。新的 `target\release\delray.exe` 已生成，等待 Windows TUI 人工复测。

### 2026-07-17 管理员模式人工反馈

人工复测确认当前 `target\release\delray.exe` 的 Windows TUI 未发现问题；管理员模式可以正常运行。

此前已经记录普通用户会话可以启动、列出并打开 Npcap 设备。本次未在相同可控流量下量化普通用户与管理员的进程归属差异，因此「管理员权限只提高受保护进程归属完整度」仍保留为未完成验收项。

当前没有可安全复现的缺少 Npcap 或权限拒绝环境；相关英文错误路径暂不验证，checklist 保持未勾选。ticket 08 的完整人工验收暂不开始，README 的 Windows 支持平台声明保持不变。

### 2026-07-20 缺少 Npcap Runtime 验证与修复

在当前协同环境卸载 Npcap Runtime 后，旧 release 的 `delray.exe --version` 没有 stdout 或 stderr。该现象发生在 Rust `main` 之前：`pcap 2.4` 的 Windows FFI 直接导入 `wpcap.dll`，因此 Windows loader 无法加载 DLL 时不会进入现有错误处理。

修复增加 Windows 专用链接参数 `/DELAYLOAD:wpcap.dll` 和 `delayimp`，将 `wpcap.dll` 改为延迟加载；CLI 参数解析完成后，Delray 使用 `LoadLibraryW` 显式检查 Runtime。缺失时输出英文错误：

```text
Npcap Runtime is required. Install Npcap from https://npcap.com/ and try again.
```

在 Runtime 仍缺失的真实环境中，重新构建 release 后执行 `target\release\delray.exe --format json`，结果为状态码 `1`、stdout 为空、stderr 为上述错误。`cargo +1.88.0 test --locked` 通过 131 项测试，`cargo +1.88.0 build --release --locked` 通过。新增回归测试以注入 Runtime 探测失败的方式执行同一启动分支，并验证在抓包初始化前返回失败；真实验收同时覆盖了延迟加载后的启动行为和 stderr 文案。

本次只使用现有 SDK import library 进行源码构建，未下载、捆绑或提交 Npcap。权限拒绝和普通用户与管理员归属差异尚未验证，因此对应 checklist 保持未勾选。
