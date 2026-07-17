# 07 — 在 Windows 构建并修正平台行为

**What to build:** 从最新主干创建短期 Windows 分支，在 Windows `x86_64` 真机配置 Npcap SDK 和运行时，生成可用 `delray.exe` 并修正 Windows 特有问题。

**Blocked by:** 06 — 完成 Linux 共享改造验收

**Status:** ready-for-human

- [x] 从已经合并 Linux 共享改造的最新主干创建 `windows-support` 短期分支。
- [ ] 记录 Windows、Rust 1.88、Npcap SDK 和 Npcap 运行时版本。
- [ ] 在 Windows `x86_64` 完成锁定依赖的测试、格式检查、Clippy 和 release 构建。
- [ ] 生成能够启动并列出 Npcap 设备的 `delray.exe`。
- [ ] 数字编号和完整 Npcap 设备名都能够选择网卡。
- [ ] 缺少 Npcap、设备不存在和权限不足时显示明确英文错误。
- [ ] 普通用户可以运行；管理员权限只提高受保护进程的归属完整度。
- [ ] Windows 修正复用共享模块，不复制统计、报告或 TUI 业务逻辑。
- [ ] Windows 发现的共享问题具有自动化回归测试，并保持 Linux 测试通过。
- [x] 本 ticket 不制作安装包、不签名、不捆绑 Npcap，也不更新 README 的支持平台声明。

## 2026-07-17 Windows 验证记录

### 环境

- 分支：`windows-support`
- 分支来源：`windows-support` 从 `origin/main` 的 `6b5b3e4ccb27790e6274f86a859ebe8094755688` 创建
- 操作系统：Windows 10 Pro 25H2，build 26200.8875，AMD64
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
