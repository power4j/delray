# 06 — 完成 Linux 共享改造验收

**What to build:** 在 Linux `x86_64` 主力环境验证全部共享改造，证明新进程查询、数据链路、输出和 TUI 可以合并主干而不降低现有 Linux 可用性。

**Blocked by:** 02 — 保守处理歧义与过期进程查询；03 — 支持多种数据链路与编号选网卡；05 — 提供可保持非最新数据的进程详情

**Status:** in-progress

- [x] Rust 1.88 下锁定依赖的测试、格式检查、Clippy 和 release 构建全部通过。
- [x] glibc 2.28 和 libpcap 运行基线保持不变。
- [ ] 物理网卡、loopback 和 Linux `any` 完成人工抓包验证。
- [ ] TCP、UDP、IPv4 和 IPv6 的接口、IP、进程与未归属统计符合规格。
- [ ] 通配监听、同端口 TCP/UDP、共享 socket 和普通权限完成针对性验证。
- [ ] plain、JSON/JSONL 和 TUI 展示路径、`Last seen`、详情和 paused 状态符合规格。
- [x] 现有 TUI 延迟脚本通过，持续运行没有明显 CPU、内存或丢包回归。
- [ ] 最终 Standards/Spec 双轴审查没有未处理的阻断问题。
- [ ] Windows 仍保持目标平台，README 的支持平台声明在本 ticket 中不更新。
- [ ] `cross-platform-core` 分支形成可合并、工作区干净的提交序列。

## Linux 验证记录

- `cargo +1.88.0 check`、`cargo +1.88.0 test`、`cargo fmt --check`、`cargo clippy --all-targets --all-features -- -D warnings` 和 `git diff --check` 已通过。
- `cargo +1.88.0 zigbuild --release --target x86_64-unknown-linux-gnu` 已重新生成 `target/x86_64-unknown-linux-gnu/release/delray`。
- release 产物已设置 `cap_net_raw=ep`，可用于非 root 抓包验证。
- 当前 WSL 环境中，Cloudflare 下载路径不经过 `eth0`；`eth0` 验证仅观察到少量 rustdesk 流量，不能作为下载统计验证依据。
- `loopback0` 下 Cloudflare 下载可捕获有效流量：接口统计约 10.7 MB In 和 10.7 MB Out，进程侧可归属到 `curl` 的一侧约 10.7 MB，另一侧保持未归属。该结果符合 WSL/proxy/loopback 路径下的系统抓包边界。
- `--diagnostics` 已验证：JSON/JSONL 仍写 stdout，进程归属诊断写 stderr，包含 lookup 命中/未命中、刷新计数、刷新耗时、pending 记录数和 pending 字节数。
