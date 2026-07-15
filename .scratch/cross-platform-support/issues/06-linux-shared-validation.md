# 06 — 完成 Linux 共享改造验收

**What to build:** 在 Linux `x86_64` 主力环境验证全部共享改造，证明新进程查询、数据链路、输出和 TUI 可以合并主干而不降低现有 Linux 可用性。

**Blocked by:** 02 — 保守处理歧义与过期进程查询；03 — 支持多种数据链路与编号选网卡；05 — 提供可保持非最新数据的进程详情

**Status:** ready-for-agent

- [ ] Rust 1.88 下锁定依赖的测试、格式检查、Clippy 和 release 构建全部通过。
- [ ] glibc 2.28 和 libpcap 运行基线保持不变。
- [ ] 物理网卡、loopback 和 Linux `any` 完成人工抓包验证。
- [ ] TCP、UDP、IPv4 和 IPv6 的接口、IP、进程与未归属统计符合规格。
- [ ] 通配监听、同端口 TCP/UDP、共享 socket 和普通权限完成针对性验证。
- [ ] plain、JSON/JSONL 和 TUI 展示路径、`Last seen`、详情和 paused 状态符合规格。
- [ ] 现有 TUI 延迟脚本通过，持续运行没有明显 CPU、内存或丢包回归。
- [ ] 最终 Standards/Spec 双轴审查没有未处理的阻断问题。
- [ ] Windows 仍保持目标平台，README 的支持平台声明在本 ticket 中不更新。
- [ ] `cross-platform-core` 分支形成可合并、工作区干净的提交序列。
