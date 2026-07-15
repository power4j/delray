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
- [ ] plain 和 JSON/JSONL 字段、空值和时间格式符合规格。
- [ ] 持续运行测试没有不可接受的 CPU、内存、丢包或稳定性问题。
- [ ] README 链接 Npcap 官方网站 `https://npcap.com/`，并简要说明 Npcap SDK、运行时、源码构建和权限重点。
- [ ] 人工验收通过后，将 Windows `x86_64` 从目标平台更新为支持平台；未通过时保持目标平台状态。
- [ ] 最终 Standards/Spec 双轴审查没有未处理的阻断问题。
- [ ] `windows-support` 是短期分支，完成后合并回唯一主线，不保留长期 Windows 产品分支。
