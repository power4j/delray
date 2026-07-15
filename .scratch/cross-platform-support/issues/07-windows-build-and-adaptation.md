# 07 — 在 Windows 构建并修正平台行为

**What to build:** 从最新主干创建短期 Windows 分支，在 Windows `x86_64` 真机配置 Npcap SDK 和运行时，生成可用 `delray.exe` 并修正 Windows 特有问题。

**Blocked by:** 06 — 完成 Linux 共享改造验收

**Status:** ready-for-human

- [ ] 从已经合并 Linux 共享改造的最新主干创建 `windows-support` 短期分支。
- [ ] 记录 Windows、Rust 1.88、Npcap SDK 和 Npcap 运行时版本。
- [ ] 在 Windows `x86_64` 完成锁定依赖的测试、格式检查、Clippy 和 release 构建。
- [ ] 生成能够启动并列出 Npcap 设备的 `delray.exe`。
- [ ] 数字编号和完整 Npcap 设备名都能够选择网卡。
- [ ] 缺少 Npcap、设备不存在和权限不足时显示明确英文错误。
- [ ] 普通用户可以运行；管理员权限只提高受保护进程的归属完整度。
- [ ] Windows 修正复用共享模块，不复制统计、报告或 TUI 业务逻辑。
- [ ] Windows 发现的共享问题具有自动化回归测试，并保持 Linux 测试通过。
- [ ] 本 ticket 不制作安装包、不签名、不捆绑 Npcap，也不更新 README 的支持平台声明。
