# 01 — 以 listeners 打通 Linux 进程归属

**What to build:** 在 Linux 上以 `listeners 0.6` 替代项目自行维护的 `/proc` 查询，让已捕获的 TCP/UDP 流量继续端到端归属到正确进程，同时建立后续 Windows 复用的进程查询接口。

**Blocked by:** None — can start immediately

**Status:** ready-for-agent

- [ ] 将项目 MSRV 提高到 Rust 1.88，并锁定包含 `listeners 0.6` 的依赖解析结果。
- [ ] 使用 Rust 1.88 完成锁定依赖的构建和测试。
- [ ] 流量记录能够区分 TCP、UDP 和没有本机 socket 的其他协议。
- [ ] 进程查询使用本机 IP、端口和协议进行匹配，不使用只按端口查询的接口。
- [ ] Linux 上的常见 TCP/UDP、IPv4/IPv6 流量能够归属到 `listeners` 返回的 PID 和可执行文件名。
- [ ] 进程显示名使用可执行文件名，不再使用完整命令行。
- [ ] 未匹配到 PID 的流量继续计入「未归属流量」，接口和进程流量分区不变量保持成立。
- [ ] 项目不再自行扫描 Linux `/proc` socket 和进程文件。
- [ ] 进程查询行为通过可注入记录测试，不依赖测试机当前打开的真实端口。
- [ ] 现有 CLI、管线、plain、JSON/JSONL 和 TUI 测试保持通过。
