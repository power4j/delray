# 05 — 提供可保持非最新数据的进程详情

**What to build:** 让流量分析人员从进程列表进入详情，查看路径、累计流量和 `Last seen`；进程离开 top-N 后保留最后数据，由使用者决定何时返回。

**Blocked by:** 04 — 输出进程统计身份、路径和 Last seen

**Status:** ready-for-agent

- [ ] 概览页继续只显示进程名和总流量，不展示路径。
- [ ] 进程列表继续显示进程名、PID、Recv、Sent 和 Total，并具有明确选中状态。
- [ ] 按 `Enter` 进入所选进程的详情视图，并提供明确返回操作。
- [ ] 详情显示进程名、PID、完整路径、Recv、Sent、Total 和相对 `Last seen`。
- [ ] 未归属流量可以进入详情，PID 和路径显示 `-`，特殊名称样式保持不变。
- [ ] 所选统计身份仍在当前 top-N 时，详情随新快照更新。
- [ ] 所选统计身份离开 top-N 时不自动退出、不清空数据，并显示一次 `Tracking paused: process is no longer in Top-N.`。
- [ ] 一次性提示消失后仍显示持久 `Tracking paused` 状态、最后数据和 `Last seen`。
- [ ] 相同统计身份重新进入 top-N 后自动恢复实时更新。
- [ ] 进程查询数据过期时显示 `Tracking paused: process data is stale.`，不声称进程已经退出。
- [ ] 所有新增用户可见文案使用英文。
- [ ] ratatui `TestBackend` 覆盖进入、返回、实时更新、离开 top-N、提示消失、持续 paused、重新进入和未归属详情。
- [ ] 80 列终端中内容不重叠，现有 TUI 页面切换延迟检查保持通过。
