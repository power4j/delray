# 10 — lookup 未命中时合并刷新进程表

Status: ready-for-agent

**What to build:** 当 TCP/UDP 本机 socket lookup 未命中时，请求进程表线程提前刷新；多个未命中必须合并并限速，避免每包扫描系统进程表。

**Blocked by:** 09 — 进程归属诊断指标

## Acceptance Criteria

- [ ] lookup 未命中时聚合线程能够向进程表线程发送刷新请求。
- [ ] 多个未命中在已有刷新进行中或限速窗口内不会触发多次实际 `listeners::get_all()`。
- [ ] 刷新在进程表线程执行；抓包、聚合和 TUI 线程不被系统进程扫描阻塞。
- [ ] 刷新失败保留现有快照和 stale 语义。
- [ ] 本票不追溯修改已经计入未归属流量的历史数据。
- [ ] 测试覆盖单次未命中触发刷新、突发未命中合并、限速窗口、刷新失败和后续常规刷新继续工作。

## Notes

- 这是降低刷新间隔竞态窗口的低风险阶段。
- 不使用 `listeners::get_process_by_port()`，继续保留 Delray 的本机 IP、端口、协议和唯一 PID 规则。
