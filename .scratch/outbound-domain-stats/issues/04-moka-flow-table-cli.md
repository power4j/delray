# 04 — 引入 moka + 连接级流表 + --flow-table 参数

**What to build:** 引入 `moka 0.12`（`default-features = false, features = ["sync"]`），实现连接级域名流表：5-tuple → 流表项（Pending/Resolved/NoDomain）；`max_capacity` 默认 65536、`time_to_idle` 5 分钟；capture 层首包解析后填表、后续包查表；新增 `--flow-table <N>` CLI 参数调容量。

**Blocked by:** 01

**Status:** ready-for-agent

- [ ] Cargo.toml 加 `moka 0.12`（`default-features = false, features = ["sync"]`）
- [ ] 流表项 enum：Pending / Resolved(Arc<str>) / NoDomain
- [ ] moka 配置 `max_capacity`（默认 65536）+ `time_to_idle`（5 分钟）
- [ ] capture 接线：流表未命中 → 解析（02/03）→ 填表；命中 → 返回域名
- [ ] NoDomain 填入后该连接后续包不再解析
- [ ] clap 加 `--flow-table <N>`（正整数），传入流表容量
- [ ] 测试：首包填表、查表命中、NoDomain 不重试、空闲超时淘汰、表满 LRU 淘汰、5-tuple 复用

## Comments
