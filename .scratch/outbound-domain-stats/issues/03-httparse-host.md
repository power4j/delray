# 03 — 引入 httparse + HTTP Host 提取

**What to build:** 引入 `httparse 1.10`，实现 01 seam 的 HTTP 解析：从明文 TCP payload 用 httparse 解析请求行 + Host 头。按 Q12 首包只解析一次，`Status::Partial` / 非 HTTP 请求 / 无 Host 都返回 None（走 NoDomain）。只匹配出站方向的请求。

**Blocked by:** 01

**Status:** done

- [x] Cargo.toml 加 `httparse 1.10`
- [x] httparse 解析请求行 + Headers，提取 Host 头
- [x] `Status::Partial`、非 HTTP 请求、无 Host、解析错误返回 None
- [x] 只解析请求（HTTP 响应不算），匹配出站方向
- [x] 测试：GET+Host、POST+Host、Partial、无 Host、HTTP/1.0 无 Host、非 HTTP 字节、HTTP 响应

## Comments

- 2026-07-21 实现：`src/domain_parse_http.rs`（14 单测全绿），与 `domain_parse_tls.rs` 平行独立；CaptureSource 仍走 NoopDomainParser，留待 04 接线。
- HTTP 响应自然落入 `Err(Token)` 分支返回 None（httparse 1.10.1 实测）——不靠方向判断实现"只匹配请求"。
- Host 大小写不敏感：httparse 保留 wire 形式（已对照源码确认），本解析器用 `eq_ignore_ascii_case` 比对。
- 按 spec"不做归一"返回原始 Host 值（含端口、trailing dot、大小写），由后续统计层决定是否归一。
- 三项质量门（test / fmt / clippy -D warnings）全过。
