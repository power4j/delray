# 03 — 引入 httparse + HTTP Host 提取

**What to build:** 引入 `httparse 1.10`，实现 01 seam 的 HTTP 解析：从明文 TCP payload 用 httparse 解析请求行 + Host 头。按 Q12 首包只解析一次，`Status::Partial` / 非 HTTP 请求 / 无 Host 都返回 None（走 NoDomain）。只匹配出站方向的请求。

**Blocked by:** 01

**Status:** ready-for-agent

- [ ] Cargo.toml 加 `httparse 1.10`
- [ ] httparse 解析请求行 + Headers，提取 Host 头
- [ ] `Status::Partial`、非 HTTP 请求、无 Host、解析错误返回 None
- [ ] 只解析请求（HTTP 响应不算），匹配出站方向
- [ ] 测试：GET+Host、POST+Host、Partial、无 Host、HTTP/1.0 无 Host、非 HTTP 字节、HTTP 响应

## Comments
