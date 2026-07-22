# 01 — Flow 扩展 domain 字段 + capture 层解析 seam

**What to build:** 在 capture 层建立 L7 域名解析 seam，并扩展 Flow 携带解析结果，为后续 TLS/HTTP 解析与流表提供接入点。本票只建 seam（trait/函数签名 + Flow 字段 + 可注入测试），具体 TLS/HTTP 解析在 02/03，流表在 04。

**Blocked by:** 无

**Status:** done

- [x] Flow 增加 `domain: Option<Arc<str>>` 字段（含测试构造与默认值）
- [x] capture 层定义解析 seam：接受 TCP payload 字节、方向、5-tuple，返回 `Option<域名>`；可注入（测试桩）
- [x] 调用点：只对出站方向、有 payload 的包调用 seam（流表查询在 04 接入，本票用桩）
- [x] 不传 raw payload 到聚合层（只传解析出的 domain）
- [x] 现有 capture / pipeline / stats 测试不回归

## Comments
