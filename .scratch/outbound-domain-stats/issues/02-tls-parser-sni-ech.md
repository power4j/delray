# 02 — 引入 tls-parser + TLS SNI/ECH 提取

**What to build:** 引入 `tls-parser 0.12`，实现 01 seam 的 TLS 解析：从 TCP payload 识别 TLS handshake ClientHello，用 `parse_tls_extension_sni` 提取 SNI，用 `parse_tls_extension_encrypted_server_name` 检测 ECH。ECH 或无 SNI 返回 None（走 NoDomain）。

**Blocked by:** 01

**Status:** done

- [x] Cargo.toml 加 `tls-parser 0.12`
- [x] 识别 TLS 记录 ContentType=Handshake(22) + ClientHello(0x01)
- [x] 提取 SNI（parse_tls_extension_sni）
- [x] 检测 ECH extension，存在时返回 None（加密，走 NoDomain）
- [x] 非 ClientHello / ApplicationData / 无 SNI / 解析错误返回 None
- [x] 测试：含 SNI 的 ClientHello、无 SNI、含 ECH、ApplicationData、残缺字节

## Comments
