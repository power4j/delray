//! TLS ClientHello 域名解析器（02 票）。
//!
//! 从 TCP payload 识别 TLS handshake ClientHello，用 [`tls_parser`] 提取 SNI；
//! 检测 ECH（encrypted_server_name / encrypted_client_hello）extension，存在时
//! 返回 `None`（无法解密真实 SNI，走 NoDomain）。
//!
//! 04 票起由 [`CompositeDomainParser`] 在 TLS handshake ContentType 分支调用。
//!
//! [`CompositeDomainParser`]: crate::domain_parse_composite::CompositeDomainParser

use std::sync::Arc;

use tls_parser::{
    TlsExtension, TlsExtensionType, TlsMessage, TlsMessageHandshake, parse_tls_extensions,
    parse_tls_plaintext,
};

use crate::domain_parse::DomainParser;

/// RFC 9849 `encrypted_client_hello` extension type code。
///
/// tls-parser 0.12 只注册了 draft-ietf-tls-esni 的 [`DRAFT_ENCRYPTED_SERVER_NAME_TYPE`]
/// （0xFFCE），不识别 RFC 9849 的 0xFE0D；真实世界 ECH 流量（现代浏览器）使用
/// 0xFE0D，解析后落到 [`TlsExtension::Unknown`] 分支，需手动对照类型码。
const RFC9849_ECH_EXTENSION_TYPE: u16 = 0xFE0D;

/// draft-ietf-tls-esni 的 `encrypted_server_name` extension type code。
///
/// tls-parser 0.12 注册此码点并将其解析为 [`TlsExtension::EncryptedServerName`]。
/// 若 extension 数据残缺导致解析失败，整个 extensions 列表解析会失败（不回退为
/// `Unknown`），调用方得到 `None`——符合"解析错误返回 None"的规格。
const DRAFT_ENCRYPTED_SERVER_NAME_TYPE: u16 = 0xFFCE;

/// TLS ClientHello 的域名解析器。
///
/// 行为契约：
/// - 仅处理 TLS handshake ClientHello（ContentType=22, HandshakeType=0x01）；
/// - 检测到 ECH extension（`EncryptedServerName` 变体，或 `Unknown(0xFFCE)`，
///   或 `Unknown(0xFE0D)`）时返回 `None`，即使同时存在外层 SNI；
/// - 否则返回首个 `host_name` 类型的 SNI 条目；
/// - 非 ClientHello（ApplicationData 等）、无 SNI、解析错误、残缺字节返回 `None`。
pub struct TlsDomainParser;

impl TlsDomainParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TlsDomainParser {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainParser for TlsDomainParser {
    fn parse_domain(&self, tcp_payload: &[u8]) -> Option<Arc<str>> {
        let (_, record) = parse_tls_plaintext(tcp_payload).ok()?;

        let client_hello = record.msg.iter().find_map(|msg| match msg {
            TlsMessage::Handshake(TlsMessageHandshake::ClientHello(contents)) => Some(contents),
            _ => None,
        })?;

        let ext_bytes = client_hello.ext?;
        let (_, extensions) = parse_tls_extensions(ext_bytes).ok()?;

        if has_ech(&extensions) {
            return None;
        }

        extract_sni(&extensions)
    }
}

/// 是否含 ECH 相关 extension（draft `EncryptedServerName`、`Unknown(0xFFCE)`
/// 或 `Unknown(0xFE0D)`）。
fn has_ech(extensions: &[TlsExtension<'_>]) -> bool {
    extensions.iter().any(|ext| match ext {
        TlsExtension::EncryptedServerName { .. } => true,
        TlsExtension::Unknown(TlsExtensionType(t), _) => {
            *t == RFC9849_ECH_EXTENSION_TYPE || *t == DRAFT_ENCRYPTED_SERVER_NAME_TYPE
        }
        _ => false,
    })
}

/// 从 extensions 提取首个 `host_name` 类型的 SNI 条目；无效 UTF-8 跳过。
fn extract_sni(extensions: &[TlsExtension<'_>]) -> Option<Arc<str>> {
    for ext in extensions {
        if let TlsExtension::SNI(entries) = ext {
            for (name_type, name) in entries {
                if name_type.0 == 0
                    && let Ok(hostname) = std::str::from_utf8(name)
                {
                    return Some(Arc::from(hostname));
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── 成功路径 ────────────────────────────────────────────────────────

    #[test]
    fn parses_sni_from_client_hello_with_sni() {
        let record = tls_record_handshake(&client_hello_body(Some("example.com"), &[]));

        let domain = TlsDomainParser::new()
            .parse_domain(&record)
            .expect("应从 ClientHello 提取 SNI");
        assert_eq!(domain.as_ref(), "example.com");
    }

    #[test]
    fn parses_long_sni_from_client_hello() {
        let name = "very-long-subdomain.example.invalid";
        let record = tls_record_handshake(&client_hello_body(Some(name), &[]));

        let domain = TlsDomainParser::new()
            .parse_domain(&record)
            .expect("应提取较长的 SNI");
        assert_eq!(domain.as_ref(), name);
    }

    #[test]
    fn parses_sni_when_other_extensions_present() {
        let renegotiation = build_raw_extension(0xFF01, &[0x00]);
        let record =
            tls_record_handshake(&client_hello_body(Some("example.com"), &[renegotiation]));

        let domain = TlsDomainParser::new()
            .parse_domain(&record)
            .expect("应跳过非 SNI/ECH extension 并提取 SNI");
        assert_eq!(domain.as_ref(), "example.com");
    }

    // ── ECH 路径 ───────────────────────────────────────────────────────

    #[test]
    fn returns_none_for_draft_encrypted_server_name_extension() {
        let ech = build_raw_extension(0xFFCE, &valid_draft_ech_data());
        let record = tls_record_handshake(&client_hello_body(Some("cover.example"), &[ech]));

        assert!(TlsDomainParser::new().parse_domain(&record).is_none());
    }

    #[test]
    fn returns_none_for_rfc9849_ech_extension() {
        let ech = build_raw_extension(0xFE0D, &[0xDE, 0xAD, 0xBE, 0xEF]);
        let record = tls_record_handshake(&client_hello_body(Some("cover.example"), &[ech]));

        assert!(TlsDomainParser::new().parse_domain(&record).is_none());
    }

    #[test]
    fn ech_takes_precedence_over_sni() {
        // RFC 9849 §4: ECH 客户端应同时提供外层 SNI 作为掩护域名。
        // 本解析器必须在 ECH 存在时丢弃外层 SNI。
        let ech = build_raw_extension(0xFE0D, &[0x00, 0x01, 0x02]);
        let record = tls_record_handshake(&client_hello_body(Some("cover.example"), &[ech]));

        assert!(TlsDomainParser::new().parse_domain(&record).is_none());
    }

    // ── 失败路径 ───────────────────────────────────────────────────────

    #[test]
    fn returns_none_for_client_hello_without_extensions() {
        let record = tls_record_handshake(&client_hello_body(None, &[]));

        assert!(TlsDomainParser::new().parse_domain(&record).is_none());
    }

    #[test]
    fn returns_none_for_client_hello_with_extensions_but_no_sni() {
        let renegotiation = build_raw_extension(0xFF01, &[0x00]);
        let record = tls_record_handshake(&client_hello_body(None, &[renegotiation]));

        assert!(TlsDomainParser::new().parse_domain(&record).is_none());
    }

    #[test]
    fn returns_none_for_application_data_record() {
        let record = tls_record(0x17, &[0x01, 0x02, 0x03, 0x04]);

        assert!(TlsDomainParser::new().parse_domain(&record).is_none());
    }

    #[test]
    fn returns_none_for_alert_record() {
        let record = tls_record(0x15, &[0x01, 0x00]);

        assert!(TlsDomainParser::new().parse_domain(&record).is_none());
    }

    #[test]
    fn returns_none_for_empty_payload() {
        assert!(TlsDomainParser::new().parse_domain(&[]).is_none());
    }

    #[test]
    fn returns_none_for_truncated_record_header() {
        assert!(TlsDomainParser::new().parse_domain(&[0x16, 0x03]).is_none());
    }

    #[test]
    fn returns_none_for_truncated_handshake_body() {
        // Record header 声明 64 字节 payload，但只给 5 字节。
        let mut record = vec![0x16, 0x03, 0x01, 0x00, 0x40];
        record.extend_from_slice(&[0x01, 0x00, 0x00, 0x3F, 0x03]);

        assert!(TlsDomainParser::new().parse_domain(&record).is_none());
    }

    #[test]
    fn returns_none_for_non_tls_payload() {
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

        assert!(TlsDomainParser::new().parse_domain(payload).is_none());
    }

    #[test]
    fn returns_none_for_non_handshake_record_with_handshake_bytes_in_payload() {
        // ApplicationData record 的 payload 碰巧以 0x01 开头也不应被当成 ClientHello。
        let payload = [0x01, 0x00, 0x00, 0x10, 0x03, 0x03, 0x00, 0x00];
        let record = tls_record(0x17, &payload);

        assert!(TlsDomainParser::new().parse_domain(&record).is_none());
    }

    // ── Fixture 构造 ───────────────────────────────────────────────────
    //
    // 手工构造 TLS 记录字节，避免依赖外部 pcap 文件。所有 fixture 使用 TLS 1.2
    // ClientHello 骨架（TLS 1.3 的 SNI/ECH 字段位置一致）。

    /// 构造 TLS record：`content_type(1) | version(2) | length(2) | payload`。
    fn tls_record(content_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut record = Vec::with_capacity(5 + payload.len());
        record.push(content_type);
        record.extend_from_slice(&[0x03, 0x01]); // record version: TLS 1.0
        record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        record.extend_from_slice(payload);
        record
    }

    /// 构造 ContentType=Handshake(0x16) 的 TLS record，payload 为 handshake msg。
    fn tls_record_handshake(handshake_msg: &[u8]) -> Vec<u8> {
        tls_record(0x16, handshake_msg)
    }

    /// 构造 handshake 消息：`msg_type(1) | length(3) | body`。
    fn handshake_msg(msg_type: u8, body: &[u8]) -> Vec<u8> {
        let len = body.len() as u32;
        let mut msg = Vec::with_capacity(4 + body.len());
        msg.push(msg_type);
        msg.push((len >> 16) as u8);
        msg.push((len >> 8) as u8);
        msg.push(len as u8);
        msg.extend_from_slice(body);
        msg
    }

    /// 构造 ClientHello body（handshake type=0x01 的 payload），可选 SNI 和
    /// 额外 extensions。
    fn client_hello_body(sni: Option<&str>, extra_extensions: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        // version: TLS 1.2
        body.extend_from_slice(&[0x03, 0x03]);
        // random: 32 个零
        body.extend_from_slice(&[0u8; 32]);
        // session_id: 空
        body.push(0x00);
        // cipher_suites: 一个套件
        body.extend_from_slice(&[0x00, 0x02]); // length=2
        body.extend_from_slice(&[0x00, 0x2F]); // TLS_RSA_WITH_AES_128_CBC_SHA
        // compression_methods: null
        body.push(0x01); // length=1
        body.push(0x00); // null

        // 组装 extensions
        let mut extensions_buf = Vec::new();
        if let Some(name) = sni {
            extensions_buf.extend_from_slice(&sni_extension(name));
        }
        for ext in extra_extensions {
            extensions_buf.extend_from_slice(ext);
        }

        if !extensions_buf.is_empty() {
            body.extend_from_slice(&(extensions_buf.len() as u16).to_be_bytes());
            body.extend_from_slice(&extensions_buf);
        }

        // 包装成 handshake msg (type=0x01)
        handshake_msg(0x01, &body)
    }

    /// 构造 SNI extension（type=0x0000，单个 host_name 条目）。
    fn sni_extension(hostname: &str) -> Vec<u8> {
        let name = hostname.as_bytes();
        let name_len = name.len();
        let list_len = 1 + 2 + name_len; // name_type + name_length + name
        let ext_data_len = 2 + list_len; // server_name_list_length + list

        let mut ext = Vec::new();
        ext.extend_from_slice(&[0x00, 0x00]); // type: server_name
        ext.extend_from_slice(&(ext_data_len as u16).to_be_bytes());
        ext.extend_from_slice(&(list_len as u16).to_be_bytes()); // server_name_list_length
        ext.push(0x00); // name_type: host_name
        ext.extend_from_slice(&(name_len as u16).to_be_bytes());
        ext.extend_from_slice(name);
        ext
    }

    /// 构造任意 extension：`type(2) | length(2) | data`。
    fn build_raw_extension(ext_type: u16, data: &[u8]) -> Vec<u8> {
        let mut ext = Vec::with_capacity(4 + data.len());
        ext.extend_from_slice(&ext_type.to_be_bytes());
        ext.extend_from_slice(&(data.len() as u16).to_be_bytes());
        ext.extend_from_slice(data);
        ext
    }

    /// 构造合法的 draft-ietf-tls-esni EncryptedServerName 数据。
    ///
    /// 字段顺序（来自 tls-parser 源码 parse_tls_extension_encrypted_server_name）：
    /// ciphersuite(2) | group(2) | key_share<2+> | record_digest<2+> | encrypted_sni<2+>
    fn valid_draft_ech_data() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&[0x00, 0x01]); // ciphersuite
        data.extend_from_slice(&[0x00, 0x17]); // group: x25519
        data.extend_from_slice(&[0x00, 0x01, 0xAA]); // key_share: len=1
        data.extend_from_slice(&[0x00, 0x01, 0xBB]); // record_digest: len=1
        data.extend_from_slice(&[0x00, 0x01, 0xCC]); // encrypted_sni: len=1
        data
    }
}
