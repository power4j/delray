use std::sync::Arc;

/// L7 域名解析器接口（capture 层的 trait seam）。
///
/// 实现方从 TCP payload（如 TLS ClientHello、明文 HTTP/1.x 请求）中提取目标域名。
/// capture 层只对出站方向且有 payload 的包调用此接口；解析结果通过
/// [`crate::capture::Flow::domain`] 透传到聚合层，原始 payload 不出 capture 层。
///
/// 生产路径使用 [`CompositeDomainParser`]（04 票）；测试可注入实现此 trait 的
/// 自定义桩（如 `capture::tests::RecordingParser`）控制解析行为。
///
/// [`CompositeDomainParser`]: crate::domain_parse_composite::CompositeDomainParser
pub trait DomainParser: Send + Sync {
    /// 从 TCP payload 字节中解析目标域名；解析失败返回 `None`。
    fn parse_domain(&self, tcp_payload: &[u8]) -> Option<Arc<str>>;
}
