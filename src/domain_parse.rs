use std::sync::Arc;

/// L7 域名解析器接口（capture 层的 trait seam）。
///
/// 实现方从 TCP payload（如 TLS ClientHello、明文 HTTP/1.x 请求）中提取目标域名。
/// capture 层只对出站方向且有 payload 的包调用此接口；解析结果通过
/// [`crate::capture::Flow::domain`] 透传到聚合层，原始 payload 不出 capture 层。
///
/// 具体的 TLS（02）/ HTTP（03）实现后续接入；本 trait 为它们预留稳定接口。
pub trait DomainParser: Send + Sync {
    /// 从 TCP payload 字节中解析目标域名；解析失败返回 `None`。
    fn parse_domain(&self, tcp_payload: &[u8]) -> Option<Arc<str>>;
}

/// 默认空实现：不做任何解析，总是返回 `None`。
///
/// 在 TLS/HTTP 解析（02/03）落地前作为 [`CaptureSource`] 的占位解析器使用。
///
/// [`CaptureSource`]: crate::capture::CaptureSource
pub struct NoopDomainParser;

impl DomainParser for NoopDomainParser {
    fn parse_domain(&self, _tcp_payload: &[u8]) -> Option<Arc<str>> {
        None
    }
}
