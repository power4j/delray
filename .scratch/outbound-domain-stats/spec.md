# 出站域名统计

Status: ready-for-agent — 库选型已定（见 `docs/local/research/2026-07-21-outbound-domain-rust-crates.md`），待 /to-tickets 拆票

## Problem Statement

delray 当前统计接口流量、进程和 IP 三个维度。运维在异常流量定位时还缺一个关键维度："这台机器正在访问哪些外部域名"——异常外连（被入侵后连 C2、异常数据外传）是服务器异常的主要形态，而域名是最直接的定位线索。

HTTP host / TLS SNI 在 2026-07-09 因三条理由砍出 v1：现代流量以 HTTPS 为主明文 Host 抓不到、SNI 仅出站可稳定取得入站要从证书反推、实现复杂度高。本轮推进它，聚焦价值最高、技术最干净的**出站视角**，绕开最硬的入站证书反推。

关键约束：delray 部署在资源受限服务器（1 CPU / 1G 内存），解析开销必须可控；payload 在数据层可得（snaplen 65535），但当前 Flow 抽取后丢弃 payload，管线需改造。

## Solution

delray 在 TCP 出站流量的连接级解析 TLS SNI（ClientHello）和明文 HTTP Host 头，建立 `连接(5-tuple) → 域名` 映射，按连接双向累计流量，作为与进程、IP 并列的独立 top-N 维度。解析在 capture 层对每个连接的首个有 payload 出站包做一次，结果通过 Flow 新增的 `domain` 字段传递到聚合层。连接映射用有界（上限 + 空闲超时 + LRU）流表维护，复用开源缓存库。

覆盖范围：TCP 上 TLS SNI + 明文 HTTP/1.x Host。不覆盖 QUIC/HTTP3、入站发起连接、ECH 加密 SNI、解析失败的连接——这些流量不进出站域名维度。

## User Stories

1. 作为运维人员，希望看到这台机器主动访问的外部域名 top-N，以便定位异常外连（C2、数据外传）。
2. 作为运维人员，希望明文 HTTP 流量（内网服务、云元数据、容器 registry、代理）也能识别 Host，以便覆盖非 HTTPS 出站。
3. 作为流量分析人员，希望域名流量按连接双向累计（含对端回包），以便看到与某域名的实际通信量而非仅请求字节。
4. 作为流量分析人员，希望出站域名是独立 top-N 维度、不绑定进程，以便先快速看"去了哪"，再对照进程 top-N 定位来源。
5. 作为流量分析人员，希望未识别的流量不进入域名维度，以便统计只含可信识别结果、不被误导。
6. 作为流量分析人员，希望 ECH 加密的流量不显示掩护域名，以免 top-N 被泛域名污染。
7. 作为交互式使用者，希望 TUI 有专门的 Domains 页，以便查看完整 top-N 域名排行。
8. 作为交互式使用者，希望 Overview 概览也能看到 top 域名预览，以便第一眼定位。
9. 作为交互式使用者，希望 Overview 布局工整（每行满宽或两列等宽），以便快速扫读。
10. 作为脚本编写者/离线分析者，希望 JSON/plane 输出含 top_hosts 段且 schema 稳定，以便程序解析。
11. 作为资源受限服务器使用者，希望流表有内存上限，以便 1G 服务器不因高并发连接爆内存。
12. 作为资源受限服务器使用者，希望域名解析开销可控，以便 1 CPU 上持续运行不受影响。
13. 作为使用者，希望域名解析默认开启、无需参数，以便开箱即用。
14. 作为运维人员，希望能用 `--flow-table` 调整流表大小，以便适应不同并发连接规模。
15. 作为项目维护者，希望 TLS/HTTP 解析和流表缓存都用成熟开源库，以便不重复造轮子并跟随协议演进。

## Implementation Decisions

- **出站视角**：只统计本机作为发起方建立的连接；不做入站证书反推。
- **协议覆盖**：TCP 上的 TLS ClientHello SNI + 明文 HTTP/1.x 请求 Host 头。不做 QUIC/HTTP3（UDP）——QUIC Initial 加密，复杂度单独够一轮。
- **ECH**：解析 ClientHello extensions 时检测 encrypted_server_name；ECH 流量标记 NoDomain、不进域名维度，避免掩护域名污染 top-N。
- **独立维度**：出站域名是与进程、IP 并列的 top-N 维度，不绑定进程（域名×进程交叉留作后续增量）。
- **连接级流表**：键为 5-tuple（本机 IP、本机端口、peer IP、peer端口、协议），值为域名。capture 层解析首包填表，后续包按连接查表累计。
- **双向统计**：已识别连接的双向流量（in + out）都归该域名。
- **不设未归属域名**：未识别流量不进出站域名维度；用户对照接口流量看识别比例。流表淘汰的连接后续流量同样不进维度。
- **解析位置**：capture 层对流表未命中连接的**首个有 payload 出站包**解析一次；Flow 扩展带 `domain: Option<Arc<str>>`，不传 raw payload（性能：避免每包传 2KB）。
- **解析失败**：TCP 顺序保证首包即应用层首包；首包解析失败则标记该连接 NoDomain，后续包不再试。
- **流表项状态**：Pending（首包未到）/ Resolved(域名) / NoDomain（首包解析失败或 ECH）。
- **流表边界**：默认上限 65536 条（~6MB）；新增 `--flow-table <N>` CLI 参数可调；空闲超时 5 分钟 + 表满 LRU 兜底；不做 TCP 状态追踪（FIN/RST），接受低概率 5-tuple 复用误归属。
- **缓存库**：用 `moka 0.12`（`default-features = false, features = ["sync"]`），原生提供 `max_capacity` + `time_to_idle`（对应空闲 5 分钟淘汰），sync 模式不引入 tokio/async runtime；不手写淘汰逻辑。
- **解析库**：TLS 用 `tls-parser 0.12`（唯一同时暴露 SNI 解析 `parse_tls_extension_sni` 和 ECH 检测 `parse_tls_extension_encrypted_server_name` 的现成库；rustls 不暴露原始 extensions 且引入 aws-lc-rs C 依赖，不选；etherparse 不解析 TLS 层）；HTTP/1.x 用 `httparse 1.10`（零依赖、原生处理 `Status::Partial`）；etherparse（已有）负责切到 TCP payload。
- **TUI 输出**：新增 Domains 页（第 4 页，About 顺延第 5）；复用 `--top-n`；列 `Host / In / Out / Total / Last seen`；无未归属行。
- **Overview 布局**：重排为行式——Wide/Standard 模式 `Traffic / [Process | Domain] / [Inbound IP | Outbound IP]`（两列等宽），Compact 模式 `Traffic / Process / Domain / Inbound IP`（单列堆叠）；新增 domain preview（Top Domains，按高度裁剪）。
- **plain/JSON 输出**：加 `top_hosts` 段，字段 `host / in_bytes / out_bytes / total_bytes / last_seen`；last_seen 在 JSON 用 RFC 3339、plain 用 ISO 8601、TUI 用相对时间（与进程/IP 维度一致）。
- **默认开启**：域名解析默认开启，不加开关参数。
- **术语**：CONTEXT.md 已定义"出站域名（Outbound Domain）"。

## Testing Decisions

- **解析 seam**：可注入 TCP payload 字节和 TLS/HTTP 标志，覆盖 TLS ClientHello 含 SNI、无 SNI、ECH extension 存在/不存在、HTTP/1.x 请求行+Host、部分请求、非 HTTP/TLS payload、空 payload。
- **流表 seam**：可注入时间和 5-tuple，覆盖首包填表、后续包查表累计、空闲超时淘汰、表满 LRU 淘汰、NoDomain 标记后不再解析、5-tuple 复用。
- **统计 seam**：从带 `domain` 的 Flow 到出站域名快照，覆盖双向累计、top-N 排序、未识别不进维度、Last seen 更新规则（与进程一致：只在实际捕获并归属的流量时更新）。
- **展示 seam**：ratatui TestBackend，覆盖 Domains 页渲染、Overview 三档模式（Wide/Standard/Compact）行式布局、domain preview、列与空状态、复用 `--top-n`。
- **守恒边界**：明确测试出站域名维度不与接口总流量守恒（只含已识别连接子集），不设未归属兜底。
- **性能**：复用现有持续运行测试基准，对比加域名解析后的 CPU/内存/句柄增量，确认 1CPU/1G 可接受。
- **回归**：继续运行现有 CLI、管线、进程归属、TUI 事件循环、输出测试，防止既有行为回归。
- **MSRV**：用 Rust 1.88 运行锁定依赖的 test / fmt / clippy / build。

## Out of Scope

- QUIC/HTTP3（UDP）SNI 解析——Initial 解密复杂，后续增量。
- 入站发起连接的域名识别（入站证书反推）。
- 出站域名绑定进程（域名×进程交叉表）——后续增量。
- 未归属域名兜底行。
- TCP 状态追踪（FIN/RST）与基于连接生命周期的清理。
- 反向 DNS、GeoIP、ASN 等 IP 归属查询（那是 sniffnet 式外部数据库查询，不是 payload 解析）。
- 域名归一化策略（大小写、trailing dot）作为产品决策——实现时取库给出的原始形式，不做额外归一。
- 域名黑名单、告警、分类、信誉。
- 可靠识别 pcap 启动前已建立连接的域名（pcap 半路加入的固有局限）。
- HTTP/2 明文（h2c）解析（罕见）。

## Further Notes

- 2026-07-09 砍的三条理由本轮如何收：明文 Host → 做出站明文 HTTP（内网/元数据/代理有价值）；SNI 入站 → 只做出站 ClientHello，不做证书反推；复杂度 → 连接级流表 + 开源库控制。
- 嗅探参考：sniffnet 只解析到 L4，不做 L7，**无可借鉴**；已记录于 `docs/local/research/2026-07-16-sniffnet-process-attribution.md`。
- 库选型：`docs/local/research/2026-07-21-outbound-domain-rust-crates.md`（已完成）。选定 tls-parser 0.12 + httparse 1.10 + moka 0.12 sync；三者无版本冲突、都不强制 async runtime。
- 内存预算：65536 条流表 × ~100 字节 ≈ 6MB，1G 服务器可接受。
- 性能预算：每连接解析一次（非每包），开销远小于 pcap 抓包和进程表刷新。
- 与跨平台架构的关系：Flow 扩展 `domain` 字段、capture 层 L7 嗅探是平台无关的（纯字节解析）；流表、缓存库跨平台通用。Linux/Windows 共享同一实现，不需要平台分支。
- 本规格应在下一阶段拆为阻塞关系明确的 tracer-bullet tickets。
