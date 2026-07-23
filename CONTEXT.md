# Delray 流量分析

Delray 观测网络接口上的流量，并区分流量是否能归属到具体进程。

## Language

**未归属流量（Unattributed Traffic）**：
已捕获，但在观测时无法关联到唯一具体进程 ID 的流量。没有候选进程或存在多个候选进程都属于未归属流量。该术语不假定流量必然来自某个用户进程。
_Avoid_：未知进程、其他进程流量

**支持平台（Supported Platform）**：
经过原生环境构建、核心功能和基本稳定性验证，Delray 明确承诺可用的操作系统与 CPU 架构组合。目前包括 Linux `x86_64` 和 Windows `x86_64`。支持平台不表示所有边界场景都已完成穷尽测试；已知限制和运行前置条件必须在发布文档中说明。

**目标平台（Target Platform）**：
计划支持但尚未完成最低原生环境验收的操作系统与 CPU 架构组合。目标平台不应作为正式支持平台发布，除非完成对应验收并更新领域词汇。

**可移植架构（Portable Architecture）**：
允许为不同操作系统提供实现的系统结构。可移植架构不表示相关操作系统已经成为支持平台；macOS 当前只作为架构兼容性考虑，不承诺可用。
_Avoid_：用「跨平台支持」同时指代架构可扩展性和产品可用性承诺

**进程归属可用性（Process Attribution Usability）**：
在支持平台上，常见的 TCP、UDP、IPv4 和 IPv6 流量能够关联到正确进程。无法识别的部分可以计入未归属流量，但进程统计不能整体失效；不同支持平台不要求达到完全相同的归属率。

**进程显示名（Process Display Name）**：
用于 TUI、plain 和 JSON 输出的稳定可执行文件名。进程显示名不是完整命令行，也不包含可执行文件路径。

**进程统计身份（Process Statistical Identity）**：
进程流量累计所使用的身份。路径可用时由进程 ID 和可执行文件路径共同确定；相同进程 ID 对应不同路径时视为不同身份，不合并历史流量。路径不可用时只能使用进程 ID，并接受无法识别进程 ID 复用的限制。

**进程详情（Process Details）**：
所选进程的身份和流量信息，包括进程显示名、进程 ID、可执行文件路径、接收流量、发送流量和总流量。可执行文件路径不在 TUI 概览或进程列表中展示，但可以出现在 TUI 详情、plain 和 JSON 进程记录中；未归属流量没有可执行文件路径。

**详情新鲜度（Detail Freshness）**：
进程详情使用 `Last seen` 表示最近一次实际捕获并归属到该进程的流量时间。进程表刷新、路径变化和名称变化不更新该时间。进程离开当前 top-N 后保留最后一份数据和 `Last seen`，不自动退出详情页；状态文案必须说明跟踪停止或数据不再更新，不能暗示进程已经退出。

**用户可见文案（User-visible Copy）**：
TUI、plain、JSON 字段说明和状态提示统一使用英文；中文仅用于技术文档、研究记录和领域词汇说明。

**出站域名（Outbound Domain）**：
本机作为发起方建立的 TCP 连接中，通过 TLS SNI 或明文 HTTP Host 头识别出的目标域名。出站域名按连接双向累计流量，统计的是连接发起方为本机的通信。识别来源覆盖 TCP 上的 TLS ClientHello SNI 与明文 HTTP/1.x 请求的 Host 头；不覆盖 QUIC/HTTP3、入站发起的连接、ECH 加密的 SNI，以及解析失败的连接——这些流量不进入出站域名维度。出站域名不绑定进程，是与进程、IP 并列的独立统计维度。
_Avoid_：把它与反向 DNS 或 GeoIP 得到的主机名混用；后者来自外部数据库的 IP 归属查询，不是从流量 payload 解析，且 delray 不提供该能力

**调色板（Palette）**：
TUI 根据终端颜色能力选用的一组语义配色。Delray 定义三档：真彩色（24-bit RGB，默认）、16 色（ANSI 基色加 `Modifier`）、单色（仅 `Modifier`，无颜色）。档位在启动时按 `NO_COLOR`、`COLORTERM`、`TERM` 环境变量检测；用户也可在设置浮层中选择 `Auto`（沿用检测结果）或强制指定某档，选择仅本次会话生效、不持久化。同一组语义角色（如 inbound、outbound、accent）在三档下映射到不同具体颜色，但角色名不变。
_Avoid_：把「调色板」与具体 RGB 数值混用；调色板是「角色→颜色」的映射规则，RGB 值只是真彩色档下的实现

**正式版本（Stable Release Version）**：
由 `MAJOR.MINOR.PATCH` 组成、写入 Cargo 包元数据并对应唯一 Git tag 的版本。Delray 的每次 GitHub Release 都必须在当前版本基础上通过 `major`、`minor` 或 `patch` bump 产生新版本；版本号不包含 `beta`、`rc` 等预发布后缀。
_Avoid_：把 GitHub Release 的预发布状态编码进 Cargo 版本号或 Git tag

**草稿 Release（Draft Release）**：
由流水线创建、尚未公开发布的 GitHub Release。草稿可以由维护者补充或修改发布文案，并在确认后人工发布。

**预发布标记（Pre-release Flag）**：
GitHub Release 的发布状态（GitHub 界面中的 `pre-release` 选项），用于表明该正式版本尚未被视为稳定版本。预发布标记独立于 Cargo 版本号和 Git tag；同一正式版本只对应一个 Release，不通过 `beta.1`、`beta.2` 等后缀创建多个候选版本。
