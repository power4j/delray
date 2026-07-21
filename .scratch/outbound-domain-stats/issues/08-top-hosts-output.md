# 08 — plain/JSON top_hosts 输出

**What to build:** report 层加 top_hosts 段：plain 表格 `Host / In / Out / Total / Last Seen`（Last Seen 用 ISO 8601）；JSON `top_hosts` 数组 `[{host, in_bytes, out_bytes, total_bytes, last_seen}]`（last_seen 用 RFC 3339）；未归属不输出；空列表处理。

**Blocked by:** 05

**Status:** done

- [x] plain report 加 top_hosts 表（Host/In/Out/Total/Last Seen）
- [x] JSON schema：`top_hosts` 数组，字段 host/in_bytes/out_bytes/total_bytes/last_seen
- [x] last_seen：plain ISO 8601、JSON RFC 3339（与进程/IP 维度一致）
- [x] 空列表 / 无域名场景处理
- [x] 测试：plain 与 JSON 字段、空值、时间格式、与 top_processes/top_ips 同构

## Comments
