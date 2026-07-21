# 06 — TUI Domains 页

**What to build:** TUI 新增 Domains 页（第 4 页，About 顺延第 5）；导航 1 Overview 2 Processes 3 IPs 4 Domains 5 About；表格列 Host/In/Out/Total/Last seen；复用 `--top-n`；无未归属行；导航/返回与 Processes/IPs 一致。

**Blocked by:** 05

**Status:** done

- [x] Page 枚举加 Domains（第 4），About 顺延第 5；`ALL` 数组与索引同步
- [x] 顶部 tab 渲染 1–5
- [x] `draw_domains`：表格 Host/In/Out/Total/Last seen
- [x] Last seen 相对时间（与进程详情一致）
- [x] 空状态文案
- [x] 测试：TestBackend 渲染、tab 导航、空状态、列内容

## Comments
