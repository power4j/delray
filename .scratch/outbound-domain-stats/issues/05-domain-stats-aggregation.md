# 05 — 出站域名统计聚合

**What to build:** 在 stats 聚合层新增出站域名维度：从带 `domain` 的 Flow 累计（按域名双向 in/out 字节 + Last seen）；top-N 排序复用 `--top-n`；未识别（domain=None）不进维度；Last seen 规则与进程一致（只在实际捕获并归属的流量时更新）。

**Blocked by:** 02, 03, 04

**Status:** done

- [x] 出站域名快照类型：host / in_bytes / out_bytes / total_bytes / last_seen
- [x] 聚合：domain=Some 的 Flow 按域名累计双向字节 + 更新 last_seen
- [x] domain=None 不进维度（不设未归属域名）
- [x] top-N 排序复用 `--top-n`
- [x] 测试：双向累计、top-N、未识别不进、Last seen 规则、守恒边界（不与接口总量守恒，只含已识别子集）

## Comments
