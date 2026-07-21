# 07 — Overview 行式布局重排 + domain preview

**What to build:** Overview `draw_overview` 重排为行式布局：Wide/Standard 模式 `Traffic / [Process | Domain] / [Inbound IP | Outbound IP]`（两列等宽 50/50）；Compact 模式 `Traffic / Process / Domain / Inbound IP`（单列堆叠）。新增 `draw_domain_preview` + `domain_table`（与 ip_preview 同构）。

**Blocked by:** 05

**Status:** done

- [x] Wide/Standard：Traffic（满宽）+ Process|Domain（两列）+ Inbound IP|Outbound IP（两列）
- [x] Compact：Traffic / Process / Domain / Inbound IP 单列堆叠
- [x] 新增 `draw_domain_preview` + `domain_table`（panel "Top Domains"，按高度裁剪）
- [x] 两列等宽，行间沿用 1 行 gap
- [x] LayoutMode 切档阈值不变
- [x] 测试：三档模式 TestBackend 渲染、domain preview、两列对齐、不回归现有 Overview 测试

## Comments
