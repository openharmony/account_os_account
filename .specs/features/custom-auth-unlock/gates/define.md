# 定义阶段 Gate 检查

## Profile 判定

- [x] 已扫描 profiles 目录，确认可用 Profile 列表（arkweb/arkui/arkgraphic/arkdata）
- [x] 已根据仓路径（account/os_account）判定不命中任何 Profile
- [x] Profile = none，无追加规则

## 入口检查

- [x] 原始问题和期望结果已记录 — proposal.md 一、原始需求
- [x] 需求来源和责任人已明确 — Account 团队
- [x] 待澄清问题已逐项关闭（Q-1~Q-5 均已澄清）
- [x] 讨论记录包含需求方/Owner/SIG 的明确确认证据 — 用户 2026-05-28 明确回复"已确认"
- [x] 澄清结论全部适用项已勾选
- [x] 功能范围（包含/不包含）已确认
- [x] API 变更已评估（AuthType.CUSTOM + AuthOptions.additionalInfo）
- [x] 兼容性和非功能需求已确认
- [x] 依赖和风险已识别且有缓解方案

> **已确认：** 用户 2026-05-28 明确回复"已确认"，入口通过。

## 出口检查

- [x] 所有 P0/P1 用户故事有 AC（WHEN/THEN 格式） — US-1~US-4，共 16 条 AC
- [x] 每条 AC 可测试、可度量
- [x] manifest.target_release 已确认 — OpenHarmony-6.0-Release
- [x] manifest.profile 已确认 — none
- [x] 不涉及项已显式标记 N/A
- [x] manifest.baseline_approval.approved=true — 用户 2026-05-28 确认
- [x] gates/define.md 总结论为 通过/Approved — 用户 2026-05-28 确认

**总结论:** Approved