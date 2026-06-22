# 规格化阶段 Gate 检查

## 入口检查

- [x] proposal.md 中 API 变更项清单已填写（AuthType.CUSTOM + AuthOptions.additionalInfo）
- [x] design.md 和 spec.md 引用的仓/模块列表与 proposal.md 影响范围一致

## 设计检查

- [x] 分层调用合规（应用→NAPI→InnerKit→服务→UserIam，禁止反向调用）
- [x] 无跨层违规调用
- [x] 子系统边界清晰（变均在 account 内，依赖 UserIam 通过 IPC 代理）
- [x] API 命名和参数符合 OH 规范
- [x] 错误码不与已有子系统冲突（无新增错误码）
- [x] 数据模型定义完整（AuthOptions.additionalInfo 字段扩展）
- [x] 构建系统影响已评估（无 BUILD.gn/bundle.json 变更）
- [x] 涉及 IPC/异步时超时已定义（重试 20次×100ms）
- [x] 涉及 Public API 变更时接口参数规约已填写（design.md）

## 一致性检查

- [x] 涉及仓和模块名称一致（os_account）
- [x] API 名称和变更类型一致（spec 列变更项，design 给签名细节）
- [x] 架构约束不矛盾（spec 声明约束要求，design 给满足方案）
- [x] 不涉及项结论一致（性能/构建/国际化/数据迁移均 N/A）

## Spec 检查

- [x] 用户故事和 AC 完整（4 US, 16 AC）
- [x] AC 覆盖正常/异常/边界
- [x] Spec 中无 InnerKit 接口定义、内部实现流程或框架层实现细节
- [x] API 变更分析完整（AuthType.CUSTOM + AuthOptions.additionalInfo）
- [x] 兼容性声明完整（所有新增可选，向后兼容）
- [x] 非功能需求有指标或明确 N/A
- [x] 全局特性影响已筛选
- [x] 上下文引用完整

## 出口检查

- [x] 用户批准 design.md 和 spec.md — 用户 2026-05-28 批准

**总结论:** Approved