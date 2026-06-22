# Task 规格: 单元测试

## Task 元数据

| 字段 | 内容 |
|------|------|
| Task ID | TASK-4 |
| 关联 AC | 全量 AC |
| 依赖 | TASK-1~3 完成 |
| 状态 | Done |

## 目标

编写单元测试覆盖所有 AC：additionalInfo 数据结构、NAPI 参数解析（有值/无值/undefined）、Taihe 参数转换、AuthType.CUSTOM 可用性检查、GetAuthTypeIndex(CUSTOM) 映射、CUSTOM/COMPANION_DEVICE 认证成功后解密流程、解锁失败重试逻辑、账户停用状态。

## 受影响文件

| 文件 | 变更类型 | 变更说明 |
|------|----------|----------|
| services/accountmgr/test/unittest/ | 新增 | additionalInfo 数据结构测试 |
| services/accountmgr/test/unittest/ | 新增 | NAPI 参数解析测试 |
| services/accountmgr/test/unittest/ | 新增 | Taihe 参数转换测试 |
| services/accountmgr/test/unittest/ | 新增 | CUSTOM/COMPANION_DEVICE 解密流程测试 |

## 不做范围

- 不编写 Fuzz 测试（TASK-5 负责）
- 不编写集成测试（需联调环境）

## 验证方式

- 所有单元测试 PASS

## AC 验证映射

覆盖全量 16 条 AC 的单元测试验证。