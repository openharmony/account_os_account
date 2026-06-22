# Task 规格: Fuzz 测试更新

## Task 元数据

| 字段 | 内容 |
|------|------|
| Task ID | TASK-5 |
| 关联 AC | VM-1~VM-7 |
| 依赖 | TASK-4 完成 |
| 状态 | Done |

## 目标

更新 auth_fuzzer.cpp 和 authuser_fuzzer.cpp，新增 additionalInfo 模糊测试数据生成和 CUSTOM 认证类型覆盖。

## 受影响文件

| 文件 | 变更类型 | 变更说明 |
|------|----------|----------|
| test/fuzztest/auth_fuzzer.cpp | 修改 | 新增 additionalInfo 模糊测试数据生成 |
| test/fuzztest/authuser_fuzzer.cpp | 修改 | 新增 CUSTOM 认证类型覆盖 |

## 不做范围

- 不新增 Fuzz 测试入口（仅修改已有）
- 不编写单元测试（TASK-4 负责）

## 验证方式

- Fuzz 测试编译通过且可运行