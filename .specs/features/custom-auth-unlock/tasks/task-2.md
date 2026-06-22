# Task 规格: NAPI/Taihe 参数解析

## Task 元数据

| 字段 | 内容 |
|------|------|
| Task ID | TASK-2 |
| 关联 AC | AC-2.1, AC-2.2, AC-2.3 |
| 依赖 | TASK-1 完成 |
| 状态 | Done |

## 目标

在 NAPI 层 ParseContextForAuthOptions 函数中新增 additionalInfo 解析逻辑（使用 GetOptionalStringPropertyByKey），在 Taihe IDL 中新增 CUSTOM = 128 枚举值和 AuthOptions.additionalInfo Optional<String> 字段，在 Taihe impl 中更新 ConvertToAuthOptionsInner() 函数支持 additionalInfo 转换。

## 受影响文件

| 文件 | 变更类型 | 变更说明 |
|------|----------|----------|
| interfaces/kits/napi/account_iam/src/napi_account_iam_user_auth.cpp | 修改 | ParseContextForAuthOptions 新增 additionalInfo 解析 |
| frameworks/ets/taihe/os_account/idl/ohos.account.osAccount.taihe | 修改 | AuthType 新增 CUSTOM = 128，AuthOptions 新增 additionalInfo Optional<String> |
| frameworks/ets/taihe/os_account/src/ohos.account.osAccount.impl.cpp | 修改 | ConvertToAuthOptionsInner() 新增 additionalInfo 转换 |

## 不做范围

- 不修改 InnerKit 数据结构（TASK-1 负责）
- 不修改服务层认证流程（TASK-3 负责）
- 不修改 account_iam_service.cpp 中 AuthUser 方法（TASK-1 已覆盖 IPC 序列化）

## 验证方式

- 编译通过
- 单元测试覆盖 additionalInfo 传递（有值/无值/undefined 三种场景）

## AC 验证映射

| AC | 验证重点 |
|----|----------|
| AC-2.1 | ParseContextForAuthOptions 解析 additionalInfo 有值时正确传递 |
| AC-2.2 | ParseContextForAuthOptions 解析 additionalInfo 缺失时使用默认值 |
| AC-2.3 | NAPI 层接收 undefined additionalInfo 时视为未提供 |