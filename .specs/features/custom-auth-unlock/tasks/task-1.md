# Task 规格: 类型定义 + AuthTypeIndex 映射 + IPC 序列化

## Task 元数据

| 字段 | 内容 |
|------|------|
| Task ID | TASK-1 |
| 关联 AC | AC-1.1, AC-1.2, AC-1.3 |
| 依赖 | design.md + spec.md Approved |
| 状态 | Done |

## 目标

在类型定义层新增 AuthType.CUSTOM = 128、AuthTypeIndex.CUSTOM = 7，扩展 AuthOptions 结构体增加 additionalInfo 和 hasAdditionalInfo 字段，扩展 AuthParam IPC 序列化支持 additionalInfo 传递，并在 GetAuthTypeIndex() 中新增 CUSTOM 分支映射。

## 受影响文件

| 文件 | 变更类型 | 变更说明 |
|------|----------|----------|
| interfaces/innerkits/account_iam/native/include/account_iam_info.h | 修改 | 新增 CUSTOM = 128 到 AuthType 枚举，新增 CUSTOM = 7 到 AuthTypeIndex，新增 additionalInfo/hasAdditionalInfo 到 AuthOptions |
| interfaces/kits/napi/account_iam/include/napi_account_iam_common.h | 修改 | 新增 CUSTOM = 128 到 NAPI AuthType 映射 |
| services/accountmgr/src/account_iam/account_iam_client.cpp | 修改 | GetAuthTypeIndex() 新增 case AuthType::CUSTOM_AUTH |
| services/accountmgr/src/common/database/account_iam_info.cpp (Marshalling/Unmarshalling) | 修改 | AuthParam 序列化扩展 additionalInfo |

## 不做范围

- 不修改 HandleAuthResult() 或 UnlockAccount() 流程
- 不修改 NAPI 参数解析逻辑（TASK-2 负责）
- 不修改 Taihe IDL/impl（TASK-2 负责）

## 验证方式

- 编译通过
- 单元测试覆盖新增枚举值和 IPC 序列化

## AC 验证映射

| AC | 验证重点 |
|----|----------|
| AC-1.1 | AuthType.CUSTOM = 128 枚举值存在且 GetAuthTypeIndex(CUSTOM) 返回 7 |
| AC-1.2 | CUSTOM 类型在可用性检查流程中可被识别 |
| AC-1.3 | d.ts 中 AuthType.CUSTOM 和 AuthOptions.additionalInfo 类型声明完整 |