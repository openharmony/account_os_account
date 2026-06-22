# Task 规格: COMPANION_DEVICE 跳过逻辑移除 + 解密流程确认

## Task 元数据

| 字段 | 内容 |
|------|------|
| Task ID | TASK-3 |
| 关联 AC | AC-3.1~AC-3.5, AC-4.1~AC-4.5 |
| 依赖 | TASK-1 完成 |
| 状态 | Done |

## 目标

移除 account_iam_callback.cpp 中 UnlockUserScreen() 函数对 COMPANION_DEVICE 的跳过条件（保留 RECOVERY_KEY 跳过逻辑），确认 HandleAuthResult() 对 CUSTOM 类型执行完整解锁流程（无需新增代码），，确认 COMPANION_DEVICE 不在 CheckAllowUnlockUserStorage allowlist 中（不触发 ActivateUserKey， EL2 不解密）。

## 受影响文件

| 文件 | 变更类型 | 变更说明 |
|------|----------|----------|
| services/accountmgr/src/account_iam/account_iam_callback.cpp | 修改 | UnlockUserScreen() 中移除 COMPANION_DEVICE 跳过条件：`if (authType_ == AuthType::RECOVERY_KEY || authType_ == AuthType::COMPANION_DEVICE)` → `if (authType_ == AuthType::RECOVERY_KEY)` |

## 不做范围

- 不修改 HandleAuthResult() 中 DOMAIN 提前返回逻辑
- 不修改 UnlockAccount() 内部流程
- 不新增 CUSTOM 类型的特殊处理分支

## 验证方式

- 源码确认 HandleAuthResult() 仅对 DOMAIN 做提前返回
- 单元测试覆盖 CUSTOM/COMPANION_DEVICE 解密流程

## AC 验证映射

| AC | 验证重点 |
|----|----------|
| AC-3.1 | CUSTOM 认证成功后 ActivateUserKey() 被调用 |
| AC-3.2 | CUSTOM 认证成功后 UnlockUserScreen() 被调用（不被跳过） |
| AC-3.3 | CUSTOM 认证成功后 isVerified/isLoggedIn 设为 true |
| AC-3.4 | 解密失败时重试 20 次×100ms，全部失败返回错误 |
| AC-3.5 | 账户停用时不执行解密 |
| AC-4.1 | COMPANION_DEVICE 认证成功后 ActivateUserKey() 不被调用（EL2 不解密） |
| AC-4.2 | COMPANION_DEVICE 认证成功后 UnlockUserScreen() 被调用（不被跳过） |
| AC-4.3 | COMPANION_DEVICE 认证成功后 isVerified/isLoggedIn 设为 true |
| AC-4.4 | 解密失败时重试 20 次×100ms，全部失败返回错误 |
| AC-4.5 | 账户停用时不执行解密 |