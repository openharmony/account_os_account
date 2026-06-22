# 执行计划

> 多任务编排和交接信息。

## 计划元数据

| 字段 | 内容 |
|------|------|
| 关联需求 | proposal.md |
| 关联设计 | design.md |
| 关联 Spec | spec.md |
| 复杂度 | 标准 |
| 状态 | Done |

## 交接信息

| 项 | 值 |
|----|-----|
| 上游产物 | proposal.md (Approved) + design.md (Approved) + spec.md (Approved) |
| 核心约束 | 分层调用合规、HandleAuthResult 仅 DOMAIN 提前返回、COMPANION_DEVICE 仅移除 UnlockUserScreen 跳过逻辑（EL3/EL4 解密），不触发 ActivateUserKey（EL2 不解密） |
| 不涉及项 | 性能/构建/国际化/数据迁移 |
| 外部依赖 | UserIam 框架需预先支持 CUSTOM 认证类型（不在本 spec 范围内）；SDK d.ts 类型声明在 interface_sdk-js 外仓（PR: https://gitcode.com/openharmony/interface_sdk-js/pull/33557） |

## Task 编排

| Task ID | 目标 | 受影响文件 | 依赖 | AC 覆盖 |
|---------|------|------------|------|---------|
| TASK-1 | 类型定义 + AuthTypeIndex 映射 + IPC 序列化 | account_iam_info.h、account_iam_client.cpp | 无 | AC-1.1, AC-1.2, AC-1.3 |
| TASK-2 | NAPI/Taihe 参数解析 | napi_account_iam_user_auth.cpp、napi_account_iam_common.h、ohos.account.osAccount.taihe、ohos.account.osAccount.impl.cpp | TASK-1 | AC-2.1, AC-2.2, AC-2.3 |
| TASK-3 | COMPANION_DEVICE 跳过逻辑移除（仅 UnlockUserScreen） + 解密流程确认 | account_iam_callback.cpp | TASK-1 | AC-3.1~AC-3.5, AC-4.1~AC-4.5 |
| TASK-4 | 单元测试 | test/ 目录 | TASK-1~3 | 全量 AC |
| TASK-5 | Fuzz 测试更新 | fuzz/ 目录 | TASK-4 | VM-1~VM-7 |

## 执行顺序

```
TASK-1 → TASK-2 (并行 TASK-3) → TASK-4 → TASK-5
```

## 验证命令

```bash
# 单元测试
./start.sh run -p rk3568 -t UT -tp os_account -ts OsAccountIAMTest

# Fuzz 测试
./start.sh run -p rk3568 -t UT -tp os_account -ts AccountIAMFuzzTest
```