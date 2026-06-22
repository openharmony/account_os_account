# 特性规格

> 固化用户可见行为和验收标准。

## 概述

| 属性 | 值 |
|------|-----|
| 特性名称 | Custom Auth Type & Companion Device Unlock Support |
| 特性编号 | FEAT-20260528-001 |
| 所属 Epic | 无 |
| 优先级 | P0 |
| 目标版本 | OpenHarmony-6.0-Release |
| SIG 归属 | SIG_Account |
| 状态 | Approved |
| 复杂度 | 标准 |

## 本次变更范围（Delta）

| 类型 | 内容 | 说明 |
|------|------|------|
| ADDED | AuthType.CUSTOM = 128 枚举值 | Public API 新增枚举值 |
| ADDED | AuthOptions.additionalInfo 可选 string 字段 | Public API 新增可选字段 |
| ADDED | AuthTypeIndex.CUSTOM = 7 内部映射 | InnerAPI 新增映射 |
| ADDED | CUSTOM 认证成功后用户空间解密（EL2-EL5） | 安全关键行为新增 |
| MODIFIED | COMPANION_DEVICE 认证成功后 UnlockUserScreen 跳过逻辑移除 | 修改现有条件判断，COMPANION_DEVICE 不再跳过 EL3/EL4 解密，但仍不触发 ActivateUserKey（EL2 不解密） |
| ADDED | NAPI 层 additionalInfo 参数解析（ParseContextForAuthOptions） | NAPI 层新增 additionalInfo 解析逻辑 |
| ADDED | @ohos.account.osAccount.d.ts 类型声明 | Public API TypeScript 类型声明更新（外部仓库 interface_sdk-js） |
| ADDED | ohos.account.osAccount.taihe IDL 类型定义 | Taihe IDL 新增 AuthType.CUSTOM = 128 和 AuthOptions.additionalInfo: Optional<String> |
| ADDED | ConvertToAuthOptionsInner() additionalInfo 转换 | Taihe 实现层新增 additionalInfo 转换逻辑 |

## 输入文档

| 文档 | 路径 | 状态 |
|------|------|------|
| Requirement | proposal.md | Approved |
| Design | design.md | Draft |

## 用户故事

### US-1: 使用 CUSTOM 认证类型进行认证

**作为** 应用开发者,
**我想要** 使用 AuthType.CUSTOM = 128 进行身份认证,
**以便** 集成自定义认证插件（如智能卡、安全令牌、硬件密钥等）。

**验收标准：**

- **AC-1.1 [NEW]:** WHEN 应用调用 `UserAuth.auth()` 且 `authType = 128` (CUSTOM) THEN 系统应接受认证类型并进入自定义认证流程
- **AC-1.2 [NEW]:** WHEN 应用调用 `UserAuth.getAvailableStatus()` 且 `authType = 128` (CUSTOM) THEN 系统应返回自定义认证能力的可用状态
- **AC-1.3 [NEW]:** WHEN TypeScript 应用导入 osAccount 模块 THEN 编译器应识别 `AuthType.CUSTOM` 和 `AuthOptions.additionalInfo` 为有效类型（由外部 PR [interface_sdk-js#33557](https://gitcode.com/openharmony/interface_sdk-js/pull/33557) 实现）

### US-2: 传递自定义认证附加信息

**作为** 应用开发者,
**我想要** 通过 AuthOptions.additionalInfo 传递附加信息到认证流程,
**以便** 自定义认证插件能接收外部参数。

**验收标准：**

- **AC-2.1 [NEW]:** WHEN 应用调用 `UserAuth.auth()` 且 `options.additionalInfo` 已设置 THEN 认证流程应接收到提供的附加信息
- **AC-2.2 [EXISTING+NEW]:** WHEN 应用调用 `UserAuth.auth()` 且 `options.additionalInfo` 未设置 THEN 认证流程应正常执行，不依赖附加信息
- **AC-2.3 [NEW]:** WHEN NAPI 层接收 `additionalInfo` 为 `undefined` THEN 应视为未提供，使用默认值

### US-3: CUSTOM 认证成功后解锁用户空间

**作为** 最终用户,
**我想要** CUSTOM 认证成功后系统完整解锁用户空间（EL2-EL5）,
**以便** 获得与 PIN/FACE/FINGERPRINT 认证一致的解锁体验。

**验收标准：**

- **AC-3.1 [NEW]:** WHEN CUSTOM 认证成功且 token 和 secret 有效 THEN 系统应调用 `ActivateUserKey()` 激活用户密钥并解密 EL2 存储
- **AC-3.2 [EXISTING]:** WHEN CUSTOM 认证成功且屏幕锁定 THEN 系统应调用 `UnlockUserScreen()` 解密 EL3/EL4 加密文件
- **AC-3.3 [EXISTING]:** WHEN CUSTOM 认证成功且包含用户空间解锁 THEN 系统应设置 OS 账户的 `isVerified` 和 `isLoggedIn` 状态为 true
- **AC-3.4 [EXISTING]:** WHEN CUSTOM 认证成功但 `ActivateUserKey()` 或 `UnlockUserScreen()` 失败 THEN 系统应重试最多 20 次（间隔 100ms），全部失败时返回错误且不设置 verified/logged-in 状态
- **AC-3.5 [EXISTING]:** WHEN CUSTOM 认证成功但目标账户处于停用（deactivating）状态 THEN 系统不应执行用户空间解密，并返回认证结果而不修改存储状态

### US-4: COMPANION_DEVICE 认证成功后解锁用户空间

**作为** 最终用户,
**我想要** COMPANION_DEVICE 认证成功后系统完整解锁用户空间（含 EL3/EL4）,
**以便** 可信持有物（如智能手表、安全密钥）认证能完全解锁设备。

**验收标准：**

- **AC-4.1 [EXISTING]:** WHEN COMPANION_DEVICE 认证成功且 token 和 secret 有效 THEN 系统不应调用 `ActivateUserKey()`，EL2 存储不解密（COMPANION_DEVICE 不在 CheckAllowUnlockUserStorage allowlist 中）
- **AC-4.2 [NEW]:** WHEN COMPANION_DEVICE 认证成功且屏幕锁定 THEN 系统应调用 `UnlockUserScreen()` 解密 EL3/EL4 加密文件
- **AC-4.3 [EXISTING+NEW]:** WHEN COMPANION_DEVICE 认证成功且包含用户空间解锁 THEN 系统应设置 OS 账户的 `isVerified` 和 `isLoggedIn` 状态为 true
- **AC-4.4 [EXISTING+NEW]:** WHEN COMPANION_DEVICE 认证成功但 `UnlockUserScreen()` 失败 THEN 系统应重试最多 20 次（间隔 100ms），全部失败时返回错误且不设置 verified/logged-in 状态
- **AC-4.5 [EXISTING]:** WHEN COMPANION_DEVICE 认证成功但目标账户处于停用（deactivating）状态 THEN 系统不应执行用户空间解密，并返回认证结果而不修改存储状态

### US-5: NAPI 层解析 additionalInfo 参数

**作为** 框架开发者,
**我想要** NAPI 层正确解析 AuthOptions 中的 additionalInfo 参数,
**以便** 认证流程能接收来自 JavaScript 的附加信息。

**验收标准：**

- **AC-5.1 [NEW]:** WHEN NAPI 层接收 JavaScript authOptions 对象且 `additionalInfo` 为有效字符串 THEN ParseContextForAuthOptions 应将 additionalInfo 解析为有效字符串并设置 `hasAdditionalInfo = true`
- **AC-5.2 [NEW]:** WHEN NAPI 层接收 JavaScript authOptions 对象且 `additionalInfo` 为 undefined 或未设置 THEN ParseContextForAuthOptions 应视为未提供，设置 `hasAdditionalInfo = false`

> AC-5.1/5.2 与 AC-2.1/2.2/2.3 互补：AC-2 系描述认证流程的行为结果，AC-5 系描述 NAPI 层的解析机制。

### US-6: TypeScript 类型声明

**作为** 应用开发者,
**我想要** @ohos.account.osAccount.d.ts 包含 AuthType.CUSTOM 和 AuthOptions.additionalInfo 类型声明,
**以便** TypeScript 编译器能正确识别和校验这些类型。

**验收标准：**

- **AC-6.1 [NEW]:** WHEN @ohos.account.osAccount.d.ts 文件更新后 THEN 应包含 `AuthType.CUSTOM = 128` 枚举值声明（由外部 PR [interface_sdk-js#33557](https://gitcode.com/openharmony/interface_sdk-js/pull/33557) 实现）
- **AC-6.2 [NEW]:** WHEN @ohos.account.osAccount.d.ts 文件更新后 THEN 应包含 `AuthOptions.additionalInfo?: string` 可选字段声明（由外部 PR [interface_sdk-js#33557](https://gitcode.com/openharmony/interface_sdk-js/pull/33557) 实现）

> AC-6.1/6.2 与 AC-1.3 互补：AC-1.3 系描述编译器行为结果，AC-6 系描述 .d.ts 文件的具体声明要求。.d.ts 文件位于外部仓库 interface_sdk-js。

### US-7: Taihe IDL 类型定义与参数转换

**作为** 框架开发者,
**我想要** Taihe IDL 和实现层支持 AuthType.CUSTOM 和 AuthOptions.additionalInfo,
**以便** Taihe（静态 NAPI）通道能正确传递类型和参数到原生认证流程。

**验收标准：**

- **AC-7.1 [NEW]:** WHEN ohos.account.osAccount.taihe IDL 文件更新后 THEN AuthType 枚举应包含 `CUSTOM = 128` 值
- **AC-7.2 [NEW]:** WHEN ohos.account.osAccount.taihe IDL 文件更新后 THEN AuthOptions 结构体应包含 `additionalInfo: Optional<String>` 字段
- **AC-7.3 [NEW]:** WHEN Taihe 层接收 AuthOptions 且 `additionalInfo` 有值 THEN ConvertToAuthOptionsInner() 应设置 `hasAdditionalInfo = true` 并将 additionalInfo 转换为原生 `std::string`
- **AC-7.4 [EXISTING+NEW]:** WHEN Taihe 层接收 AuthOptions 且 `additionalInfo` 无 Optional 值 THEN ConvertToAuthOptionsInner() 应设置 `hasAdditionalInfo = false`，additionalInfo 保持默认空字符串

## 验收追溯

| AC | 来源 | 关联规则 | 关联 Task | 验证方式 | 证据 |
|----|------|----------|-----------|----------|------|
| AC-1.1 | NEW | BR-1 | TASK-1 | 单测 | `AccountIAMInfo_AuthType_CUSTOM_0100` |
| AC-1.2 | NEW | BR-1 | TASK-1 | 无需验证，由 XTS 验证 | `_test` |
| AC-1.3 | NEW | BR-1 | TASK-1 | 编译验证（外部 PR interface_sdk-js#33557） | `_test` |
| AC-2.1 | NEW | FR-1 | TASK-2 | 单测 | `AccountIAMInfo_AuthParam_Marshalling_WithAdditionalInfo_0100, AccountIAMInfo_AuthOptions_AdditionalInfo_0100, AccountIAMInfo_CredentialParametersIam_WithAdditionalInfo_0100` |
| AC-2.2 | EXISTING+NEW | FR-1 | TASK-2 | 单测 | `AccountIAMInfo_AuthParam_Marshalling_NoAdditionalInfo_0100, AccountIAMInfo_AuthOptions_AdditionalInfo_0100` |
| AC-2.3 | NEW | EX-1 | TASK-2 | 无需验证，由 XTS 验证 | `_test` |
| AC-3.1 | NEW | FR-2, BR-2 | TASK-3 | 单测 | `AuthCallback_UnlockAccount_CustomAuth_0100` |
| AC-3.2 | EXISTING | FR-2, BR-2 | TASK-3 | 单测 | `AuthCallback_UnlockUserScreen_CustomAuth_0100` |
| AC-3.3 | EXISTING | FR-2 | TASK-3 | 单测 | `AuthCallback_OnResult_CustomAuth_0100` |
| AC-3.4 | EXISTING | EX-2, RC-1 | TASK-3 | 无需验证，由 XTS 验证 | `_test` |
| AC-3.5 | EXISTING | FR-3 | TASK-3 | 单测 | `AuthCallback_OnResult_CustomAuth_Deactivating_0100` |
| AC-4.1 | EXISTING | FR-4, BR-3 | TASK-3 | 单测 | `AuthCallback_UnlockAccount_CompanionDevice_0100` |
| AC-4.2 | NEW | FR-4, BR-3 | TASK-3 | 单测 | `AuthCallback_UnlockUserScreen_CompanionDevice_0100, AuthCallback_UnlockUserScreen_RecoveryKey_0100` |
| AC-4.3 | EXISTING+NEW | FR-4 | TASK-3 | 单测 | `AuthCallback_OnResult_CompanionDevice_0100` |
| AC-4.4 | EXISTING+NEW | EX-3, RC-2 | TASK-3 | 无需验证，由 XTS 验证（UnlockUserScreen 重试为已有功能代码，仅需验证 COMPANION_DEVICE 能解锁 EL3/EL4，已由 AuthCallback_UnlockUserScreen_CompanionDevice_0100 覆盖） | `_test` |
| AC-4.5 | EXISTING | FR-5 | TASK-3 | 单测 | `AuthCallback_OnResult_CompanionDevice_Deactivating_0100` |
| AC-5.1 | NEW | FR-6 | TASK-2 | 无需验证，由 XTS 验证（NAPI 层无法通过单元测试覆盖） | `_test` |
| AC-5.2 | NEW | EX-1 | TASK-2 | 无需验证，由 XTS 验证（NAPI 层无法通过单元测试覆盖） | `_test` |
| AC-6.1 | NEW | BR-1 | TASK-1 | 编译验证（外部 PR interface_sdk-js#33557） | `_test` |
| AC-6.2 | NEW | BR-1 | TASK-1 | 编译验证（外部 PR interface_sdk-js#33557） | `_test` |
| AC-7.1 | NEW | BR-4 | TASK-2 | 编译验证 | `_test` |
| AC-7.2 | NEW | BR-4 | TASK-2 | 编译验证 | `_test` |
| AC-7.3 | NEW | FR-7 | TASK-2 | 无需验证，由 XTS 验证（Taihe 层无法通过单元测试覆盖） | `_test` |
| AC-7.4 | EXISTING+NEW | EX-4 | TASK-2 | 无需验证，由 XTS 验证（Taihe 层无法通过单元测试覆盖） | `_test` |

## 业务规则

| 编号 | 来源 | 规则描述 | 约束条件 | 关联 AC |
|------|------|----------|----------|---------|
| BR-1 | NEW | AuthType.CUSTOM = 128 是新增的合法认证类型枚举值 | 值为 2 的幂次（128），与现有风格一致，不与 DOMAIN=1024 冲突 | AC-1.1, AC-1.2, AC-1.3 |
| BR-2 | EXISTING+NEW | CUSTOM 认证安全等级与 PIN/FACE/FINGERPRINT 同级别，享有完整 EL2-EL5 解密权限 | HandleAuthResult() 仅对 DOMAIN 类型做提前返回（EXISTING），CUSTOM 类型自然进入 UnlockAccount() 流程（EXISTING）；CUSTOM 加入 CheckAllowUnlockUserStorage allowlist（NEW） | AC-3.1, AC-3.2, AC-3.3 |
| BR-3 | EXISTING+NEW | COMPANION_DEVICE 认证享有 EL3/EL4 解密权限（不含 EL2） | 移除 UnlockUserScreen() 中 COMPANION_DEVICE 的跳过条件（NEW），保留 RECOVERY_KEY 的跳过逻辑（EXISTING）；COMPANION_DEVICE 不在 CheckAllowUnlockUserStorage allowlist 中，不触发 ActivateUserKey（EXISTING） | AC-4.1, AC-4.2, AC-4.3 |
| BR-4 | NEW | Taihe IDL 与 .d.ts 类型定义需与 InnerAPI 保持一致 | AuthType.CUSTOM=128、AuthOptions.additionalInfo 在 Taihe IDL、NAPI .d.ts 和 InnerAPI 三层定义一致 | AC-5.1, AC-6.1, AC-6.2, AC-7.1, AC-7.2 |

## 功能规则

| 编号 | 来源 | 规则描述 | 触发条件 | 作用对象 | 关联 AC |
|------|------|----------|----------|----------|---------|
| FR-1 | NEW | additionalInfo 作为可选字符串参数，从 NAPI 层传递到认证流程 | 应用设置 options.additionalInfo | AuthOptions 结构体 | AC-2.1, AC-2.2 |
| FR-2 | EXISTING+NEW | CUSTOM 认证成功后执行 ActivateUserKey + UnlockUserScreen 完整解密流程 | authType_ != DOMAIN 且认证成功 | 用户密钥和加密存储 | AC-3.1, AC-3.2, AC-3.3 |
| FR-3 | EXISTING | 账户停用状态下不执行用户空间解密 | 目标账户为 deactivating 状态 | 存储解密流程 | AC-3.5 |
| FR-4 | EXISTING+NEW | COMPANION_DEVICE 认证成功后仅执行 UnlockUserScreen 解密流程（EL3/EL4），不执行 ActivateUserKey（EL2） | authType_ == COMPANION_DEVICE 且认证成功 | 用户加密存储（仅 EL3/EL4） | AC-4.1, AC-4.2 |
| FR-5 | EXISTING | COMPANION_DEVICE 认证成功但账户停用时不执行用户空间解密 | 目标账户为 deactivating 状态 | 存储解密流程 | AC-4.5 |
| FR-6 | NEW | NAPI 层 ParseContextForAuthOptions 解析 additionalInfo 字段 | NAPI 层接收 JavaScript authOptions 对象且 additionalInfo 有值 | AuthOptions 结构体 | AC-5.1 |
| FR-7 | NEW | Taihe 实现层 ConvertToAuthOptionsInner 转换 additionalInfo 到原生格式 | Taihe 层接收 AuthOptions 且 additionalInfo 有值 | 原生 AuthOptions 结构体 | AC-7.3 |

## 异常/豁免规则

| 编号 | 来源 | 异常码/枚举 | 规则描述 | 触发条件 | 超时阈值 | 处理结果 | 关联 AC |
|------|------|------------|----------|----------|----------|----------|---------|
| EX-1 | NEW | N/A | additionalInfo 为 undefined 时视为未提供 | NAPI 层接收 undefined additionalInfo | N/A | 使用默认值，正常执行 | AC-2.3 |
| EX-2 | EXISTING | ERR_OK != result | ActivateUserKey 或 UnlockUserScreen 失败时执行重试 | 认证成功但解密操作返回非 ERR_OK | 20次×100ms（总计 2s） | 全部失败时返回错误码，不设置 verified/logged-in | AC-3.4 |
| EX-3 | EXISTING+NEW | ERR_OK != result | COMPANION_DEVICE 认证成功但 UnlockUserScreen 失败时执行重试 | COMPANION_DEVICE 认证成功但 UnlockUserScreen 返回非 ERR_OK | 20次×100ms（总计 2s） | 全部失败时返回错误码，不设置 verified/logged-in | AC-4.4 |
| EX-4 | NEW | N/A | Taihe 层 additionalInfo 无 Optional 值时视为未提供 | ConvertToAuthOptionsInner 接收 additionalInfo 无 Optional 值 | N/A | hasAdditionalInfo 设为 false，additionalInfo 保持默认空字符串 | AC-7.4 |

## 恢复契约

| 编号 | 来源 | 触发条件 | 恢复策略 | 恢复结果 | 约束 |
|------|------|----------|----------|----------|------|
| RC-1 | EXISTING | CUSTOM 认证成功但解密操作失败 | 重试 20 次（间隔 100ms） | 成功时继续设置 verified/logged-in；全部失败时返回错误 | 总超时 2s |
| RC-2 | EXISTING+NEW | COMPANION_DEVICE 认证成功但 UnlockUserScreen 失败 | 重试 20 次（间隔 100ms） | 成功时继续设置 verified/logged-in；全部失败时返回错误 | 总超时 2s |

## 验证映射

| 编号 | 来源 | 对应规格项 | 验证方式 | 验证重点 | 证据 |
|------|------|------------|----------|----------|------|
| VM-1 | NEW | FR-1 / AC-2.1, AC-2.2, AC-2.3 | 单测 | additionalInfo 传递和默认值处理 | `AccountIAMInfo_AuthParam_Marshalling_WithAdditionalInfo_0100, AccountIAMInfo_AuthOptions_AdditionalInfo_0100` |
| VM-2 | EXISTING+NEW | BR-2 / AC-3.1, AC-3.2, AC-3.3 | 单测 | CUSTOM 认证成功后解密流程执行 | `AuthCallback_UnlockAccount_CustomAuth_0100, AuthCallback_UnlockUserScreen_CustomAuth_0100, AuthCallback_OnResult_CustomAuth_0100` |
| VM-3 | EXISTING | EX-2, RC-1 / AC-3.4 | 无需验证，由 XTS 验证 | 解密失败重试逻辑 | — |
| VM-4 | EXISTING | FR-3 / AC-3.5 | 单测 | 账户停用时不执行解密 | `AuthCallback_OnResult_CustomAuth_Deactivating_0100` |
| VM-5 | EXISTING+NEW | BR-3 / AC-4.1, AC-4.2 | 单测 | COMPANION_DEVICE 仅 UnlockUserScreen（EL3/EL4）解密，ActivateUserKey 不被调用 | `AuthCallback_UnlockAccount_CompanionDevice_0100, AuthCallback_UnlockUserScreen_CompanionDevice_0100` |
| VM-6 | EXISTING+NEW | EX-3, RC-2 / AC-4.4 | 无需验证，由 XTS 验证 | COMPANION_DEVICE 解密失败重试 | — |
| VM-7 | EXISTING | FR-5 / AC-4.5 | 单测 | 账户停用时不执行解密 | `AuthCallback_OnResult_CompanionDevice_Deactivating_0100` |
| VM-8 | NEW | FR-6, EX-1 / AC-5.1, AC-5.2 | 无需验证，由 XTS 验证 | NAPI 层 additionalInfo 解析与 undefined 处理 | — |
| VM-9 | NEW | BR-4, FR-7, EX-4 / AC-7.1, AC-7.2, AC-7.3, AC-7.4 | 编译验证（运行测试由 XTS 验证） | Taihe IDL 定义与 ConvertToAuthOptionsInner 转换 | — |

## API 变更分析

### 新增 API

| API 名称 | 开放范围 | 入参概要 | 返回值 | 错误码范围 | 功能描述 | 关联 AC |
|----------|----------|----------|--------|------------|----------|---------|
| `AuthType.CUSTOM` (= 128) | Public | N/A（枚举值） | N/A | N/A | 自定义认证类型枚举值 | AC-1.1, AC-1.2, AC-1.3 |
| `AuthOptions.additionalInfo?: string` | Public | string 类型，可选 | N/A（字段） | N/A | 自定义认证附加信息参数 | AC-2.1, AC-2.2, AC-2.3 |
| `ohos.account.osAccount.taihe` AuthType.CUSTOM / AuthOptions.additionalInfo | Public（Taihe IDL） | N/A | N/A | N/A | Taihe IDL 类型定义 | AC-7.1, AC-7.2 |
| `@ohos.account.osAccount.d.ts` AuthType.CUSTOM / AuthOptions.additionalInfo | Public（.d.ts） | N/A | N/A | N/A | TypeScript 类型声明（外部仓库 interface_sdk-js） | AC-6.1, AC-6.2 |

### 变更/废弃 API

| API 名称 | 变更类型 | 影响场景 | 迁移指引 | 关联 AC |
|----------|----------|----------|----------|---------|
| 无 | - | - | - | - |

## 兼容性声明

- **已有 API 行为变更:** 否。AuthType 枚举新增值不影响现有枚举值的行为；AuthOptions 新增可选字段不影响现有调用方
- **配置文件格式变更:** 否
- **数据存储格式变更:** 否
- **最低支持版本:** API Version 26.0.0
- **API 版本号策略:** 新增 API 标注 `@since` 版本号，通过 SysCap 声明能力
- **跨仓声明变更:** @ohos.account.osAccount.d.ts 需在 interface_sdk-js 仓库同步更新，标注 `@since API Version 26.0.0`（外部 PR [interface_sdk-js#33557](https://gitcode.com/openharmony/interface_sdk-js/pull/33557)）

## 架构约束

| 关键约束 | 约束说明 | 影响 AC |
|----------|----------|---------|
| 分层调用合规 | 应用→NAPI→InnerKit→服务→UserIam，禁止反向调用 | AC-1.1, AC-2.1 |
| IPC 序列化扩展 | AuthParam Marshalling/Unmarshalling 需扩展 additionalInfo 字段 | AC-2.1 |
| 认证回调处理 | HandleAuthResult() 仅对 DOMAIN 做提前返回，其他类型自然进入解锁流程 | AC-3.1, AC-3.2 |
| NAPI 参数解析扩展 | ParseContextForAuthOptions 需新增 additionalInfo 字段解析，使用 GetOptionalStringPropertyByKey | AC-5.1 |
| Taihe 参数转换扩展 | ConvertToAuthOptionsInner() 需处理 additionalInfo Optional<String> 到原生 hasAdditionalInfo + string 的映射 | AC-7.3, AC-7.4 |
| 跨仓类型一致性 | .d.ts（interface_sdk-js 仓）与 .taihe（本仓）AuthType/AuthOptions 定义需与 InnerAPI account_iam_info.h 保持一致 | AC-6.1, AC-6.2, AC-7.1, AC-7.2 |

## 非功能性需求

| 类型 | 指标/阈值 | 验证方式 | 证据 |
|------|-----------|----------|------|
| 安全 | CUSTOM/COMPANION_DEVICE 与 PIN 同级别解密权限 | 单测 | `_test` |
| 可靠性 | 解密失败重试机制（20次×100ms） | 单测 | `_test` |
| 问题定位 | 复用现有 hilog 日志（域 0xD001B00） | hilog | `_test` |

## 多设备适配声明

| 设备类型 | 行为差异 | 规格/约束 | 验证方式 | 证据 |
|----------|----------|-----------|----------|------|
| 手机 | 无差异 | 全功能支持 | 单测 | `_test` |
| 平板 | 无差异 | 全功能支持 | 单测 | `_test` |

## 全局特性影响

| 特性 | 适用？ | 结论 | 关联场景 |
|------|--------|------|----------|
| 无障碍 | 否 | 无 UI 变更 | N/A |
| 大字体 | 否 | 无 UI 变更 | N/A |
| 深色模式 | 否 | 无 UI 变更 | N/A |
| 多窗口/分屏 | 否 | 无 UI 变更 | N/A |
| 多用户 | 是 | CUSTOM/COMPANION_DEVICE 认证成功后设置 isVerified/isLoggedIn | AC-3.3, AC-4.3 |
| 版本升级 | 否 | 无数据迁移 | N/A |
| 生态兼容 | 是 | 新增可选字段，旧版本忽略 additionalInfo | AC-2.2 |

## 行为场景（可选，Gherkin）

```gherkin
Feature: Custom Auth Type & Companion Device Unlock
  作为应用开发者/最终用户
  我想要使用 CUSTOM 认证类型并支持完整用户空间解密
  以便集成自定义认证插件并获得与 PIN 认证一致的解锁体验

  Scenario: CUSTOM auth with additionalInfo
    Given 应用已配置自定义认证插件
    When 应用调用 UserAuth.auth() 且 authType = 128 且 options.additionalInfo = "Custom Data"
    Then 系统接受认证类型并传递附加信息到认证流程

  Scenario: CUSTOM auth without additionalInfo
    Given 应用已配置自定义认证插件
    When 应用调用 UserAuth.auth() 且 authType = 128 且不设置 options.additionalInfo
    Then 系统接受认证类型且认证流程正常执行

  Scenario: CUSTOM auth success unlocks EL2
    Given 自定义认证成功且 token 和 secret 有效
    When AuthCallback.OnResult() 处理认证结果
    Then 系统调用 ActivateUserKey() 解密 EL2 存储

  Scenario: CUSTOM auth success unlocks EL3/EL4
    Given 自定义认证成功且屏幕锁定
    When AuthCallback.OnResult() 处理认证结果
    Then 系统调用 UnlockUserScreen() 解密 EL3/EL4 存储

  Scenario: CUSTOM auth sets verified status
    Given 自定义认证成功且用户空间解锁完成
    Then OS 账户的 isVerified 和 isLoggedIn 状态为 true

  Scenario: CUSTOM auth unlock failure retries
    Given 自定义认证成功但 ActivateUserKey() 返回错误
    When 系统执行重试
    Then 最多重试 20 次间隔 100ms
    And 全部失败时返回错误且不设置 verified/logged-in

  Scenario: CUSTOM auth does not unlock deactivating account
    Given 自定义认证成功但目标账户处于停用状态
    Then 系统不执行用户空间解密
    And 系统返回认证结果而不修改存储状态

  Scenario: COMPANION_DEVICE auth success does NOT unlock EL2
    Given 可信持有物认证成功且 token 和 secret 有效
    When AuthCallback.OnResult() 处理认证结果
    Then 系统不调用 ActivateUserKey()
    And EL2 存储不被解密

  Scenario: COMPANION_DEVICE auth success unlocks EL3/EL4
    Given 可信持有物认证成功且屏幕锁定
    When AuthCallback.OnResult() 处理认证结果
    Then 系统调用 UnlockUserScreen() 解密 EL3/EL4 存储
    And 系统不跳过 UnlockUserScreen 流程

  Scenario: COMPANION_DEVICE auth unlock failure retries
    Given 可信持有物认证成功但 UnlockUserScreen() 返回错误
    When 系统执行重试
    Then 最多重试 20 次间隔 100ms
    And 全部失败时返回错误且不设置 verified/logged-in

  Scenario: NAPI parses valid additionalInfo
    Given NAPI 层接收 JavaScript authOptions 对象包含 additionalInfo
    When ParseContextForAuthOptions 解析参数
    Then additionalInfo 字段被解析为有效字符串
    And hasAdditionalInfo 设为 true

  Scenario: NAPI parses undefined additionalInfo
    Given NAPI 层接收 JavaScript authOptions 对象不含 additionalInfo 或值为 undefined
    When ParseContextForAuthOptions 解析参数
    Then additionalInfo 视为未提供
    And hasAdditionalInfo 设为 false

  Scenario: TypeScript type declaration includes CUSTOM and additionalInfo
    Given @ohos.account.osAccount.d.ts 文件已更新
    Then AuthType.CUSTOM = 128 被声明为有效枚举值
    And AuthOptions.additionalInfo?: string 被声明为有效可选字段

  Scenario: Taihe IDL defines CUSTOM and additionalInfo
    Given ohos.account.osAccount.taihe 已更新
    Then AuthType 枚举包含 CUSTOM = 128 值
    And AuthOptions 结构体包含 additionalInfo: Optional<String> 字段

  Scenario: Taihe converts additionalInfo to native format
    Given Taihe 层接收 AuthOptions 且 additionalInfo 有值
    When ConvertToAuthOptionsInner() 执行转换
    Then hasAdditionalInfo 设为 true 且 additionalInfo 转换为原生 std::string

  Scenario: Taihe converts additionalInfo when undefined
    Given Taihe 层接收 AuthOptions 且 additionalInfo 无 Optional 值
    When ConvertToAuthOptionsInner() 执行转换
    Then hasAdditionalInfo 设为 false 且 additionalInfo 保持默认空字符串
```

## Spec 自审清单

- [x] 无"待定""TBD""TODO"等占位符
- [x] 所有 AC 使用 WHEN/THEN 格式，可独立测试
- [x] 范围边界明确（做什么/不做什么清晰）
- [x] 无语义模糊表述
- [x] AC 与业务规则/异常规则/恢复契约交叉一致

## context-references

```yaml
context-queries:
  - repo: "openharmony/os_account"
    query: "account_iam_callback.cpp 中 HandleAuthResult() 和 UnlockUserScreen() 的完整实现逻辑，包括 DOMAIN 类型跳过条件和 COMPANION_DEVICE 跳过条件"
  - repo: "openharmony/os_account"
    query: "account_iam_info.h 中 AuthType、AuthTypeIndex、IAMAuthType 枚举定义，AuthOptions 结构体定义"
  - repo: "openharmony/os_account"
    query: "napi_account_iam_user_auth.cpp 中 ParseContextForAuthOptions 的参数解析逻辑"
  - repo: "openharmony/os_account"
    query: "ohos.account.osAccount.taihe 中 AuthType 枚举和 AuthOptions 结构体定义，包括 CUSTOM 值和 additionalInfo 字段"
  - repo: "openharmony/os_account"
    query: "ohos.account.osAccount.impl.cpp 中 ConvertToAuthOptionsInner() 的 additionalInfo 转换逻辑"
```

**关键文档：**
- AGENTS.md（本仓知识库）
- account_iam_callback.cpp（认证回调处理）
- account_iam_info.h（数据结构定义）
- napi_account_iam_user_auth.cpp（NAPI 参数解析）
- ohos.account.osAccount.taihe（Taihe IDL 类型定义）
- ohos.account.osAccount.impl.cpp（Taihe 实现层参数转换）
- @ohos.account.osAccount.d.ts（TypeScript 类型声明，外部仓库 interface_sdk-js）