# 需求文档

## 一、原始需求

### 基本信息

| 字段 | 内容 |
|------|------|
| 需求ID | REQ-20260528-001 |
| 需求名称 | 自定义认证类型与可信持有物认证用户空间解密支持 |
| 来源 | IAM 模块能力扩展 |
| 提出人 | Account 团队 |
| 目标发行版本 | OpenHarmony-6.0-Release |
| 候选 Profile | none |
| 优先级 | P0 |
| 状态 | Draft |

### 原始描述

**原始问题：** 当前 IAM 模块支持多种认证类型（PIN、FACE、FINGERPRINT 等），但缺少对"自定义认证"方式的支持。自定义认证是指用户通过自定义的认证方式（如智能卡、安全令牌、硬件密钥或其他第三方认证机制）来完成身份认证，并在认证成功后解锁系统。同时，COMPANION_DEVICE 认证成功后当前代码跳过了用户空间解密（EL3/EL4），导致可信持有物认证无法完整解锁用户存储空间。

**痛点：**

| 用户类型 | 当前痛点 | 影响 |
|----------|----------|------|
| 应用开发者 | 缺少 AuthType.CUSTOM 认证类型，无法集成自定义认证插件 | 无法支持智能卡/安全令牌等企业认证场景 |
| 系统开发者 | AuthOptions 不支持传递自定义认证的附加信息 | 自定义认证插件无法接收外部参数 |
| 最终用户 | COMPANION_DEVICE 认证成功后 EL3/EL4 不解密 | 可信持有物（如智能手表）认证后无法解锁 EL3/EL4（EL2 亦不解密） |

**期望结果：** 支持 AuthType.CUSTOM = 128 认证类型和 AuthOptions.additionalInfo 参数，CUSTOM 认证成功后完整解密用户空间（EL2-EL5），COMPANION_DEVICE 认证成功后解密 EL3/EL4（不含 EL2）。

### 背景证据

| 证据类型 | 链接/路径 | 说明 |
|----------|-----------|------|
| 源码分析 | account_iam_callback.cpp | 当前 UnlockUserScreen() 跳过 COMPANION_DEVICE，HandleAuthResult() 仅跳过 DOMAIN |
| 源码分析 | account_iam_info.h | AuthType/AuthTypeIndex/IAMAuthType 枚举定义 |
| 源码分析 | napi_account_iam_user_auth.cpp | NAPI 层参数解析逻辑 |

### 初始范围

**可能包含：**
- AuthType.CUSTOM = 128 枚举值
- AuthOptions.additionalInfo 可选字段
- NAPI/Taihe 层参数解析扩展
- CUSTOM 认证成功后用户空间解密（EL2-EL5）
- COMPANION_DEVICE 认证成功后移除 UnlockUserScreen 跳过逻辑（EL3/EL4 解密，EL2 不解密）

**明确不包含：**
- UserIam framework 侧的 CUSTOM 认证类型支持（由 UserIam 团队独立实现）
- 具体的自定义认证插件逻辑（由外部插件提供）
- 凭证管理（AddCredential/UpdateCredential）变更
- DOMAIN 认证类型的行为变更

### 初始假设

| 假设 | 类型 | 验证方式 | 状态 |
|------|------|----------|------|
| UserIam 框架已支持 AuthType.CUSTOM = 128 | 技术 | 源码确认 | 已验证 |
| HandleAuthResult() 仅对 DOMAIN 类型做提前返回，CUSTOM 自然进入解锁流程 | 技术 | 源码分析 account_iam_callback.cpp | 已验证 |
| COMPANION_DEVICE 跳过逻辑位于 UnlockUserScreen() 中 | 技术 | 源码分析 account_iam_callback.cpp:256 | 已验证 |
| additionalInfo 使用简单字符串即可满足初始需求 | 技术 | 方案评估 | 已验证 |

### 初始分级判断

| 判断项 | 结果 | 依据 |
|--------|------|------|
| 复杂度 | 标准 | 单仓多模块特性，涉及 NAPI/服务层/类型声明，有新 API |
| 涉及仓数量 | 1（os_account） | 所有变更在本仓内 |
| 是否涉及 Public/System API | 是 | AuthType.CUSTOM 枚举新增、AuthOptions.additionalInfo 字段新增 |
| 是否涉及安全/性能关键路径 | 是 | 认证成功后的用户空间解密属于安全关键路径 |
| 是否跨 SIG | 否 | 变均在 account 子系统内 |

### 进入澄清条件

- [x] 原始问题和期望结果已记录
- [x] 需求来源和责任人已明确
- [x] 初始范围和不包含项已记录
- [x] 关键假设和待澄清问题已列出
- [x] 复杂度有判断

---

## 二、澄清记录

### 待澄清问题

| 编号 | 问题 | 为什么需要澄清 | 状态 |
|------|------|----------------|------|
| Q-1 | AuthType.CUSTOM 的枚举值是否确定为 128？ | 需确认与现有枚举风格一致且无冲突 | 已澄清 — 128 是 2 的幂次，与现有风格一致，不与 DOMAIN=1024 冲突 |
| Q-2 | additionalInfo 的数据类型是否使用 string？ | 类型选择影响 NAPI 解析复杂度和扩展性 | 已澄清 — string 类型足够灵活，可传递 JSON 格式结构化数据 |
| Q-3 | CUSTOM 认证是否享有与 PIN 同级别的安全等级？ | 安全等级决定认证成功后的解密权限 | 已澄清 — 与 PIN 同级别，可完全解锁用户空间 |
| Q-4 | COMPANION_DEVICE 是否也应享有完整解密权限？ | 当前代码跳过 EL3/EL4 解密 | 已澄清 — 安全等级与 PIN 同级别，需移除 UnlockUserScreen 跳过逻辑；但 COMPANION_DEVICE 不在 CheckAllowUnlockUserStorage allowlist 中，不触发 ActivateUserKey（EL2 不解密） |
| Q-5 | HandleAuthResult() 是否需要新增 CUSTOM 特殊处理代码？ | 决定实现复杂度 | 已澄清 — 无需新增代码，现有逻辑已自动支持 |

### 讨论记录

| 日期 | 参与人 | 讨论主题 | 结论 | 后续动作 |
|------|--------|----------|------|----------|
| 2026-05-19 | Account 团队 | CUSTOM 认证安全等级与解密权限 | 与 PIN/FACE/FINGERPRINT 同级别，享有完整解密权限 | 无需新增特殊处理代码 |
| 2026-05-19 | Account 团队 | COMPANION_DEVICE 解密行为 | 移除 UnlockUserScreen() 中 COMPANION_DEVICE 的跳过逻辑（EL3/EL4 解密）；COMPANION_DEVICE 不在 ActivateUserKey allowlist 中（EL2 不解密） | 仅修改 UnlockUserScreen 条件判断 |
| 2026-05-19 | Account 团队 | additionalInfo 类型选择 | string 类型，可选参数，保证向后兼容 | NAPI 层使用 GetOptionalStringPropertyByKey 解析 |

### 功能范围确认

| 问题 | 回答 | 认人 | 状态 |
|------|------|--------|------|
| 核心功能包含哪些？ | AuthType.CUSTOM + AuthOptions.additionalInfo + CUSTOM/COMPANION_DEVICE 用户空间解密 | Account 团队 | 已确认 |
| 明确不包含哪些？ | UserIam 框架侧 CUSTOM 支持、认证插件逻辑、凭证管理变更、DOMAIN 行为变更 | Account 团队 | 已确认 |
| 是否有分期策略？ | 无分期，一次性交付 | Account 团队 | 已确认 |

### 方案探索

| 编号 | 方案概述 | 优势 | 风险/代价 | 选择结论 |
|------|----------|------|-----------|----------|
| A-1 | 在 HandleAuthResult() 中为 CUSTOM 新增显式分支处理 | 逻辑显式清晰 | 代码冗余，与现有流程不一致，维护成本增加 | 放弃 |
| A-2 | 依赖现有 HandleAuthResult() 逻辑（仅 DOMAIN 提前返回），CUSTOM 自然进入解锁流程 | 零新增代码、复用现有逻辑、与 PIN/FACE 流程一致 | 需确认 DOMAIN 是唯一跳过类型 | 推荐 |

**取舍理由：** 方案 A-2 零新增代码、完全复用现有解锁流程、与 PIN/FACE/FINGERPRINT 行为一致，是最小化实现。

### 子系统影响

| 问题 | 回答 | 确认人 | 状态 |
|------|------|--------|------|
| 涉及哪些子系统？ | account（os_account 仓） | Account 团队 | 已确认 |
| 是否需要新增子系统或部件？ | 否 | Account 团队 | 已确认 |

### API 变更评估

| 问题 | 回答 | 确认人 | 状态 |
|------|------|--------|------|
| 是否需要新增/修改 Public API？ | 是 — AuthType.CUSTOM 枚举值、AuthOptions.additionalInfo 可选字段 | Account 团队 | 已确认 |
| 是否需要新增 System API？ | 否 | Account 团队 | 已确认 |
| 是否会废弃已有 API？ | 否 | Account 团队 | 已确认 |
| 是否需要新增权限声明？ | 否 | Account 团队 | 已确认 |

### 兼容性与非功能需求

| 类别 | 核心问题 | 结论 | 确认人 | 状态 |
|------|----------|------|--------|------|
| 兼容性 | 向前/向后兼容要求？ | 所有新增字段为可选，向后兼容；无破坏性变更 | Account 团队 | 已确认 |
| 性能 | 无新增耗时路径 | N/A | Account 团队 | 已确认 |
| 安全 | 认证成功后解密权限 | CUSTOM 与 PIN 同级别（EL2-EL5）；COMPANION_DEVICE 仅 EL3/EL4 解密（EL2 不解密） | Account 团队 | 已确认 |
| 可靠性 | 解密失败重试 | 复用现有 20次×100ms 重试机制 | Account 团队 | 已确认 |

### 依赖与风险

| 依赖项 | 类型 | 说明 | 状态 |
|--------|------|------|------|
| useriam/user_auth_framework | 运行 | UserIam 框架需预先支持 CUSTOM 认证类型（不在本 spec 范围内） | 已确认 |
| storage_service | 运行 | 用户空间解密依赖 StorageManager 的 ActivateUserKey 和 UnlockUserScreen | 已确认 |

| 风险 | 类型 | 影响 | 缓解措施 | 状态 |
|------|------|------|----------|------|
| UserIam 框架不支持 CUSTOM 类型 | 外部 | 高 | 需在 UserIam 框架侧同步添加支持 | 已确认 |
| COMPANION_DEVICE 移除跳过逻辑后影响 RECOVERY_KEY | 技术 | 低 | 仅移除 COMPANION_DEVICE 条件，保留 RECOVERY_KEY 跳过逻辑 | 已确认 |
| CUSTOM 认证解密失败导致用户空间不可访问 | 技术 | 中 | 复用现有重试机制（20次×100ms），失败时返回明确错误 | 已确认 |
| additionalInfo 字符串格式不规范 | 技术 | 低 | 文档说明建议使用 JSON 格式 | 已确认 |

### AC 完整性

- [x] 每个用户故事有验收标准
- [x] AC 全部使用 WHEN/THEN 格式
- [x] 覆盖正常流程、异常流程、边界条件
- [x] AC 可测试、可度量

### 澄清结论

- [x] 功能范围已完全明确
- [x] 子系统影响已识别
- [x] API 变更已评估
- [x] 兼容性和非功能需求已确认
- [x] 依赖和风险已识别且有缓解方案
- [x] AC 完整可测试
- [x] 标准及以上复杂度已完成方案探索

**结论:** 通过

---

## 三、需求基线

### 基线信息

| 字段 | 内容 |
|------|------|
| 基线版本 | v1.0 |
| 基线日期 | 2026-05-28 |
| Owner | Account 团队 |
| 确认人 | Account 团队 |
| 复杂度 | 标准 |
| Profile | none |
| 目标发行版本 | OpenHarmony-6.0-Release |
| 版本状态 | proposed |

### 问题陈述

当前 IAM 模块缺少自定义认证类型（CUSTOM）支持，且 COMPANION_DEVICE 认证成功后跳过了 EL3/EL4 解密步骤，导致可信持有物认证无法完整解锁用户存储空间。需要在 AuthType 枚举中新增 CUSTOM = 128、扩展 AuthOptions 支持 additionalInfo 参数，并确保 CUSTOM 和 COMPANION_DEVICE 认证成功后执行完整的用户空间解密流程（EL2-EL5）。

### 目标和成功指标

| 目标 | 成功指标 | 验证方式 |
|------|----------|----------|
| 支持 CUSTOM 认证类型 | UserAuth.auth() 接受 authType = 128 并正常执行 | 单元测试 + 集成测试 |
| 支持 additionalInfo 参数 | AuthOptions.additionalInfo 可正确传递到认证流程 | 单元测试 |
| CUSTOM 认证成功后解锁 EL2-EL5 | ActivateUserKey + UnlockUserScreen 正常调用 | 单元测试 |
| COMPANION_DEVICE 认证成功后解锁 EL3/EL4（不含 EL2） | 移除跳过逻辑后 UnlockUserScreen 正常调用（EL2 不解密） | 单元测试 |

### 用户故事与 AC

| Story ID | 用户故事 | 优先级 |
|----------|----------|--------|
| US-1 | 作为应用开发者，我想要使用 AuthType.CUSTOM 进行认证，以便集成自定义认证插件 | P0 |
| US-2 | 作为应用开发者，我想要通过 AuthOptions.additionalInfo 传递附加信息，以便自定义认证插件接收外部参数 | P0 |
| US-3 | 作为最终用户，我想要 CUSTOM 认证成功后完整解锁用户空间，以便使用与 PIN 认证一致的解锁体验 | P0 |
| US-4 | 作为最终用户，我想要 COMPANION_DEVICE 认证成功后解锁 EL3/EL4（不含 EL2），以便可信持有物认证能解锁屏幕加密存储 | P0 |

| AC编号 | 验收标准 | 类型 | 关联Story |
|--------|----------|------|-----------|
| AC-1.1 | WHEN 应用调用 UserAuth.auth() 且 authType = 128 (CUSTOM) THEN 系统应接受认证类型并进入自定义认证流程 | 正常 | US-1 |
| AC-1.2 | WHEN 应用调用 UserAuth.getAvailableStatus() 且 authType = 128 (CUSTOM) THEN 系统应返回自定义认证能力的可用状态 | 正常 | US-1 |
| AC-1.3 | WHEN TypeScript 应用导入 osAccount 模块 THEN 编译器应识别 AuthType.CUSTOM 和 AuthOptions.additionalInfo 为有效类型 | 正常 | US-1 |
| AC-2.1 | WHEN 应用调用 UserAuth.auth() 且 options.additionalInfo 已设置 THEN 认证流程应接收到提供的附加信息 | 正常 | US-2 |
| AC-2.2 | WHEN 应用调用 UserAuth.auth() 且 options.additionalInfo 未设置 THEN 认证流程应正常执行不依赖附加信息 | 正常 | US-2 |
| AC-2.3 | WHEN NAPI 层接收 additionalInfo 为 undefined THEN 应视为未提供，使用默认值 | 边界 | US-2 |
| AC-3.1 | WHEN CUSTOM 认证成功且 token 和 secret 有效 THEN 系统应调用 ActivateUserKey() 激活用户密钥并解密 EL2 | 正常 | US-3 |
| AC-3.2 | WHEN CUSTOM 认证成功且屏幕锁定 THEN 系统应调用 UnlockUserScreen() 解密 EL3/EL4 | 正常 | US-3 |
| AC-3.3 | WHEN CUSTOM 认证成功且包含用户空间解锁 THEN 系统应设置 isVerified 和 isLoggedIn 为 true | 正常 | US-3 |
| AC-3.4 | WHEN CUSTOM 认证成功但 ActivateUserKey() 或 UnlockUserScreen() 失败 THEN 系统应重试最多 20 次（间隔 100ms），全部失败时返回错误且不设置 verified/logged-in 状态 | 异常 | US-3 |
| AC-3.5 | WHEN CUSTOM 认证成功但目标账户处于停用状态 THEN 系统不应执行用户空间解密并返回认证结果 | 边界 | US-3 |
| AC-4.1 | WHEN COMPANION_DEVICE 认证成功且 token 和 secret 有效 THEN 系统不应调用 ActivateUserKey()，EL2 存储不解密 | 边界 | US-4 |
| AC-4.2 | WHEN COMPANION_DEVICE 认证成功且屏幕锁定 THEN 系统应调用 UnlockUserScreen() 解密 EL3/EL4 | 正常 | US-4 |
| AC-4.3 | WHEN COMPANION_DEVICE 认证成功且包含用户空间解锁 THEN 系统应设置 isVerified 和 isLoggedIn 为 true | 正常 | US-4 |
| AC-4.4 | WHEN COMPANION_DEVICE 认证成功但解密操作失败 THEN 系统应重试最多 20 次（间隔 100ms），全部失败时返回错误且不设置 verified/logged-in 状态 | 异常 | US-4 |
| AC-4.5 | WHEN COMPANION_DEVICE 认证成功但目标账户处于停用状态 THEN 系统不应执行用户空间解密并返回认证结果 | 边界 | US-4 |

### 范围边界

**包含：** AuthType.CUSTOM = 128、AuthOptions.additionalInfo 可选字段、NAPI/Taihe 参数解析、CUSTOM 认证成功后用户空间解密（EL2-EL5）、COMPANION_DEVICE 认证成功后 UnlockUserScreen 跳过逻辑移除（EL3/EL4 解密，EL2 不解密）

**不包含：** UserIam 框架侧 CUSTOM 类型支持、自定义认证插件逻辑、凭证管理变更、DOMAIN 认证行为变更

### 影响范围

| 子系统 | 仓库 | 模块/路径 | 当前职责 | 影响类型 | Owner |
|--------|------|-----------|----------|----------|-------|
| account | os_account | frameworks/account_iam | NAPI 参数解析 | 修改 | Account 团队 |
| account | os_account | frameworks/ets/taihe | Taihe 静态 NAPI | 修改 | Account 团队 |
| account | os_account | interfaces/innerkits/account_iam | 内部 API 数据结构 | 修改 | Account 团队 |
| account | os_account | services/accountmgr/src/account_iam | 认证流程处理 | 修改 | Account 团队 |
| account | os_account | interfaces/kits/napi | NAPI 类型声明 | 修改 | Account 团队 |

### API 变更项清单

| API 名称 | 变更类型 | 开放范围 | 概要说明 |
|----------|----------|----------|----------|
| AuthType.CUSTOM (= 128) | 新增枚举值 | Public | 自定义认证类型枚举值 |
| AuthOptions.additionalInfo | 新增可选字段 | Public | 自定义认证附加信息参数 |

### 不涉及项确认

| 维度 | 涉及？ | 依据 | 若涉及，进入哪个下游文档 |
|------|--------|------|--------------------------|
| 性能 | 否 | 无新增耗时路径，复用现有流程 | N/A |
| 安全与权限 | 是 | 认证成功后解密权限属于安全关键路径 | design.md / spec.md |
| 兼容性 | 是 | 新增可选字段，需声明兼容性影响 | spec.md |
| API/SDK | 是 | 新增 Public API 枚举值和可选字段 | design.md / spec.md |
| IPC/跨进程 | 是 | AuthParam 序列化需扩展 additionalInfo | design.md |
| 构建与部件 | 否 | 无新增源文件或部件 | N/A |
| 国际化/无障碍 | 否 | 无 UI 相关变更 | N/A |
| 数据迁移 | 否 | 无存储格式变更 | N/A |

### 变更控制

| 变更类型 | 触发条件 | 处理规则 |
|----------|----------|----------|
| 范围新增 | 新增认证类型或解密流程 | 重新评估安全等级和设计影响 |
| AC 变更 | 修改可观察行为或错误码 | 重新审批基线和 Spec |
| API 变更 | 新增/修改 Public API | 触发设计审批 |
| 非功能指标变更 | 安全阈值变化 | 重新确认测试计划 |

### 进入设计/Spec 条件

- [x] 所有 P0/P1 用户故事有 AC
- [x] 每条 AC 可测试、可度量
- [x] 范围内/外已确认
- [x] manifest.target_release 已确认
- [x] manifest.profile 已确认（none）
- [x] 涉及仓、模块、SIG 已识别
- [x] 不涉及项已标记 N/A
- [x] 变更控制规则已确认

**基线结论:** 通过