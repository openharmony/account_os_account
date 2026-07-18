# Feature Specification

> Solidifies user-visible behavior and acceptance criteria. Complex interactions, state machines, and exception flows may be supplemented with Gherkin scenarios.

## Overview

| Attribute | Value |
|------|-----|
| Feature name | Domain Account Unlock Capability Switch |
| Feature ID | FEAT-F2 |
| Parent Epic | EPIC-20260703-001 |
| Priority | P0 |
| Target version | TBD (reference manifest.target_release) |
| SIG ownership | SIG_Account |
| Status | Approved |
| Complexity | High |

## Scope of This Change (Delta)

| Type | Content | Description |
|------|------|------|
| ADDED | `AccountIAMClient::SetDomainAuthUnlockEnabled` InnerKit API | Enable/disable domain account authentication unlock per user |
| ADDED | `IAccountIAM.idl::SetDomainAuthUnlockEnabled` IDL method | IPC method |
| ADDED | `AccountIAMService::SetDomainAuthUnlockEnabled` stub | Permission check + delegation to inner manager |
| ADDED | `InnerAccountIAMManager::SetDomainAuthUnlockEnabled` business logic | uid check + parameter validation + storage key management |
| ADDED | `InnerDomainAccountManager::GetUnlockDeviceConfig` internal method | Service-internal query of domain account unlock configuration (not exposed externally, not via IPC) |
| MODIFIED | `AddCredCallback::OnResult` | Queries unlock configuration when adding a PIN, conditionally skips storage key addition |
| MODIFIED | `DelCredCallback`/`VerifyTokenCallbackWrapper` | Queries unlock configuration when deleting a PIN, conditionally skips storage key deletion |
| MODIFIED | `NeedSkipActiveUserKey` (`os_account_interface.cpp`) | New `IsEnableDomainUnlock` check: skips empty-secret `ActiveUserKey` when `IsExistPIN || IsEnableDomainUnlock` is true (the storage key of a domain-authenticated user is managed by domain auth; activating with an empty secret would overwrite the existing key) |

## Input Documents

| Document | Path | Status |
|------|------|------|
| Requirement | `proposal.md` | Approved |
| Design | `design.md` | Approved |
| Epic | `epic.md` | Approved |

> For the requirements baseline, out-of-scope items, and affected subsystems/repos, see proposal.md. design.md and this document are produced in parallel and are independent of each other.

## User Stories

### US-F2-1: Enable/Disable Domain Account Unlock Capability

**As** the domain account service,
**I want** to enable or disable domain account unlock capability per user,
**so that** I can control whether domain account credentials are allowed to unlock the device.

**Acceptance criteria:**

- **AC-F2-1.1:** WHEN the domain account service (uid 7058) holding `MANAGE_USER_IDM` permission calls `SetDomainAuthUnlockEnabled(localId, token, secret, true)` THEN the system should validate parameters and notify storage to add the key
- **AC-F2-1.2:** WHEN the caller's uid is not 7058 THEN the system should reject the call and return a permission error
- **AC-F2-1.3:** WHEN the caller lacks `MANAGE_USER_IDM` permission THEN the system should reject the call and return a permission error
- **AC-F2-1.4:** WHEN localId does not exist or is not bound to a domain account THEN the system should return `ERR_DOMAIN_ACCOUNT_SERVICE_NOT_DOMAIN_ACCOUNT`
- **AC-F2-1.5:** WHEN the token is invalid (VerifyAuthToken fails) THEN the system should return an authentication token error
- **AC-F2-1.6:** WHEN enabling and the storage key already exists THEN the system should directly return success without re-adding the key
- **AC-F2-1.7:** WHEN a PIN credential exists (regardless of enable/disable) THEN the system should directly return success without calling `UpdateStorageUserAuth` to delete the key (the key is managed by the PIN flow and is not interfered with)
- **AC-F2-1.8:** WHEN there is no PIN credential and the feature is being disabled (enabled=false) THEN the system should return `ERR_ACCOUNT_IAM_NO_CREDENTIAL` to intercept (this scenario is meaningless and should be intercepted)
- **AC-F2-1.9:** WHEN `libHandle_` is nullptr (no SO plugin) THEN `SetDomainAuthUnlockEnabled` should return a "not supported" error

### US-F2-2: Internal Query of Domain Account Unlock Configuration

**As** a system service,
**I want** to internally query the domain account unlock configuration,
**so that** the PIN flow adaptation and unlock flow checks can determine the current user's unlock strategy.

**Acceptance criteria:**

- **AC-F2-2.1:** WHEN the service internally calls `InnerDomainAccountManager::GetUnlockDeviceConfig(userId)` and the plugin is available THEN the system should query the plugin `GetUnlockDeviceConfigResult` and return `enableUnlockDevice` and `unlockDeviceMode`
- **AC-F2-2.2:** WHEN `libHandle_` is nullptr THEN `GetUnlockDeviceConfig` should return `enableUnlockDevice=false` as the default value

### US-F2-3: PIN Addition Flow Adaptation

**As** the system,
**I want** PIN addition to automatically adapt to the domain account unlock status,
**so that** storage key conflicts are avoided.

**Acceptance criteria:**

- **AC-F2-3.1:** WHEN adding a PIN and `enableUnlockDevice==true && unlockDeviceMode==ONLINE_OFFLINE_AUTH_UNLOCK_DEVICE` THEN the system should not call `UpdateStorageUserAuth` (skip storage key addition)
- **AC-F2-3.2:** WHEN adding a PIN and domain account unlock is not enabled or the mode is `OFFLINE_AUTH_UNLOCK_DEVICE` THEN the system should call `UpdateStorageUserAuth` normally
- **AC-F2-3.3:** WHEN adding a PIN and `libHandle_` is nullptr THEN the system should call `UpdateStorageUserAuth` normally (no domain account unlock)

### US-F2-4: PIN Deletion Flow Adaptation

**As** the system,
**I want** PIN deletion to automatically adapt to the domain account unlock status,
**so that** the domain account unlock key is not mistakenly deleted.

**Acceptance criteria:**

- **AC-F2-4.1:** WHEN deleting a PIN and `enableUnlockDevice==true && unlockDeviceMode==ONLINE_OFFLINE_AUTH_UNLOCK_DEVICE` THEN the system should not delete the storage key
- **AC-F2-4.2:** WHEN deleting a PIN and domain account unlock is not enabled or the mode is `OFFLINE_AUTH_UNLOCK_DEVICE` THEN the system should delete the storage key normally

## Acceptance Traceability

| AC | Related rule | Related Task | Verification method | Evidence |
|----|----------|-----------|----------|------|
| AC-F2-1.1 | BR-F2-1 | TASK-5, TASK-6 | Unit test + integration test | `inner_account_iam_manager_test.cpp` |
| AC-F2-1.2 | BR-F2-2 | TASK-6 | Unit test | `account_iam_service_test.cpp` |
| AC-F2-1.3 | BR-F2-2 | TASK-6 | Unit test | `account_iam_service_test.cpp` |
| AC-F2-1.4 | BR-F2-3 | TASK-6 | Unit test | `inner_account_iam_manager_test.cpp` |
| AC-F2-1.5 | BR-F2-3 | TASK-6 | Unit test | `inner_account_iam_manager_test.cpp` |
| AC-F2-1.6 | BR-F2-4 | TASK-6 | Unit test | `inner_account_iam_manager_test.cpp` |
| AC-F2-1.7 | BR-F2-4 | TASK-6 | Unit test | `inner_account_iam_manager_test.cpp` |
| AC-F2-1.8 | BR-F2-4 | TASK-6 | Unit test | `inner_account_iam_manager_test.cpp` |
| AC-F2-1.9 | BR-F2-5 | TASK-6 | Unit test | `inner_account_iam_manager_test.cpp` |
| AC-F2-2.1 | BR-F2-6 | TASK-7 | Unit test | `inner_domain_account_manager_test.cpp` |
| AC-F2-2.2 | BR-F2-5 | TASK-7 | Unit test | `inner_domain_account_manager_test.cpp` |
| AC-F2-3.1 | BR-F2-7 | TASK-8 | Unit test | `account_iam_callback_test.cpp` |
| AC-F2-3.2 | BR-F2-7 | TASK-8 | Unit test | `account_iam_callback_test.cpp` |
| AC-F2-3.3 | BR-F2-5 | TASK-8 | Unit test | `account_iam_callback_test.cpp` |
| AC-F2-4.1 | BR-F2-7 | TASK-9 | Unit test | `account_iam_callback_test.cpp` |
| AC-F2-4.2 | BR-F2-7 | TASK-9 | Unit test | `account_iam_callback_test.cpp` |

## Business Rules

| ID | Rule description | Constraints | Related AC |
|------|----------|----------|---------|
| BR-F2-1 | `SetDomainAuthUnlockEnabled` only handles storage key management | The plugin state is set by the caller (uid 7058) itself | AC-F2-1.1 |
| BR-F2-2 | uid 7058 allowlist + `MANAGE_USER_IDM` permission double check | `IPCSkeleton::GetCallingUid() == 7058` and `AccessTokenKit::VerifyAccessToken` passes | AC-F2-1.2~1.3 |
| BR-F2-3 | Parameter validation order: localId → bound domain account → token validity | `GetDomainAccountInfoByUserId` checks binding; `UserAccessCtrlClient::VerifyAuthToken` validates the token | AC-F2-1.4~1.5 |
| BR-F2-4 | When a PIN credential exists (regardless of enable/disable), directly return success without calling `UpdateStorageUserAuth`; the key is managed by the PIN flow and is not interfered with | Avoids mistaken deletion of PIN-managed keys | AC-F2-1.6~1.8 |
| BR-F2-5 | Feature isolation: `libHandle_ != nullptr` | When there is no plugin, all features default to "not supported/not enabled" | AC-F2-1.9, AC-F2-2.2, AC-F2-3.3 |
| BR-F2-6 | `GetUnlockDeviceConfig` is a service-internal method, not via IPC | Directly calls the plugin `GetUnlockDeviceConfigResult` (same-process dlsym) | AC-F2-2.1 |
| BR-F2-7 | PIN adaptation condition: `enableUnlockDevice==true && unlockDeviceMode==ONLINE_OFFLINE_AUTH_UNLOCK_DEVICE` | Both conditions must be satisfied to skip storage key management | AC-F2-3.1, AC-F2-4.1 |

## Functional Rules

| ID | Rule description | Trigger condition | Target | Related AC |
|------|----------|----------|----------|---------|
| FR-F2-1 | Notify storage to add key when enabled | `SetDomainAuthUnlockEnabled(enabled=true)` and the key does not exist | `UpdateStorageUserAuth(userId, secureUid, token, oldSecret, newSecret)` | AC-F2-1.1 |
| FR-F2-2 | Do not delete the storage key when a PIN credential exists | `SetDomainAuthUnlockEnabled` called and a PIN credential exists (enable or disable) | Directly return success; do not call `UpdateStorageUserAuth` (the key is managed by the PIN flow) | AC-F2-1.7 |
| FR-F2-3 | Query plugin configuration when adding a PIN | `AddCredCallback::OnResult` succeeds and is a PIN | `GetUnlockDeviceConfig(userId)` → conditionally skip `UpdateStorageUserAuth` | AC-F2-3.1 |
| FR-F2-4 | Query plugin configuration when deleting a PIN | `VerifyTokenCallbackWrapper::InnerOnResult` succeeds | `GetUnlockDeviceConfig(userId)` → conditionally skip `UpdateStorageUserAuth` | AC-F2-4.1 |

## Exception/Exemption Rules

| ID | Exception code/enum | Rule description | Trigger condition | Timeout threshold | Result | Related AC |
|------|------------|----------|----------|----------|----------|---------|
| EX-F2-1 | ERR_ACCOUNT_COMMON_PERMISSION_DENIED | uid is not 7058 | `GetCallingUid() != 7058` | N/A | Rejects the call | AC-F2-1.2 |
| EX-F2-2 | Permission error | No `MANAGE_USER_IDM` permission | `VerifyAccessToken` fails | N/A | Rejects the call | AC-F2-1.3 |
| EX-F2-3 | ERR_DOMAIN_ACCOUNT_SERVICE_NOT_DOMAIN_ACCOUNT | localId does not exist or is not bound to a domain account | `GetDomainAccountInfoByUserId` returns an error or accountName is empty | N/A | Returns error | AC-F2-1.4 |
| EX-F2-4 | ERR_ACCOUNT_IAM_AUTH_TOKEN_INVALID | token invalid | `VerifyAuthToken` returns failure | 60000ms (TOKEN_ALLOWABLE_DURATION) | Returns authentication token error | AC-F2-1.5 |
| EX-F2-5 | ERR_DOMAIN_ACCOUNT_NOT_SUPPORT | No plugin | `libHandle_ == nullptr` | N/A | Returns "not supported" | AC-F2-1.9, AC-F2-2.2 |
| EX-F2-6 | Storage operation failure (IPC) | StorageManager IPC failure | `UpdateStorageUserAuth` returns E_IPC_ERROR/E_IPC_SA_DIED | N/A | Retry 20×100ms | AC-F2-1.1 |

## Recovery Contract

| ID | Trigger condition | Recovery strategy | Recovery result | Constraints |
|------|----------|----------|----------|------|
| RC-F2-1 | Storage operation IPC failure | Retry 20 times at 100ms intervals | If successful, continues; if all fail, returns error | Does not affect existing keys |
| RC-F2-2 | Plugin query failure | Returns default value `enableUnlockDevice=false` | PIN adaptation normally goes through storage key management | Does not block the PIN flow |
| RC-F2-3 | `libHandle_` is nullptr | All features return "not supported/not enabled" | Feature degrades, does not affect existing flows | Safe degradation on devices without plugin |

## Verification Mapping

| ID | Corresponding spec item | Verification method | Verification focus |
|------|------------|----------|----------|
| VM-F2-1 | FR-F2-1 / AC-F2-1.1 | Unit test + integration test | `UpdateStorageUserAuth` is called when enabling |
| VM-F2-2 | BR-F2-2 / AC-F2-1.2~1.3 | Unit test | Non-7058 uid / no permission is rejected |
| VM-F2-3 | BR-F2-5 / AC-F2-1.9 | Unit test | Returns not supported when `libHandle_` is nullptr |
| VM-F2-4 | BR-F2-7 / AC-F2-3.1 | Unit test | Conditionally skips storage key when adding a PIN |
| VM-F2-5 | BR-F2-7 / AC-F2-4.1 | Unit test | Conditionally skips storage key when deleting a PIN |
| VM-F2-6 | BR-F2-6 / AC-F2-2.1 | Unit test | Internal query returns the correct configuration |

## API Change Analysis

### New APIs

| API name | Exposure scope | Input parameters summary | Return value | Error code range | Feature description | Related AC |
|----------|----------|----------|--------|------------|----------|---------|
| `AccountIAMClient::SetDomainAuthUnlockEnabled` | InnerAPI | `localId: int32_t, token: vector<uint8_t>, secret: vector<uint8_t>, enabled: bool` | `ErrCode` | ERR_DOMAIN_ACCOUNT_*, ERR_IAM_* | Enable/disable domain account unlock | AC-F2-1.1~1.9 |
| `IAccountIAM.idl::SetDomainAuthUnlockEnabled` | IDL | Same as above | Same as above | Same as above | IPC method | AC-F2-1.1 |
| `InnerDomainAccountManager::GetUnlockDeviceConfig` | Internal method | `userId: int32_t` | `ErrCode` (out params `enableUnlockDevice: bool, unlockDeviceMode: int32_t`) | ERR_DOMAIN_ACCOUNT_* | Query unlock configuration | AC-F2-2.1~2.2 |

## Compatibility Statement

- **Existing API behavior changes:** No. `SetDomainAuthUnlockEnabled` is a new API; PIN adaptation is an incremental modification (adds a conditional branch, does not affect the existing PIN flow)
- **Config file format changes:** No
- **Data storage format changes:** No. Reuses the existing `UpdateStorageUserAuth` API
- **Minimum supported version:** TBD
- **API version number strategy:** N/A (InnerAPI)

## Architecture Constraints

| Key constraint | Constraint description | Affected AC |
|----------|----------|---------|
| uid 7058 allowlist | Only the domain account service can call `SetDomainAuthUnlockEnabled` | AC-F2-1.2 |
| `MANAGE_USER_IDM` permission | The caller must hold this permission | AC-F2-1.3 |
| `libHandle_` feature isolation | When there is no plugin, the feature defaults to "not supported/not enabled" | AC-F2-1.9, AC-F2-2.2, AC-F2-3.3 |
| Storage key management reuses existing API | Does not add a new storage interface; reuses `UpdateStorageUserAuth` | AC-F2-1.1 |
| `GetUnlockDeviceConfig` is not exposed externally | Only an `InnerDomainAccountManager` internal method, not via IPC | AC-F2-2.1 |

## Non-Functional Requirements

| Type | Metric/threshold | Verification method | Evidence |
|------|-----------|----------|------|
| Security | uid allowlist + permission check + token check | Unit test | `account_iam_service_test.cpp` |
| Reliability | Storage operation failure retries 20×100ms | Unit test | `inner_account_iam_manager_test.cpp` |
| Diagnostics | HILOG log domain 0xD001B00 | hilog | Operation logs |

## Multi-Device Adaptation Statement

| Device type | Behavior difference | Spec/constraint | Verification method | Evidence |
|----------|----------|-----------|----------|------|
| Device with plugin | Normal execution | `libHandle_ != nullptr` | Unit test + integration test | N/A |
| Device without plugin | Feature degradation | `libHandle_ == nullptr`, returns "not supported/not enabled" | Unit test | N/A |

## Global Feature Impact

| Feature | Applicable? | Conclusion | Related scenarios |
|------|--------|------|----------|
| Accessibility | No | No UI | N/A |
| Multi-user | Yes | Enable/disable per user, each user independent | AC-F2-1.1 (localId parameter) |
| Version upgrade | Yes | Plugin needs sync-upgrade | New feature available after upgrade |
| Ecosystem compatibility | No | InnerAPI internal | N/A |

## Spec Self-Review Checklist

- [x] No placeholders like "TBD", "TODO", etc. (except target version TBD)
- [x] All ACs use WHEN/THEN format and can be tested independently
- [x] Scope boundaries are clear
- [x] No semantically ambiguous statements
- [x] ACs are cross-consistent with business rules/exception rules/recovery contracts

## context-references

```yaml
context-queries:
  - repo: "openharmony/os_account"
    query: "InnerAccountIAMManager::UpdateStorageUserAuth and ActivateUserKey"
  - repo: "openharmony/os_account"
    query: "AccountIAMService permission check pattern"
  - repo: "openharmony/os_account"
    query: "AddCredCallback::OnResult storage key management"
  - repo: "openharmony/os_account"
    query: "VerifyTokenCallbackWrapper::InnerOnResult DelUser flow"
```

**Key documents:** `design.md` §ADR-3 (feature isolation), §ADR-4 (state management), §call chain layering analysis Capability 1/Capability 2
