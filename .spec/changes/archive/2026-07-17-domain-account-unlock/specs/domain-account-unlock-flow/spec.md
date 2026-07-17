# Feature Specification

> Solidifies user-visible behavior and acceptance criteria. Complex interactions, state machines, and exception flows may be supplemented with Gherkin scenarios.

## Overview

| Attribute | Value |
|------|-----|
| Feature name | Domain Account Unlock Flow |
| Feature ID | FEAT-F3 |
| Parent Epic | EPIC-20260703-001 |
| Priority | P0 |
| Target version | TBD (reference manifest.target_release) |
| SIG ownership | SIG_Account |
| Status | Approved |
| Complexity | High |

## Scope of This Change (Delta)

| Type | Content | Description |
|------|------|------|
| MODIFIED | `DomainAccountClient::AuthUser` (hook-based overload) signature | Added `DomainAccountUnlockOptions` parameter; this overload is only called by `StartDomainAuth` in production code |
| ADDED | `IDomainAccount.idl::AuthUserWithUnlockOptions` IDL method | userId + password + DomainAccountUnlockOptions + callback |
| ADDED | `DomainAccountManagerService::AuthUserWithUnlockOptions` stub | Permission check + authIntent routing: `authIntent==UNLOCK_INTENT` → inner `AuthUserWithUnlockOptions`, otherwise → inner `AuthUser` |
| ADDED | `InnerDomainAccountManager::AuthUserWithUnlockOptions` business implementation | Detects `authIntent=UNLOCK` → binding check → unlock check → calls plugin `AuthWithUnlockIntent` |
| MODIFIED | `AccountIAMClient::AuthUser` | All DOMAIN authentication calls `StartDomainAuth` (passing `DomainAccountUnlockOptions` with challenge + authIntent); authIntent routing is done server-side; no separate client function |
| MODIFIED | `InnerDomainAuthCallback` | Added `authIntent_` member |
| ADDED | `InnerDomainAuthCallback::OnResultWithUnlock` + `HandleUnlockResult` | Unlock logic (EL2 + EL3/EL4); dispatched by `AuthResultInfoCallback` via `IsUnlockIntent()` (unlock intent → `OnResultWithUnlock`); `OnResult` is unchanged |
| ADDED | `DomainAccountCallback::OnAcquireInfo` | Added `OnAcquireInfo(module, acquireInfo, DomainAccountUnlockExtraInfo&)` default empty implementation; supports passing acquire info to the caller during authentication |
| ADDED | `IDomainAccountCallback::OnAcquireInfo` | IDL callback adds `OnAcquireInfo` IPC method (third param `DomainAccountUnlockExtraInfoIdl`) |
| ADDED | `DomainAccountCallbackService::OnAcquireInfo` | IPC stub forwards to in-process `DomainAccountCallback` after receiving |
| ADDED | `DomainAuthCallbackAdapter::OnAcquireInfo` | Forwards `extraInfo.successExtraInfo` (already `vector<uint8_t>`) to `IIDMCallback::OnAcquireInfo` (no Parcel→vector conversion) |
| ADDED | `InnerDomainAuthCallback::OnAcquireInfo` | no-op implementation (service side does not receive this callback) |

## Input Documents

| Document | Path | Status |
|------|------|------|
| Requirement | `proposal.md` | Approved |
| Design | `design.md` | Approved |
| Epic | `epic.md` | Approved |
| Feature F1 Spec | `specs/plugin-interface-extension/spec.md` | Draft |
| Feature F2 Spec | `specs/unlock-capability-switch/spec.md` | Draft |

> F3 depends on F1 (plugin interface: `AuthWithUnlockIntent` function + `secret` field + `GetUnlockDeviceConfigResult` function) and F2 (`GetUnlockDeviceConfig` internal query + `libHandle_` feature isolation).

## User Stories

### US-F3-1: Domain Account Unlock Authentication

**As** an end user,
**I want** to unlock the system with a domain account password from the PC lock screen,
**so that** I do not need to maintain an additional PIN.

**Acceptance criteria:**

- **AC-F3-1.1:** WHEN a system application holding `ACCESS_USER_AUTH_INTERNAL` permission calls `AuthUser` with `authType=DOMAIN, authIntent=UNLOCK` THEN the system should route via the modified `DomainAccountClient::AuthUser` (carrying `DomainAccountUnlockOptions`) to the `AuthUserWithUnlockOptions` IDL method, and the service-side `DomainAccountManagerService::AuthUserWithUnlockOptions` routes by `authIntent==UNLOCK_INTENT` to inner `AuthUserWithUnlockOptions`, ultimately calling the `AuthWithUnlockIntent` plugin function
- **AC-F3-1.2:** WHEN the user has not bound a domain account THEN the system should return an error and not attempt to unlock
- **AC-F3-1.3:** WHEN domain account unlock is not enabled (`enableUnlockDevice=false`) THEN the system should return an error and not attempt to unlock
- **AC-F3-1.4:** WHEN the `AuthWithUnlockIntent` plugin call succeeds and returns token+secret THEN the system should call `ActivateUserKey(userId, token, secret)` to perform EL2 decryption
- **AC-F3-1.5:** WHEN the `AuthWithUnlockIntent` plugin call succeeds and the screen is locked THEN the system should call `UnlockUserScreen(userId, token, secret)` to perform EL3/EL4 decryption
- **AC-F3-1.6:** WHEN the `AuthWithUnlockIntent` plugin call succeeds THEN the system should set `OsAccountIsVerified=true`
- **AC-F3-1.7:** WHEN the `AuthWithUnlockIntent` plugin call fails THEN the system should not perform any storage unlock and should return an error to the caller
- **AC-F3-1.8:** WHEN the target account is being deactivated or locked THEN the system should not perform storage unlock
- **AC-F3-1.9:** WHEN `libHandle_` is nullptr THEN domain account unlock is unavailable, returning "not supported"
- **AC-F3-1.10:** WHEN unlock is complete THEN token and secret should be zeroed in memory (memset)
- **AC-F3-1.11:** WHEN `AuthWithUnlockIntent` is called carrying a challenge value THEN the plugin should receive the challenge for authentication

### US-F3-2: Unlock Trigger Entry Restriction

**As** the system,
**I want** only domain account authentication triggered via the `AccountIAMClient` entry to be able to unlock,
**so that** callers without permission verification cannot directly trigger storage unlock.

**Acceptance criteria:**

- **AC-F3-2.1:** WHEN domain account authentication is triggered via `DomainAccountClient::Auth` or `DomainAccountClient::AuthUser` (non-modified overload) THEN the system should only perform authentication, not perform storage unlock (`ActivateUserKey`/`UnlockUserScreen` are not called)
- **AC-F3-2.2:** WHEN domain account authentication is triggered via `AccountIAMClient::Auth` or `AccountIAMClient::AuthUser` (`authType=DOMAIN, authIntent=UNLOCK`) THEN the system should perform storage unlock (via the `AuthUserWithUnlockOptions` IDL path)

### US-F3-3: Domain Account Authentication AcquireInfo Callback

**As** a system application,
**I want** to receive the `OnAcquireInfo` callback during domain account authentication,
**so that** I can obtain intermediate authentication status info (e.g. authentication prompts, remaining attempts, etc.), consistent with IAM authentication (PIN/Face) behavior.

**Acceptance criteria:**

- **AC-F3-3.1:** WHEN the server side calls `callback->OnAcquireInfo(module, acquireInfo, DomainAccountUnlockExtraInfoIdl)` during domain account authentication THEN the client should receive `OnAcquireInfo` via IPC and forward it to `DomainAccountCallback::OnAcquireInfo`
- **AC-F3-3.2:** WHEN `DomainAuthCallbackAdapter::OnAcquireInfo` is called THEN it should forward `extraInfo.successExtraInfo` (already `vector<uint8_t>`) to `IIDMCallback::OnAcquireInfo(module, acquireInfo, extraInfoBuffer)`
- **AC-F3-3.3:** WHEN an existing `DomainAccountCallback` subclass does not override `OnAcquireInfo` THEN the default empty implementation does not affect existing authentication flows

## Acceptance Traceability

| AC | Related rule | Related Task | Verification method | Evidence |
|----|----------|-----------|----------|------|
| AC-F3-1.1 | BR-F3-1, BR-F3-3 | TASK-10-1, TASK-10-2, TASK-11 | Unit test + integration test | `account_iam_client_test.cpp` |
| AC-F3-1.2 | BR-F3-4 | TASK-11 | Unit test | `inner_domain_account_manager_test.cpp` |
| AC-F3-1.3 | BR-F3-4 | TASK-11 | Unit test | `inner_domain_account_manager_test.cpp` |
| AC-F3-1.4 | BR-F3-5 | TASK-11 | Unit test | `inner_domain_account_manager_test.cpp` |
| AC-F3-1.5 | BR-F3-5 | TASK-11 | Unit test | `inner_domain_account_manager_test.cpp` |
| AC-F3-1.6 | BR-F3-5 | TASK-11 | Unit test | `inner_domain_account_manager_test.cpp` |
| AC-F3-1.7 | EX-F3-3 | TASK-11 | Unit test | `inner_domain_account_manager_test.cpp` |
| AC-F3-1.8 | EX-F3-4 | TASK-11 | Unit test | `inner_domain_account_manager_test.cpp` |
| AC-F3-1.9 | BR-F3-2 | TASK-11 | Unit test | `inner_domain_account_manager_test.cpp` |
| AC-F3-1.10 | BR-F3-6 | TASK-11 | Code review + security scan | `inner_domain_account_manager.cpp` |
| AC-F3-1.11 | BR-F3-3 | TASK-10-2, TASK-11 | Unit test | `inner_domain_account_manager_test.cpp` |
| AC-F3-2.1 | BR-F3-7 | TASK-11 | Unit test | `inner_domain_account_manager_test.cpp` |
| AC-F3-2.2 | BR-F3-7 | TASK-10-2, TASK-11 | Unit test | `account_iam_client_test.cpp` |
| AC-F3-3.1 | BR-F3-8 | TASK-10b | Unit test | `domain_account_callback_service_test.cpp` |
| AC-F3-3.2 | BR-F3-8 | TASK-10b | Unit test | `account_iam_callback_service_test.cpp` |
| AC-F3-3.3 | BR-F3-9 | TASK-10b | Unit test | Existing callback subclass test regression |

## Business Rules

| ID | Rule description | Constraints | Related AC |
|------|----------|----------|---------|
| BR-F3-1 | `AuthUser` DOMAIN authentication routes via `StartDomainAuth` | All DOMAIN authentication calls `StartDomainAuth` (passing `DomainAccountUnlockOptions` with challenge + authIntent); no separate client function; the `authIntent` is routed server-side in `DomainAccountManagerService::AuthUserWithUnlockOptions` (`UNLOCK_INTENT` → inner `AuthUserWithUnlockOptions`, otherwise → inner `AuthUser`) | AC-F3-1.1 |
| BR-F3-2 | Feature isolation: `libHandle_ != nullptr` | Unlock unavailable when there is no plugin | AC-F3-1.9 |
| BR-F3-3 | challenge is passed through to the plugin | `DomainAccountUnlockOptions.challenge` → `AuthWithUnlockIntent`'s `challengeValue` parameter | AC-F3-1.1, AC-F3-1.11 |
| BR-F3-4 | Pre-unlock checks: bound domain account + unlock enabled | `GetDomainAccountInfoByUserId` checks binding; `GetUnlockDeviceConfigWithInfo` checks `enableUnlockDevice` | AC-F3-1.2~1.3 |
| BR-F3-5 | Unlock logic executes in `InnerDomainAuthCallback::OnResultWithUnlock` | `AuthResultInfoCallback` dispatches by `IsUnlockIntent()` to `OnResultWithUnlock` (passes `DomainAuthResult` directly, without Marshalling, secret preserved); calls `HandleUnlockResult` to execute `UnlockUserStorage` (EL2) + `UnlockEnhancedStorage` (EL3/EL4) + `SetOsAccountIsVerified` | AC-F3-1.4~1.6 |
| BR-F3-6 | token/secret zeroed after use | `DomainAuthResult` destructor automatically zeroes token + secret; Marshalling does not contain secret | AC-F3-1.10 |
| BR-F3-7 | Unlock entry restriction | Only the `AccountIAMClient` entry (via `AuthUserWithUnlockOptions` IDL, carrying `authIntent=UNLOCK`) can trigger unlock; direct `DomainAccountClient` calls (non-modified overload, via existing IDL) only authenticate without unlocking; server-side `DomainAccountManagerService` routes by `authIntent` | AC-F3-2.1~2.2 |
| BR-F3-8 | `OnAcquireInfo` end-to-end forwarding | Server-side `callback->OnAcquireInfo` → IPC → `DomainAccountCallbackService::OnAcquireInfo` → `innerCallback_->OnAcquireInfo` → `DomainAuthCallbackAdapter::OnAcquireInfo` → `IIDMCallback::OnAcquireInfo` | AC-F3-3.1~3.2 |
| BR-F3-9 | `OnAcquireInfo` backward compatibility | `DomainAccountCallback::OnAcquireInfo` default empty implementation; when all existing subclasses do not override, existing authentication flows are not affected | AC-F3-3.3 |

## Functional Rules

| ID | Rule description | Trigger condition | Target | Related AC |
|------|----------|----------|----------|---------|
| FR-F3-1 | `AuthUserWithUnlockOptions` IDL routing | `AccountIAMClient::AuthUser` DOMAIN | `DomainAccountClient::AuthUser` (signature modified) → `proxy->AuthUserWithUnlockOptions` | AC-F3-1.1 |
| FR-F3-2 | Binding check | `InnerDomainAccountManager::AuthUserWithUnlockOptions` entry | `GetDomainAccountInfoByUserId` | AC-F3-1.2 |
| FR-F3-3 | Unlock-enabled check | Binding check passed | `GetUnlockDeviceConfigWithInfo` → `enableUnlockDevice` + `unlockDeviceMode` | AC-F3-1.3 |
| FR-F3-4 | EL2 unlock | `errCode==ERR_OK` in `HandleUnlockResult` | `UnlockUserStorage(userId, token, secret, isUpdateVerifiedStatus)` | AC-F3-1.4 |
| FR-F3-5 | EL3/EL4 unlock | After EL2 unlock | `UnlockEnhancedStorage(userId, token, secret, isUpdateVerifiedStatus)` (internally checks `GetLockScreenStatus` → `UnlockUserScreen`) | AC-F3-1.5 |
| FR-F3-6 | Set IsVerified | Both EL2 and EL3/EL4 unlock succeed | `IInnerOsAccountManager::SetOsAccountIsVerified(userId, true)` | AC-F3-1.6 |
| FR-F3-7 | Plugin async call | `AuthUserWithUnlockOptions` business implementation | `PluginAuthWithUnlockIntent` (looks up the `AUTH_WITH_UNLOCK_INTENT` function pointer via `methodMap_`) | AC-F3-1.1 |

## Exception/Exemption Rules

| ID | Exception code/enum | Rule description | Trigger condition | Timeout threshold | Result | Related AC |
|------|------------|----------|----------|----------|----------|---------|
| EX-F3-1 | ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE | No plugin | `libHandle_ == nullptr` | N/A | Returns not supported | AC-F3-1.9 |
| EX-F3-2 | ERR_DOMAIN_ACCOUNT_SERVICE_NOT_DOMAIN_ACCOUNT | Domain account not bound | `GetDomainAccountInfoByUserId` returns an error | N/A | Returns error, does not attempt unlock | AC-F3-1.2 |
| EX-F3-3 | ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE | Unlock not enabled | `enableUnlockDevice != true` | N/A | Returns not supported | AC-F3-1.3 |
| EX-F3-4 | Plugin authentication failed | Plugin returns an error | `AuthWithUnlockIntent` returns error | N/A | Does not perform unlock, returns error to caller | AC-F3-1.7 |
| EX-F3-5 | Account deactivating/locking (before unlock) | `IsOsAccountDeactivatingOrLocking` is true in `HandleUnlockResult` | Checked after authentication success, before unlock | N/A | Does not perform unlock, returns ERR_OK (authentication succeeds but no unlock) | AC-F3-1.8 |
| EX-F3-5b | ERR_IAM_BUSY | Account deactivating/locking (before authentication) | `IsOsAccountDeactivatingOrLocking` is true in `AuthUserWithUnlockOptions` | N/A | Does not start authentication, returns ERR_IAM_BUSY | AC-F3-1.8 |
| EX-F3-6 | Storage unlock failed | `UnlockUserStorage`/`UnlockEnhancedStorage` returns failure | EL2 `E_ACTIVE_EL2_FAILED` or EL3/EL4 failure | Retry 20×100ms (internal) | Does not set IsVerified, returns error code + empty parcel | AC-F3-1.4~1.5 |
| EX-F3-7 | DomainAccountManagerService insufficient permission | Caller does not have `ACCESS_USER_AUTH_INTERNAL` | `CheckPermission` fails | N/A | Rejects the call | AC-F3-1.1 |

## Recovery Contract

| ID | Trigger condition | Recovery strategy | Recovery result | Constraints |
|------|----------|----------|----------|------|
| RC-F3-1 | Storage unlock IPC failure | Retry 20 times at 100ms intervals | If successful, continues to set IsVerified; if all fail, returns error | Does not set IsVerified; token/secret still need to be zeroed |
| RC-F3-2 | Plugin authentication failed | Does not perform any storage unlock | Returns error to caller | Does not call ActivateUserKey/UnlockUserScreen |
| RC-F3-3 | Account deactivating/locking | Does not perform storage unlock | Returns ERR_OK (authentication succeeds but no unlock) | Does not affect account deactivation/lock flow |
| RC-F3-4 | `libHandle_` is nullptr | Returns "not supported" | Feature unavailable | Safe degradation on devices without plugin |

## Verification Mapping

| ID | Corresponding spec item | Verification method | Verification focus |
|------|------------|----------|----------|
| VM-F3-1 | FR-F3-1 / AC-F3-1.1 | Unit test + integration test | DOMAIN+UNLOCK correctly routes to AuthUserWithUnlockOptions |
| VM-F3-2 | FR-F3-4 / AC-F3-1.4 | Unit test | ActivateUserKey is called |
| VM-F3-3 | FR-F3-5 / AC-F3-1.5 | Unit test | UnlockUserScreen is called when the screen is locked |
| VM-F3-4 | BR-F3-6 / AC-F3-1.10 | Code review + security scan | token/secret zeroing |
| VM-F3-5 | BR-F3-7 / AC-F3-2.1 | Unit test | DomainAccountClient entry does not unlock |
| VM-F3-6 | BR-F3-7 / AC-F3-2.2 | Unit test | AccountIAMClient entry unlocks |
| VM-F3-7 | EX-F3-5 / AC-F3-1.8 | Unit test | Account is not unlocked when deactivating/locking |

## API Change Analysis

### New APIs

| API name | Exposure scope | Input parameters summary | Return value | Error code range | Feature description | Related AC |
|----------|----------|----------|--------|------------|----------|---------|
| `IDomainAccount.idl::AuthUserWithUnlockOptions` | IDL | `userId: int, password: unsigned char[], unlockOptions: DomainAccountUnlockOptions, callback: IDomainAccountCallback` | void | ERR_DOMAIN_ACCOUNT_* | AuthUser IPC method with unlockOptions | AC-F3-1.1 |
| `DomainAccountManagerService::AuthUserWithUnlockOptions` | Service Stub | Same as above | `ErrCode` | Same as above | Permission check + authIntent routing | AC-F3-1.1 |
| `InnerDomainAccountManager::AuthUserWithUnlockOptions` | Internal method | `userId, password, unlockOptions, callback` | `ErrCode` | Same as above | Business logic | AC-F3-1.1~1.3 |
| `DomainAccountCallback::OnAcquireInfo` | InnerAPI | `module: int32_t, acquireInfo: uint32_t, extraInfo: DomainAccountUnlockExtraInfo&` | void | N/A | Domain account authentication acquire info callback, default empty implementation | AC-F3-3.1 |
| `IDomainAccountCallback::OnAcquireInfo` | IDL | `module: int, acquireInfo: unsigned int, extraInfo: DomainAccountUnlockExtraInfoIdl` | void | N/A | Domain account IPC callback acquire info | AC-F3-3.1 |
| `DomainAccountCallbackService::OnAcquireInfo` | Framework | Same as IDL | `ErrCode` | N/A | IPC stub forwards to in-process callback after receiving | AC-F3-3.1 |
| `DomainAuthCallbackAdapter::OnAcquireInfo` | InnerAPI | `module, acquireInfo, extraInfo: DomainAccountUnlockExtraInfo&` | void | N/A | Forwards `extraInfo.successExtraInfo` (vector\<uint8_t\>) to IIDMCallback | AC-F3-3.2 |

### Changed/Deprecated APIs

| API name | Change type | Affected scenarios | Migration guide | Related AC |
|----------|----------|----------|----------|---------|
| `DomainAccountClient::AuthUser` (hook-based overload) | Signature modified | Only called by `StartDomainAuth` (production code) | Added `DomainAccountUnlockOptions` parameter; existing tests need to update the signature in sync; internally changed from `proxy->AuthUser` to `proxy->AuthUserWithUnlockOptions` | AC-F3-1.1 |
| `AccountIAMClient::AuthUser` | Modified | DOMAIN authentication routing | All DOMAIN authentication goes through `StartDomainAuth` (passing `DomainAccountUnlockOptions` with challenge + authIntent); authIntent routing is performed server-side in `DomainAccountManagerService::AuthUserWithUnlockOptions` (`UNLOCK_INTENT` → inner `AuthUserWithUnlockOptions`, otherwise → inner `AuthUser`); no separate client function | AC-F3-1.1, AC-F3-2.2 |
| `InnerDomainAuthCallback` | Modified | Added `authIntent_` member | Constructor adds `authIntent` parameter; existing call sites set `DEFAULT` | AC-F3-1.4, AC-F3-2.1 |
| `InnerDomainAuthCallback::OnResultWithUnlock` | Added | New method for unlock intent | Dispatched by `AuthResultInfoCallback` via `IsUnlockIntent()` (unlock intent → `OnResultWithUnlock`, otherwise → unchanged `OnResult`); calls `HandleUnlockResult` to execute `UnlockUserStorage` (EL2) + `UnlockEnhancedStorage` (EL3/EL4) + `SetOsAccountIsVerified`; `OnResult` is unchanged | AC-F3-1.4~1.6, AC-F3-1.10 |

## Compatibility Statement

- **Existing API behavior changes:** `DomainAccountClient::AuthUser` (hook-based overload) signature modified, but this overload is only called by `StartDomainAuth` in production code with no external usage, so there is no compatibility risk. `AccountIAMClient::AuthUser` routes all DOMAIN authentication through `StartDomainAuth` (passing `DomainAccountUnlockOptions`); the authIntent-based unlock routing happens server-side in `DomainAccountManagerService::AuthUserWithUnlockOptions` and does not affect non-DOMAIN authentication.
- **Config file format changes:** No
- **Data storage format changes:** No. Reuses existing `ActivateUserKey`/`UnlockUserScreen` APIs
- **Minimum supported version:** TBD
- **API version number strategy:** N/A (InnerAPI)

## Architecture Constraints

| Key constraint | Constraint description | Affected AC |
|----------|----------|---------|
| Unlock logic is in `InnerDomainAuthCallback::OnResultWithUnlock` (A-1 solution) | Does not modify the `AuthCallback` class; the domain module directly calls `InnerAccountIAMManager` public unlock APIs; `OnResult` is unchanged | AC-F3-1.4~1.6 |
| Unlock entry restriction (ADR-6) | Only the `AccountIAMClient` entry (via `AuthUserWithUnlockOptions` IDL, `authIntent=UNLOCK`) can trigger unlock; direct `DomainAccountClient` calls go through existing IDL, `authIntent=DEFAULT`, no unlock | AC-F3-2.1~2.2 |
| Token zeroing timing | Unlock logic must execute before token/secret zeroing; unlock runs in `OnResultWithUnlock` → `HandleUnlockResult`, and token/secret are zeroed when `DomainAuthResult` is destroyed | AC-F3-1.4~1.6, AC-F3-1.10 |
| `DomainAccountUnlockOptions` must be declared sequenceable in IDL | `IDomainAccount.idl` needs to add `sequenceable DomainAccountCommon..OHOS.AccountSA.DomainAccountUnlockOptions;` | AC-F3-1.1 |
| `DomainAccountManagerService::AuthUserWithUnlockOptions` permission check | Uses `ACCESS_USER_AUTH_INTERNAL` (consistent with existing `AuthUser`) | AC-F3-1.1 |

## Non-Functional Requirements

| Type | Metric/threshold | Verification method | Evidence |
|------|-----------|----------|------|
| Security | token/secret zeroed with memset_s after use | Code review + security scan | `inner_domain_account_manager.cpp` |
| Security | Unlock entry restriction (AccountIAMClient only) | Unit test | `inner_domain_account_manager_test.cpp` |
| Reliability | Storage unlock failure retries 20×100ms | Unit test | `inner_domain_account_manager_test.cpp` |
| Performance | Plugin async call does not block the caller thread | Unit test | detach thread execution |
| Diagnostics | HILOG log domain 0xD001B00 | hilog | Operation logs |

## Multi-Device Adaptation Statement

| Device type | Behavior difference | Spec/constraint | Verification method | Evidence |
|----------|----------|-----------|----------|------|
| Device with plugin | Normal unlock | `libHandle_ != nullptr` | Unit test + integration test | N/A |
| Device without plugin | Unlock unavailable | `libHandle_ == nullptr`, returns "not supported" | Unit test | N/A |

## Global Feature Impact

| Feature | Applicable? | Conclusion | Related scenarios |
|------|--------|------|----------|
| Accessibility | No | No UI | N/A |
| Multi-user | Yes | Authenticates and unlocks per user, each user independent | AC-F3-1.1 (userId parameter) |
| Version upgrade | Yes | Plugin needs to be upgraded in sync | New feature available after upgrade |
| Ecosystem compatibility | No | InnerAPI internal | N/A |

## Behavior Scenarios (Gherkin)

> L2+ (complex) uses Gherkin scenarios to express core flows.

```gherkin
Feature: Domain Account Unlock Authentication

  Scenario: Domain account authentication succeeds and unlocks the system
    Given the user has bound a domain account and domain account unlock is enabled
      And the domain account plugin is loaded (libHandle_ != nullptr)
      And the screen is locked
    When a system application calls AuthUser(authType=DOMAIN, authIntent=UNLOCK)
    Then the system should route to the AuthUserWithUnlockOptions IDL method
      And the system should call the AuthWithUnlockIntent plugin function
      And after plugin authentication succeeds, the system should call ActivateUserKey for EL2 decryption
      And the system should call UnlockUserScreen for EL3/EL4 decryption
      And the system should set OsAccountIsVerified=true
      And after unlock, token and secret should be zeroed

  Scenario: DomainAccountClient direct call only authenticates without unlocking
    Given the user has bound a domain account
    When domain account authentication is triggered via DomainAccountClient::AuthUser (non-modified overload)
    Then the system should only perform authentication
      And the system should not call ActivateUserKey
      And the system should not call UnlockUserScreen

  Scenario: Unlock unavailable on devices without plugin
    Given the domain account plugin is not loaded (libHandle_ == nullptr)
    When a system application calls AuthUser(authType=DOMAIN, authIntent=UNLOCK)
    Then the system should return a "not supported" error
      And the system should not perform any storage unlock

  Scenario: Domain account unlock not enabled
    Given the user has bound a domain account but enableUnlockDevice=false
    When a system application calls AuthUser(authType=DOMAIN, authIntent=UNLOCK)
    Then the system should return an error and not attempt to unlock
```

## Spec Self-Review Checklist

- [x] No placeholders like "TBD", "TODO", etc. (except target version TBD)
- [x] All ACs use WHEN/THEN format and can be tested independently
- [x] Scope boundaries are clear
- [x] No semantically ambiguous statements
- [x] ACs are cross-consistent with business rules/exception rules/recovery contracts
- [x] Unlock entry restriction (ADR-6) has independent AC coverage (AC-F3-2.1~2.2)

## context-references

```yaml
context-queries:
  - repo: "openharmony/os_account"
    query: "InnerDomainAuthCallback::OnResultWithUnlock and HandleUnlockResult unlock logic"
  - repo: "openharmony/os_account"
    query: "AccountIAMClient::AuthUser DOMAIN early-return at line 396-404"
  - repo: "openharmony/os_account"
    query: "InnerAccountIAMManager public unlock APIs: ActivateUserKey, UnlockUserScreen, GetLockScreenStatus"
  - repo: "openharmony/os_account"
    query: "IDomainAccount.idl AuthUser and AuthWithParameters IDL methods"
  - repo: "openharmony/os_account"
    query: "DomainAccountClient::AuthUser hook-based overload getPasswordHooks"
```

**Key documents:** `design.md` §ADR-1 (unlock routing), §ADR-2 (authIntent passing), §ADR-6 (unlock entry restriction), §call chain layering analysis Capability 3, §exception propagation timing diagram, §resource ownership matrix, §thread and concurrency model
