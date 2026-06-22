# Feature Specification

> Codify user-visible behaviors and acceptance criteria.

## Overview

| Property | Value |
|----------|-------|
| Feature Name | Custom Auth Type & Companion Device Unlock Support |
| Feature ID | FEAT-20260528-001 |
| Epic | None |
| Priority | P0 |
| Target Release | OpenHarmony-6.0-Release |
| SIG | SIG_Account |
| Status | Approved |
| Complexity | Standard |

## Change Scope (Delta)

| Type | Content | Description |
|------|---------|-------------|
| ADDED | AuthType.CUSTOM = 128 enum value | Public API new enum value |
| ADDED | AuthOptions.additionalInfo optional string field | Public API new optional field |
| ADDED | AuthTypeIndex.CUSTOM = 7 internal mapping | InnerAPI new mapping |
| ADDED | User space decryption (EL2-EL5) after CUSTOM auth success | Security-critical behavior addition |
| MODIFIED | Remove COMPANION_DEVICE skip logic in UnlockUserScreen after auth success | Modify existing conditional logic; COMPANION_DEVICE no longer skips EL3/EL4 decryption, but still does not trigger ActivateUserKey (EL2 not decrypted) |
| ADDED | NAPI layer additionalInfo parameter parsing (ParseContextForAuthOptions) | NAPI layer new additionalInfo parsing logic |
| ADDED | @ohos.account.osAccount.d.ts type declarations | Public API TypeScript type declaration update (external repo interface_sdk-js) |
| ADDED | ohos.account.osAccount.taihe IDL type definitions | Taihe IDL adds AuthType.CUSTOM = 128 and AuthOptions.additionalInfo: Optional<String> |
| ADDED | ConvertToAuthOptionsInner() additionalInfo conversion | Taihe impl layer new additionalInfo conversion logic |

## Input Documents

| Document | Path | Status |
|----------|------|--------|
| Requirement | proposal.md | Approved |
| Design | design.md | Draft |

## User Stories

### US-1: Authenticate Using CUSTOM Auth Type

**As** an app developer,
**I want** to use AuthType.CUSTOM = 128 for identity authentication,
**so that** I can integrate custom authentication plugins (e.g., smart cards, security tokens, hardware keys, etc.).

**Acceptance Criteria:**

- **AC-1.1 [NEW]:** WHEN an app calls `UserAuth.auth()` with `authType = 128` (CUSTOM) THEN the system should accept the auth type and enter the custom authentication flow
- **AC-1.2 [NEW]:** WHEN an app calls `UserAuth.getAvailableStatus()` with `authType = 128` (CUSTOM) THEN the system should return the availability status of custom authentication capability
- **AC-1.3 [NEW]:** WHEN a TypeScript app imports the osAccount module THEN the compiler should recognize `AuthType.CUSTOM` and `AuthOptions.additionalInfo` as valid types (implemented by external PR [interface_sdk-js#33557](https://gitcode.com/openharmony/interface_sdk-js/pull/33557))

### US-2: Pass Custom Auth Additional Info

**As** an app developer,
**I want** to pass additional information through AuthOptions.additionalInfo to the authentication flow,
**so that** custom authentication plugins can receive external parameters.

**Acceptance Criteria:**

- **AC-2.1 [NEW]:** WHEN an app calls `UserAuth.auth()` with `options.additionalInfo` set THEN the authentication flow should receive the provided additional information
- **AC-2.2 [EXISTING+NEW]:** WHEN an app calls `UserAuth.auth()` without `options.additionalInfo` set THEN the authentication flow should proceed normally without depending on additional information
- **AC-2.3 [NEW]:** WHEN the NAPI layer receives `additionalInfo` as `undefined` THEN it should be treated as not provided, using the default value

### US-3: Unlock User Space After CUSTOM Auth Success

**As** an end user,
**I want** the system to fully unlock my user space (EL2-EL5) after CUSTOM authentication succeeds,
**so that** I get an unlock experience consistent with PIN/FACE/FINGERPRINT authentication.

**Acceptance Criteria:**

- **AC-3.1 [NEW]:** WHEN CUSTOM auth succeeds and token and secret are valid THEN the system should call `ActivateUserKey()` to activate user keys and decrypt EL2 storage
- **AC-3.2 [EXISTING]:** WHEN CUSTOM auth succeeds and the screen is locked THEN the system should call `UnlockUserScreen()` to decrypt EL3/EL4 encrypted files
- **AC-3.3 [EXISTING]:** WHEN CUSTOM auth succeeds with user space unlock THEN the system should set the OS account's `isVerified` and `isLoggedIn` status to true
- **AC-3.4 [EXISTING]:** WHEN CUSTOM auth succeeds but `ActivateUserKey()` or `UnlockUserScreen()` fails THEN the system should retry up to 20 times (100ms interval); if all retries fail, return an error and do not set verified/logged-in status
- **AC-3.5 [EXISTING]:** WHEN CUSTOM auth succeeds but the target account is in deactivating state THEN the system should not execute user space decryption and return the auth result without modifying storage state

### US-4: Unlock User Space After COMPANION_DEVICE Auth Success

**As** an end user,
**I want** the system to fully unlock my user space (including EL3/EL4) after COMPANION_DEVICE authentication succeeds,
**so that** trusted possession (e.g., smart watch, security key) authentication can fully unlock the device.

**Acceptance Criteria:**

- **AC-4.1 [EXISTING]:** WHEN COMPANION_DEVICE auth succeeds and token and secret are valid THEN the system should NOT call `ActivateUserKey()`; EL2 storage is not decrypted (COMPANION_DEVICE is not in the CheckAllowUnlockUserStorage allowlist)
- **AC-4.2 [NEW]:** WHEN COMPANION_DEVICE auth succeeds and the screen is locked THEN the system should call `UnlockUserScreen()` to decrypt EL3/EL4 encrypted files
- **AC-4.3 [EXISTING+NEW]:** WHEN COMPANION_DEVICE auth succeeds with user space unlock THEN the system should set the OS account's `isVerified` and `isLoggedIn` status to true
- **AC-4.4 [EXISTING+NEW]:** WHEN COMPANION_DEVICE auth succeeds but `UnlockUserScreen()` fails THEN the system should retry up to 20 times (100ms interval); if all retries fail, return an error and do not set verified/logged-in status
- **AC-4.5 [EXISTING]:** WHEN COMPANION_DEVICE auth succeeds but the target account is in deactivating state THEN the system should not execute user space decryption and return the auth result without modifying storage state

### US-5: NAPI Layer Parsing of additionalInfo Parameter

**As** a framework developer,
**I want** the NAPI layer to correctly parse the additionalInfo parameter in AuthOptions,
**so that** the authentication flow can receive additional information from JavaScript.

**Acceptance Criteria:**

- **AC-5.1 [NEW]:** WHEN the NAPI layer receives a JavaScript authOptions object with `additionalInfo` as a valid string THEN ParseContextForAuthOptions should parse additionalInfo as a valid string and set `hasAdditionalInfo = true`
- **AC-5.2 [NEW]:** WHEN the NAPI layer receives a JavaScript authOptions object with `additionalInfo` as undefined or not set THEN ParseContextForAuthOptions should treat it as not provided and set `hasAdditionalInfo = false`

> AC-5.1/5.2 complement AC-2.1/2.2/2.3: AC-2 describes behavioral outcomes of the authentication flow, AC-5 describes the parsing mechanism in the NAPI layer.

### US-6: TypeScript Type Declarations

**As** an app developer,
**I want** @ohos.account.osAccount.d.ts to include AuthType.CUSTOM and AuthOptions.additionalInfo type declarations,
**so that** the TypeScript compiler can correctly recognize and validate these types.

**Acceptance Criteria:**

- **AC-6.1 [NEW]:** WHEN @ohos.account.osAccount.d.ts file is updated THEN it should contain the `AuthType.CUSTOM = 128` enum value declaration (implemented by external PR [interface_sdk-js#33557](https://gitcode.com/openharmony/interface_sdk-js/pull/33557))
- **AC-6.2 [NEW]:** WHEN @ohos.account.osAccount.d.ts file is updated THEN it should contain the `AuthOptions.additionalInfo?: string` optional field declaration (implemented by external PR [interface_sdk-js#33557](https://gitcode.com/openharmony/interface_sdk-js/pull/33557))

> AC-6.1/6.2 complement AC-1.3: AC-1.3 describes the compiler behavioral outcome, AC-6 describes the specific declaration requirements in the .d.ts file. The .d.ts file is located in the external repo interface_sdk-js.

### US-7: Taihe IDL Type Definitions and Parameter Conversion

**As** a framework developer,
**I want** Taihe IDL and impl layer to support AuthType.CUSTOM and AuthOptions.additionalInfo,
**so that** the Taihe (static NAPI) channel can correctly pass types and parameters to the native authentication flow.

**Acceptance Criteria:**

- **AC-7.1 [NEW]:** WHEN ohos.account.osAccount.taihe IDL file is updated THEN the AuthType enum should include the `CUSTOM = 128` value
- **AC-7.2 [NEW]:** WHEN ohos.account.osAccount.taihe IDL file is updated THEN the AuthOptions struct should include the `additionalInfo: Optional<String>` field
- **AC-7.3 [NEW]:** WHEN Taihe layer receives AuthOptions with `additionalInfo` having a value THEN ConvertToAuthOptionsInner() should set `hasAdditionalInfo = true` and convert additionalInfo to native `std::string`
- **AC-7.4 [EXISTING+NEW]:** WHEN Taihe layer receives AuthOptions with `additionalInfo` having no Optional value THEN ConvertToAuthOptionsInner() should set `hasAdditionalInfo = false` and additionalInfo remains the default empty string

## Acceptance Traceability

| AC | Source | Related Rule | Related Task | Verification Method | Evidence |
|----|--------|--------------|--------------|---------------------|----------|
| AC-1.1 | NEW | BR-1 | TASK-1 | Unit test | `AccountIAMInfo_AuthType_CUSTOM_0100` |
| AC-1.2 | NEW | BR-1 | TASK-1 | No verification needed, covered by XTS | `_test` |
| AC-1.3 | NEW | BR-1 | TASK-1 | Compile verification (external PR interface_sdk-js#33557) | `_test` |
| AC-2.1 | NEW | FR-1 | TASK-2 | Unit test | `AccountIAMInfo_AuthParam_Marshalling_WithAdditionalInfo_0100, AccountIAMInfo_AuthOptions_AdditionalInfo_0100, AccountIAMInfo_CredentialParametersIam_WithAdditionalInfo_0100` |
| AC-2.2 | EXISTING+NEW | FR-1 | TASK-2 | Unit test | `AccountIAMInfo_AuthParam_Marshalling_NoAdditionalInfo_0100, AccountIAMInfo_AuthOptions_AdditionalInfo_0100` |
| AC-2.3 | NEW | EX-1 | TASK-2 | No verification needed, covered by XTS | `_test` |
| AC-3.1 | NEW | FR-2, BR-2 | TASK-3 | Unit test | `AuthCallback_UnlockAccount_CustomAuth_0100` |
| AC-3.2 | EXISTING | FR-2, BR-2 | TASK-3 | Unit test | `AuthCallback_UnlockUserScreen_CustomAuth_0100` |
| AC-3.3 | EXISTING | FR-2 | TASK-3 | Unit test | `AuthCallback_OnResult_CustomAuth_0100` |
| AC-3.4 | EXISTING | EX-2, RC-1 | TASK-3 | No verification needed, covered by XTS | `_test` |
| AC-3.5 | EXISTING | FR-3 | TASK-3 | Unit test | `AuthCallback_OnResult_CustomAuth_Deactivating_0100` |
| AC-4.1 | EXISTING | FR-4, BR-3 | TASK-3 | Unit test | `AuthCallback_UnlockAccount_CompanionDevice_0100` |
| AC-4.2 | NEW | FR-4, BR-3 | TASK-3 | Unit test | `AuthCallback_UnlockUserScreen_CompanionDevice_0100, AuthCallback_UnlockUserScreen_RecoveryKey_0100` |
| AC-4.3 | EXISTING+NEW | FR-4 | TASK-3 | Unit test | `AuthCallback_OnResult_CompanionDevice_0100` |
| AC-4.4 | EXISTING+NEW | EX-3, RC-2 | TASK-3 | No verification needed, covered by XTS (UnlockUserScreen retry is existing code; only need to verify COMPANION_DEVICE can unlock EL3/EL4, covered by AuthCallback_UnlockUserScreen_CompanionDevice_0100) | `_test` |
| AC-4.5 | EXISTING | FR-5 | TASK-3 | Unit test | `AuthCallback_OnResult_CompanionDevice_Deactivating_0100` |
| AC-5.1 | NEW | FR-6 | TASK-2 | No verification needed, covered by XTS (NAPI layer cannot be covered by unit tests) | `_test` |
| AC-5.2 | NEW | EX-1 | TASK-2 | No verification needed, covered by XTS (NAPI layer cannot be covered by unit tests) | `_test` |
| AC-6.1 | NEW | BR-1 | TASK-1 | Compile verification (external PR interface_sdk-js#33557) | `_test` |
| AC-6.2 | NEW | BR-1 | TASK-1 | Compile verification (external PR interface_sdk-js#33557) | `_test` |
| AC-7.1 | NEW | BR-4 | TASK-2 | Compile verification | `_test` |
| AC-7.2 | NEW | BR-4 | TASK-2 | Compile verification | `_test` |
| AC-7.3 | NEW | FR-7 | TASK-2 | No verification needed, covered by XTS (Taihe layer cannot be covered by unit tests) | `_test` |
| AC-7.4 | EXISTING+NEW | EX-4 | TASK-2 | No verification needed, covered by XTS (Taihe layer cannot be covered by unit tests) | `_test` |

## Business Rules

| ID | Source | Rule Description | Constraints | Related AC |
|----|--------|-----------------|-------------|------------|
| BR-1 | NEW | AuthType.CUSTOM = 128 is a new valid authentication type enum value | Value is a power of 2 (128), consistent with existing style, no conflict with DOMAIN=1024 | AC-1.1, AC-1.2, AC-1.3 |
| BR-2 | EXISTING+NEW | CUSTOM auth has the same security level as PIN/FACE/FINGERPRINT, with full EL2-EL5 decryption privilege | HandleAuthResult() only does early return for DOMAIN type (EXISTING); CUSTOM type naturally enters UnlockAccount() flow (EXISTING); CUSTOM is added to CheckAllowUnlockUserStorage allowlist (NEW) | AC-3.1, AC-3.2, AC-3.3 |
| BR-3 | EXISTING+NEW | COMPANION_DEVICE auth has EL3/EL4 decryption privilege (excluding EL2) | Remove COMPANION_DEVICE skip condition in UnlockUserScreen() (NEW), keep RECOVERY_KEY skip logic (EXISTING); COMPANION_DEVICE is not in CheckAllowUnlockUserStorage allowlist, does not trigger ActivateUserKey (EXISTING) | AC-4.1, AC-4.2, AC-4.3 |
| BR-4 | NEW | Taihe IDL and .d.ts type definitions must be consistent with InnerAPI | AuthType.CUSTOM=128, AuthOptions.additionalInfo are consistently defined across Taihe IDL, NAPI .d.ts, and InnerAPI layers | AC-5.1, AC-6.1, AC-6.2, AC-7.1, AC-7.2 |

## Functional Rules

| ID | Source | Rule Description | Trigger Condition | Target | Related AC |
|----|--------|-----------------|-------------------|--------|------------|
| FR-1 | NEW | additionalInfo as an optional string parameter, passed from NAPI layer to authentication flow | App sets options.additionalInfo | AuthOptions struct | AC-2.1, AC-2.2 |
| FR-2 | EXISTING+NEW | After CUSTOM auth success, execute ActivateUserKey + UnlockUserScreen full decryption flow | authType_ != DOMAIN and auth succeeds | User keys and encrypted storage | AC-3.1, AC-3.2, AC-3.3 |
| FR-3 | EXISTING | Do not execute user space decryption when account is in deactivating state | Target account is in deactivating state | Storage decryption flow | AC-3.5 |
| FR-4 | EXISTING+NEW | After COMPANION_DEVICE auth success, only execute UnlockUserScreen decryption flow (EL3/EL4), not ActivateUserKey (EL2) | authType_ == COMPANION_DEVICE and auth succeeds | User encrypted storage (only EL3/EL4) | AC-4.1, AC-4.2 |
| FR-5 | EXISTING | Do not execute user space decryption when COMPANION_DEVICE auth succeeds but account is deactivating | Target account is in deactivating state | Storage decryption flow | AC-4.5 |
| FR-6 | NEW | NAPI layer ParseContextForAuthOptions parses additionalInfo field | NAPI layer receives JavaScript authOptions object with additionalInfo having a value | AuthOptions struct | AC-5.1 |
| FR-7 | NEW | Taihe impl layer ConvertToAuthOptionsInner converts additionalInfo to native format | Taihe layer receives AuthOptions with additionalInfo having a value | Native AuthOptions struct | AC-7.3 |

## Exception/Exemption Rules

| ID | Source | Exception Code/Enum | Rule Description | Trigger Condition | Timeout Threshold | Result | Related AC |
|----|--------|---------------------|-----------------|-------------------|------------------|--------|------------|
| EX-1 | NEW | N/A | Treat undefined additionalInfo as not provided | NAPI layer receives undefined additionalInfo | N/A | Use default value, proceed normally | AC-2.3 |
| EX-2 | EXISTING | ERR_OK != result | Retry when ActivateUserKey or UnlockUserScreen fails | Auth succeeds but decryption operation returns non ERR_OK | 20 times × 100ms (total 2s) | Return error code on all retries failed, do not set verified/logged-in | AC-3.4 |
| EX-3 | EXISTING+NEW | ERR_OK != result | Retry when COMPANION_DEVICE auth succeeds but UnlockUserScreen fails | COMPANION_DEVICE auth succeeds but UnlockUserScreen returns non ERR_OK | 20 times × 100ms (total 2s) | Return error code on all retries failed, do not set verified/logged-in | AC-4.4 |
| EX-4 | NEW | N/A | Treat Taihe layer additionalInfo with no Optional value as not provided | ConvertToAuthOptionsInner receives additionalInfo with no Optional value | N/A | hasAdditionalInfo set to false, additionalInfo remains default empty string | AC-7.4 |

## Recovery Contracts

| ID | Source | Trigger Condition | Recovery Strategy | Recovery Result | Constraints |
|----|--------|-------------------|-------------------|-----------------|-------------|
| RC-1 | EXISTING | CUSTOM auth succeeds but decryption operation fails | Retry 20 times (100ms interval) | On success, continue setting verified/logged-in; on all retries failed, return error | Total timeout 2s |
| RC-2 | EXISTING+NEW | COMPANION_DEVICE auth succeeds but UnlockUserScreen fails | Retry 20 times (100ms interval) | On success, continue setting verified/logged-in; on all retries failed, return error | Total timeout 2s |

## Verification Mapping

| ID | Source | Corresponding Spec Item | Verification Method | Verification Focus | Evidence |
|----|--------|------------------------|---------------------|-------------------|----------|
| VM-1 | NEW | FR-1 / AC-2.1, AC-2.2, AC-2.3 | Unit test | additionalInfo passing and default value handling | `AccountIAMInfo_AuthParam_Marshalling_WithAdditionalInfo_0100, AccountIAMInfo_AuthOptions_AdditionalInfo_0100` |
| VM-2 | EXISTING+NEW | BR-2 / AC-3.1, AC-3.2, AC-3.3 | Unit test | Decryption flow execution after CUSTOM auth success | `AuthCallback_UnlockAccount_CustomAuth_0100, AuthCallback_UnlockUserScreen_CustomAuth_0100, AuthCallback_OnResult_CustomAuth_0100` |
| VM-3 | EXISTING | EX-2, RC-1 / AC-3.4 | No verification needed, covered by XTS | Decryption failure retry logic | — |
| VM-4 | EXISTING | FR-3 / AC-3.5 | Unit test | No decryption when account is deactivating | `AuthCallback_OnResult_CustomAuth_Deactivating_0100` |
| VM-5 | EXISTING+NEW | BR-3 / AC-4.1, AC-4.2 | Unit test | COMPANION_DEVICE only UnlockUserScreen (EL3/EL4) decryption, ActivateUserKey not called | `AuthCallback_UnlockAccount_CompanionDevice_0100, AuthCallback_UnlockUserScreen_CompanionDevice_0100` |
| VM-6 | EXISTING+NEW | EX-3, RC-2 / AC-4.4 | No verification needed, covered by XTS | COMPANION_DEVICE decryption failure retry | — |
| VM-7 | EXISTING | FR-5 / AC-4.5 | Unit test | No decryption when account is deactivating | `AuthCallback_OnResult_CompanionDevice_Deactivating_0100` |
| VM-8 | NEW | FR-6, EX-1 / AC-5.1, AC-5.2 | No verification needed, covered by XTS | NAPI layer additionalInfo parsing and undefined handling | — |
| VM-9 | NEW | BR-4, FR-7, EX-4 / AC-7.1, AC-7.2, AC-7.3, AC-7.4 | Compile verification (runtime testing covered by XTS) | Taihe IDL definition and ConvertToAuthOptionsInner conversion | — |

## API Change Analysis

### New APIs

| API Name | Scope | Parameter Summary | Return Value | Error Code Range | Description | Related AC |
|----------|-------|-------------------|--------------|------------------|-------------|------------|
| `AuthType.CUSTOM` (= 128) | Public | N/A (enum value) | N/A | N/A | Custom authentication type enum value | AC-1.1, AC-1.2, AC-1.3 |
| `AuthOptions.additionalInfo?: string` | Public | string type, optional | N/A (field) | N/A | Custom authentication additional info parameter | AC-2.1, AC-2.2, AC-2.3 |
| `ohos.account.osAccount.taihe` AuthType.CUSTOM / AuthOptions.additionalInfo | Public (Taihe IDL) | N/A | N/A | N/A | Taihe IDL type definitions | AC-7.1, AC-7.2 |
| `@ohos.account.osAccount.d.ts` AuthType.CUSTOM / AuthOptions.additionalInfo | Public (.d.ts) | N/A | N/A | N/A | TypeScript type declarations (external repo interface_sdk-js) | AC-6.1, AC-6.2 |

### Changed/Deprecated APIs

| API Name | Change Type | Impact Scenario | Migration Guide | Related AC |
|----------|-------------|-----------------|-----------------|------------|
| None | - | - | - | - |

## Compatibility Statement

- **Existing API behavior change:** No. Adding a new enum value to AuthType does not affect existing enum values' behavior; adding an optional field to AuthOptions does not affect existing callers
- **Configuration file format change:** No
- **Data storage format change:** No
- **Minimum supported version:** API Version 26.0.0
- **API version strategy:** New APIs are annotated with `@since` version number, with SysCap declaring capability
- **Cross-repo declaration change:** @ohos.account.osAccount.d.ts needs to be updated in the interface_sdk-js repo, annotated with `@since API Version 26.0.0` (external PR [interface_sdk-js#33557](https://gitcode.com/openharmony/interface_sdk-js/pull/33557))

## Architecture Constraints

| Key Constraint | Constraint Description | Affected AC |
|----------------|----------------------|-------------|
| Layered calling compliance | App → NAPI → InnerKit → Service → UserIam, reverse calling prohibited | AC-1.1, AC-2.1 |
| IPC serialization extension | AuthParam Marshalling/Unmarshalling needs to extend additionalInfo field | AC-2.1 |
| Auth callback processing | HandleAuthResult() only does early return for DOMAIN, other types naturally enter unlock flow | AC-3.1, AC-3.2 |
| NAPI parameter parsing extension | ParseContextForAuthOptions needs new additionalInfo field parsing, using GetOptionalStringPropertyByKey | AC-5.1 |
| Taihe parameter conversion extension | ConvertToAuthOptionsInner() needs to handle additionalInfo Optional<String> to native hasAdditionalInfo + string mapping | AC-7.3, AC-7.4 |
| Cross-repo type consistency | .d.ts (interface_sdk-js repo) and .taihe (this repo) AuthType/AuthOptions definitions must be consistent with InnerAPI account_iam_info.h | AC-6.1, AC-6.2, AC-7.1, AC-7.2 |

## Non-Functional Requirements

| Type | Metric/Threshold | Verification Method | Evidence |
|------|------------------|---------------------|----------|
| Security | CUSTOM/COMPANION_DEVICE has the same decryption privilege level as PIN | Unit test | `_test` |
| Reliability | Decryption failure retry mechanism (20 times × 100ms) | Unit test | `_test` |
| Troubleshooting | Reuse existing hilog logging (domain 0xD001B00) | hilog | `_test` |

## Multi-Device Adaptation Statement

| Device Type | Behavioral Difference | Spec/Constraint | Verification Method | Evidence |
|-------------|----------------------|-----------------|---------------------|----------|
| Phone | No difference | Full feature support | Unit test | `_test` |
| Tablet | No difference | Full feature support | Unit test | `_test` |

## Global Feature Impact

| Feature | Applicable? | Conclusion | Related Scenario |
|---------|-------------|------------|------------------|
| Accessibility | No | No UI change | N/A |
| Large font | No | No UI change | N/A |
| Dark mode | No | No UI change | N/A |
| Multi-window/split screen | No | No UI change | N/A |
| Multi-user | Yes | CUSTOM/COMPANION_DEVICE auth success sets isVerified/isLoggedIn | AC-3.3, AC-4.3 |
| Version upgrade | No | No data migration | N/A |
| Ecosystem compatibility | Yes | New optional field; old versions ignore additionalInfo | AC-2.2 |

## Behavioral Scenarios (Optional, Gherkin)

```gherkin
Feature: Custom Auth Type & Companion Device Unlock
  As an app developer/end user
  I want to use CUSTOM auth type with full user space decryption support
  So that I can integrate custom auth plugins and get an unlock experience consistent with PIN auth

  Scenario: CUSTOM auth with additionalInfo
    Given the app has configured a custom authentication plugin
    When the app calls UserAuth.auth() with authType = 128 and options.additionalInfo = "Custom Data"
    Then the system accepts the auth type and passes additional information to the auth flow

  Scenario: CUSTOM auth without additionalInfo
    Given the app has configured a custom authentication plugin
    When the app calls UserAuth.auth() with authType = 128 and does not set options.additionalInfo
    Then the system accepts the auth type and the auth flow proceeds normally

  Scenario: CUSTOM auth success unlocks EL2
    Given custom auth succeeds and token and secret are valid
    When AuthCallback.OnResult() processes the auth result
    Then the system calls ActivateUserKey() to decrypt EL2 storage

  Scenario: CUSTOM auth success unlocks EL3/EL4
    Given custom auth succeeds and the screen is locked
    When AuthCallback.OnResult() processes the auth result
    Then the system calls UnlockUserScreen() to decrypt EL3/EL4 storage

  Scenario: CUSTOM auth sets verified status
    Given custom auth succeeds and user space unlock is complete
    Then the OS account's isVerified and isLoggedIn status are true

  Scenario: CUSTOM auth unlock failure retries
    Given custom auth succeeds but ActivateUserKey() returns an error
    When the system executes retries
    Then up to 20 retries at 100ms intervals
    And on all retries failed, returns error and does not set verified/logged-in

  Scenario: CUSTOM auth does not unlock deactivating account
    Given custom auth succeeds but the target account is in deactivating state
    Then the system does not execute user space decryption
    And the system returns the auth result without modifying storage state

  Scenario: COMPANION_DEVICE auth success does NOT unlock EL2
    Given trusted possession auth succeeds and token and secret are valid
    When AuthCallback.OnResult() processes the auth result
    Then the system does not call ActivateUserKey()
    And EL2 storage is not decrypted

  Scenario: COMPANION_DEVICE auth success unlocks EL3/EL4
    Given trusted possession auth succeeds and the screen is locked
    When AuthCallback.OnResult() processes the auth result
    Then the system calls UnlockUserScreen() to decrypt EL3/EL4 storage
    And the system does not skip the UnlockUserScreen flow

  Scenario: COMPANION_DEVICE auth unlock failure retries
    Given trusted possession auth succeeds but UnlockUserScreen() returns an error
    When the system executes retries
    Then up to 20 retries at 100ms intervals
    And on all retries failed, returns error and does not set verified/logged-in

  Scenario: NAPI parses valid additionalInfo
    Given NAPI layer receives JavaScript authOptions object containing additionalInfo
    When ParseContextForAuthOptions parses parameters
    Then additionalInfo field is parsed as a valid string
    And hasAdditionalInfo is set to true

  Scenario: NAPI parses undefined additionalInfo
    Given NAPI layer receives JavaScript authOptions object without additionalInfo or with undefined value
    When ParseContextForAuthOptions parses parameters
    Then additionalInfo is treated as not provided
    And hasAdditionalInfo is set to false

  Scenario: TypeScript type declaration includes CUSTOM and additionalInfo
    Given @ohos.account.osAccount.d.ts file is updated
    Then AuthType.CUSTOM = 128 is declared as a valid enum value
    And AuthOptions.additionalInfo?: string is declared as a valid optional field

  Scenario: Taihe IDL defines CUSTOM and additionalInfo
    Given ohos.account.osAccount.taihe is updated
    Then AuthType enum includes CUSTOM = 128 value
    And AuthOptions struct includes additionalInfo: Optional<String> field

  Scenario: Taihe converts additionalInfo to native format
    Given Taihe layer receives AuthOptions with additionalInfo having a value
    When ConvertToAuthOptionsInner() executes conversion
    Then hasAdditionalInfo is set to true and additionalInfo is converted to native std::string

  Scenario: Taihe converts additionalInfo when undefined
    Given Taihe layer receives AuthOptions with additionalInfo having no Optional value
    When ConvertToAuthOptionsInner() executes conversion
    Then hasAdditionalInfo is set to false and additionalInfo remains default empty string
```

## Spec Self-Review Checklist

- [x] No placeholder text such as "pending", "TBD", "TODO"
- [x] All ACs use WHEN/THEN format, independently testable
- [x] Scope boundaries are clear (what to do / what not to do is explicit)
- [x] No semantically ambiguous expressions
- [x] ACs are cross-consistent with business rules / exception rules / recovery contracts

## context-references

```yaml
context-queries:
  - repo: "openharmony/os_account"
    query: "Full implementation logic of HandleAuthResult() and UnlockUserScreen() in account_iam_callback.cpp, including DOMAIN type skip condition and COMPANION_DEVICE skip condition"
  - repo: "openharmony/os_account"
    query: "AuthType, AuthTypeIndex, IAMAuthType enum definitions and AuthOptions struct definition in account_iam_info.h"
  - repo: "openharmony/os_account"
    query: "Parameter parsing logic of ParseContextForAuthOptions in napi_account_iam_user_auth.cpp"
  - repo: "openharmony/os_account"
    query: "AuthType enum and AuthOptions struct definitions in ohos.account.osAccount.taihe, including CUSTOM value and additionalInfo field"
  - repo: "openharmony/os_account"
    query: "additionalInfo conversion logic of ConvertToAuthOptionsInner() in ohos.account.osAccount.impl.cpp"
```

**Key Documents:**
- AGENTS.md (this repo knowledge base)
- account_iam_callback.cpp (auth callback processing)
- account_iam_info.h (data structure definitions)
- napi_account_iam_user_auth.cpp (NAPI parameter parsing)
- ohos.account.osAccount.taihe (Taihe IDL type definitions)
- ohos.account.osAccount.impl.cpp (Taihe impl layer parameter conversion)
- @ohos.account.osAccount.d.ts (TypeScript type declarations, external repo interface_sdk-js)