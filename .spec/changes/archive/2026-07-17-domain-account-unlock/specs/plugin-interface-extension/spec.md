# Feature Specification

> Solidifies user-visible behavior and acceptance criteria. Complex interactions, state machines, and exception flows may be supplemented with Gherkin scenarios.

## Overview

| Attribute | Value |
|------|-----|
| Feature name | Plugin Interface Extension |
| Feature ID | FEAT-F1 |
| Parent Epic | EPIC-20260703-001 |
| Priority | P0 |
| Target version | TBD (reference manifest.target_release) |
| SIG ownership | SIG_Account |
| Status | Approved |
| Complexity | Medium |

## Scope of This Change (Delta)

| Type | Content | Description |
|------|------|------|
| ADDED | `PluginAuthResultInfo.secret` field | Plugin authentication result adds a secret field for storage unlock |
| ADDED | `DomainAuthResult.secret` field | Mirrors the secret field on the InnerAPI side |
| ADDED | `DomainAccountUnlockOptions` struct | Carries `challenge` + `authIntent` for unlock authentication; plain struct (not `Parcelable`), cross-process transfer converts to IDL struct `DomainAccountUnlockOptionsIdl` (auto-serialized by IDL) |
| ADDED | `AuthWithUnlockIntent` plugin C-ABI function | Domain account plugin authentication with unlock intent |
| ADDED | `GetUnlockDeviceConfigResult` plugin C-ABI function | Queries unlock device configuration from the plugin |
| ADDED | `PluginUnlockDeviceConfigResult` struct | Unlock configuration result |
| ADDED | `UnlockDeviceMode` enum | OFFLINE_AUTH_UNLOCK_DEVICE=1, ONLINE_OFFLINE_AUTH_UNLOCK_DEVICE=2 |
| ADDED | `PluginMethodEnum::AUTH_WITH_UNLOCK_INTENT` | Plugin method enum |
| ADDED | `PluginMethodEnum::GET_UNLOCK_DEVICE_CONFIG` | Plugin method enum |
| MODIFIED | `DomainPluginAdapter::LoadPlugin` | Traverses the newly added enum values, requires the plugin to export new symbols |
| MODIFIED | `DomainPluginAdapter::GetAndCleanPluginAuthResultInfo` | Extracts the `secret` field into `DomainAuthResult.secret` |
| MODIFIED | `DomainAuthCallbackAdapter::OnResult` | Does NOT set `ATTR_ROOT_SECRET`; `secret` is only used at the service layer (`inner_domain_account_manager` / `inner_account_iam_manager`) for unlock storage, not passed back to `IDMCallback` |
| ADDED | `DomainPluginAdapter::GetAndCleanPluginUnlockDeviceConfigResult` | Converts the plugin query result |
| ADDED | Mock plugin `AuthWithUnlockIntent` + `GetUnlockDeviceConfigResult` | Mock implementation for testing |

## Input Documents

| Document | Path | Status |
|------|------|------|
| Requirement | `proposal.md` | Approved |
| Design | `design.md` | Approved |
| Epic | `epic.md` | Approved |

## User Stories

### US-F1-1: Plugin Authentication Result Carries secret

**As** a system developer,
**I want** the plugin authentication result to include a secret field,
**so that** after domain account authentication succeeds, token + secret can be used for storage unlock.

**Acceptance criteria:**

- **AC-F1-1.1:** WHEN the `AuthWithUnlockIntent` plugin function authenticates successfully THEN `PluginAuthResultInfo` should contain non-empty `accountToken` and `secret` fields
- **AC-F1-1.2:** WHEN `DomainPluginAdapter::GetAndCleanPluginAuthResultInfo` extracts the result THEN `DomainAuthResult.secret` should be populated from `PluginAuthResultInfo.secret`
- **AC-F1-1.3:** WHEN `DomainAuthCallbackAdapter::OnResult` converts the result THEN `Attributes` should NOT set `ATTR_ROOT_SECRET`; `secret` is only used at the service layer (`inner_domain_account_manager` / `inner_account_iam_manager`) for unlock storage, not passed back to `IDMCallback` via `OnResult`

### US-F1-2: Plugin Unlock Configuration Query

**As** a system developer,
**I want** to query domain account unlock configuration via the plugin,
**so that** the PIN flow adaptation and unlock flow checks can determine the current unlock strategy.

**Acceptance criteria:**

- **AC-F1-2.1:** WHEN calling the `GetUnlockDeviceConfigResult` plugin function THEN it should return `PluginUnlockDeviceConfigResult` containing `enableUnlockDevice` and `unlockDeviceMode`
- **AC-F1-2.2:** WHEN `DomainPluginAdapter::GetAndCleanPluginUnlockDeviceConfigResult` extracts the result THEN it should correctly convert `enableUnlockDevice` and `unlockDeviceMode` and free the memory allocated by the plugin

### US-F1-3: DomainAccountUnlockOptions Struct

**As** a system developer,
**I want** a standalone struct carrying challenge and authIntent,
**so that** unlock authentication parameters can be passed via IPC without conflicting with the existing DomainAccountAuthOptions.

**Acceptance criteria:**

- **AC-F1-3.1:** WHEN `DomainAccountUnlockOptions` contains `challenge` and `authIntent` fields THEN the struct is a plain struct (not inheriting `Parcelable`); cross-process transfer converts to IDL struct `DomainAccountUnlockOptionsIdl` (auto-serialized by IDL)
- **AC-F1-3.2:** WHEN `DomainAccountUnlockOptions` is converted to `DomainAccountUnlockOptionsIdl` for IPC transfer then converted back THEN field values should remain consistent

### US-F1-4: Plugin Loading Compatibility

**As** a system developer,
**I want** LoadPlugin to be able to load the newly added plugin function symbols,
**so that** after the plugin is upgraded in sync, the new features are available.

**Acceptance criteria:**

- **AC-F1-4.1:** WHEN `LoadPlugin` traverses `PluginMethodEnum` THEN it should include `AUTH_WITH_UNLOCK_INTENT` and `GET_UNLOCK_DEVICE_CONFIG` enum values
- **AC-F1-4.2:** WHEN the plugin .so exports the `AuthWithUnlockIntent` and `GetUnlockDeviceConfigResult` symbols THEN `LoadPlugin` should load successfully and obtain the function pointers via `dlsym`
- **AC-F1-4.3:** WHEN the plugin .so does not export new symbols THEN `LoadPlugin` should fail to load (plugin sync-upgrade requirement)

## Acceptance Traceability

| AC | Related rule | Related Task | Verification method | Evidence |
|----|----------|-----------|----------|------|
| AC-F1-1.1 | BR-F1-1 | TASK-1, TASK-2 | Unit test | `domain_plugin_adapter_test.cpp` |
| AC-F1-1.2 | BR-F1-1 | TASK-2 | Unit test | `domain_plugin_adapter_test.cpp` |
| AC-F1-1.3 | BR-F1-1 | TASK-3 | Unit test | `account_iam_callback_service_test.cpp` |
| AC-F1-2.1 | BR-F1-2 | TASK-2, TASK-4 | Unit test | `domain_plugin_adapter_test.cpp` |
| AC-F1-2.2 | BR-F1-2 | TASK-2 | Unit test | `domain_plugin_adapter_test.cpp` |
| AC-F1-3.1 | BR-F1-3 | TASK-1 | Unit test | `domain_account_common_test.cpp` |
| AC-F1-3.2 | BR-F1-3 | TASK-1 | Unit test | `domain_account_common_test.cpp` |
| AC-F1-4.1 | BR-F1-4 | TASK-2 | Unit test | `domain_plugin_adapter_test.cpp` |
| AC-F1-4.2 | BR-F1-4 | TASK-2, TASK-4 | Unit test | `mock_domain_so_plugin_test.cpp` |
| AC-F1-4.3 | BR-F1-4 | TASK-2 | Unit test | `domain_plugin_adapter_test.cpp` |

## Business Rules

| ID | Rule description | Constraints | Related AC |
|------|----------|----------|---------|
| BR-F1-1 | `secret` field is an incremental addition that does not affect the existing `accountToken` field | The position and semantics of `accountToken` in `PluginAuthResultInfo` remain unchanged | AC-F1-1.1~1.3 |
| BR-F1-2 | The plugin query result memory is freed by `DomainPluginAdapter` | `GetAndCleanPluginUnlockDeviceConfigResult` frees the plugin-allocated `PluginUnlockDeviceConfigResult` after extraction | AC-F1-2.1~2.2 |
| BR-F1-3 | `DomainAccountUnlockOptions` does not extend the existing `DomainAccountAuthOptions` | Standalone plain struct (not `Parcelable`); cross-process transfer via `DomainAccountUnlockOptionsIdl` (IDL auto-serialization); does not affect the `AuthWithParameters` IDL method | AC-F1-3.1~3.2 |
| BR-F1-4 | Plugin sync-upgrade; all .so files must export new symbols | `LoadPlugin` traverses all `PluginMethodEnum` values; missing symbols cause load failure | AC-F1-4.1~4.3 |

## Functional Rules

| ID | Rule description | Trigger condition | Target | Related AC |
|------|----------|----------|----------|---------|
| FR-F1-1 | `GetAndCleanPluginAuthResultInfo` extracts the `secret` field | `AuthWithUnlockIntent` authentication success callback | `DomainAuthResult.secret` | AC-F1-1.2 |
| FR-F1-2 | `DomainAuthCallbackAdapter::OnResult` does NOT set `ATTR_ROOT_SECRET`; `secret` is only used at the service layer for unlock storage | Domain account authentication result converts to `Attributes` | `Attributes` object | AC-F1-1.3 |
| FR-F1-3 | `METHOD_NAME_MAP` adds symbol mappings | `LoadPlugin` initialization | `methodMap_` | AC-F1-4.1 |

## Exception/Exemption Rules

| ID | Exception code/enum | Rule description | Trigger condition | Timeout threshold | Result | Related AC |
|------|------------|----------|----------|----------|----------|---------|
| EX-F1-1 | ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST | Plugin method symbol not exported | `dlsym` returns nullptr | N/A | LoadPlugin fails, `libHandle_` is nullptr | AC-F1-4.3 |
| EX-F1-2 | ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR | `DomainAccountUnlockOptionsIdl` deserialization failure | IPC data corruption | N/A | Returns error, does not continue processing | AC-F1-3.2 |

## Recovery Contract

| ID | Trigger condition | Recovery strategy | Recovery result | Constraints |
|------|----------|----------|----------|------|
| RC-F1-1 | Plugin query result is nullptr | Returns default value `enableUnlockDevice=false` | Feature degrades to "not enabled" | Does not crash |
| RC-F1-2 | `GetAndCleanPluginAuthResultInfo` extraction failure | `DomainAuthResult.secret` is empty | Subsequent unlock logic receives an empty secret, handled by the caller | Does not crash |

## Verification Mapping

| ID | Corresponding spec item | Verification method | Verification focus |
|------|------------|----------|----------|
| VM-F1-1 | FR-F1-1 / AC-F1-1.2 | Unit test | `secret` field correctly extracted into `DomainAuthResult.secret` |
| VM-F1-2 | FR-F1-2 / AC-F1-1.3 | Unit test | `ATTR_ROOT_SECRET` is NOT set by `DomainAuthCallbackAdapter::OnResult` |
| VM-F1-3 | FR-F1-3 / AC-F1-4.1 | Unit test | `METHOD_NAME_MAP` includes new symbols |
| VM-F1-4 | BR-F1-3 / AC-F1-3.2 | Unit test | `DomainAccountUnlockOptions` ↔ `DomainAccountUnlockOptionsIdl` conversion is consistent |
| VM-F1-5 | BR-F1-4 / AC-F1-4.2 | Integration test | Mock plugin LoadPlugin succeeds |

## API Change Analysis

### New APIs

| API name | Exposure scope | Input parameters summary | Return value | Error code range | Feature description | Related AC |
|----------|----------|----------|--------|------------|----------|---------|
| `PluginAuthResultInfo.secret` | C-ABI | `PluginUint8Vector secret` | N/A (struct field) | N/A | Unlock secret | AC-F1-1.1 |
| `DomainAuthResult.secret` | InnerAPI | `std::vector<uint8_t> secret` | N/A (struct field) | N/A | Secret mirrored from plugin | AC-F1-1.2 |
| `DomainAccountUnlockOptions` | InnerAPI | `challenge` + `authIntent` | N/A (plain struct, not `Parcelable`) | N/A | Unlock authentication extension options; cross-process transfer via `DomainAccountUnlockOptionsIdl` | AC-F1-3.1 |
| `AuthWithUnlockIntent` plugin function | C-ABI | `domainAccountInfo, credential, callerLocalId, challengeValue, callback, contextId` | `PluginBusinessError*` | Plugin-defined | Authentication with unlock intent | AC-F1-1.1 |
| `GetUnlockDeviceConfigResult` plugin function | C-ABI | `domainAccountInfo` | `PluginUnlockDeviceConfigResult**` | Plugin-defined | Query unlock configuration | AC-F1-2.1 |
| `PluginUnlockDeviceConfigResult` | C-ABI | `enableUnlockDevice` + `unlockDeviceMode` | N/A (struct) | N/A | Unlock configuration result | AC-F1-2.1 |
| `UnlockDeviceMode` | C-ABI | `OFFLINE_AUTH_UNLOCK_DEVICE=1, ONLINE_OFFLINE_AUTH_UNLOCK_DEVICE=2` | N/A (enum) | N/A | Unlock mode | AC-F1-2.1 |

### Changed/Deprecated APIs

| API name | Change type | Affected scenarios | Migration guide | Related AC |
|----------|----------|----------|----------|---------|
| `PluginAuthResultInfo` | Changed (field added) | All code using `PluginAuthResultInfo` | `accountToken` unchanged; `secret` is an incremental addition; `GetAndCleanPluginAuthResultInfo` needs to be extended | AC-F1-1.2 |
| `DomainAuthResult` | Changed (field added) | All code using `DomainAuthResult` | `Marshalling`/`ReadFromParcel` needs to be extended to serialize `secret`; when an older version deserializes, `secret` is empty | AC-F1-1.2 |
| `DomainAuthCallbackAdapter::OnResult` | Modified | Domain account authentication result callback | Does NOT set `ATTR_ROOT_SECRET`; `secret` is only used at the service layer for unlock storage | AC-F1-1.3 |
| `DomainPluginAdapter::LoadPlugin` | Modified | Plugin loading | `METHOD_NAME_MAP` adds 2 mappings; traverses new enum values | AC-F1-4.1 |

## Compatibility Statement

- **Existing API behavior changes:** No. `accountToken` field unchanged; `LoadPlugin` traverses newly added enums but does not affect existing symbol loading
- **Config file format changes:** No
- **Data storage format changes:** No. `DomainAuthResult` serialization extension is incremental (adds `secret` field); when an older version deserializes, `secret` is empty, which does not affect existing logic
- **Minimum supported version:** TBD
- **API version number strategy:** N/A (InnerAPI, no @since annotation)

## Architecture Constraints

| Key constraint | Constraint description | Affected AC |
|----------|----------|---------|
| C-ABI struct extension is incremental | `PluginAuthResultInfo` adding the `secret` field does not change the order and semantics of existing fields | AC-F1-1.1 |
| Plugin .so sync-upgrade | `LoadPlugin` traverses all `PluginMethodEnum`; missing symbols cause load failure | AC-F1-4.3 |
| `DomainAccountUnlockOptions` is independent of `DomainAccountAuthOptions` | Plain struct (not `Parcelable`); cross-process transfer converts to IDL struct `DomainAccountUnlockOptionsIdl`; does not affect `AuthWithParameters` IDL serialization | AC-F1-3.1 |

## Non-Functional Requirements

| Type | Metric/threshold | Verification method | Evidence |
|------|-----------|----------|------|
| Security | `secret` field is zeroed with `memset_s` after extraction | Code review | `domain_plugin_adapter.cpp` |
| Reliability | Plugin query failure returns a default value, does not crash | Unit test | `domain_plugin_adapter_test.cpp` |

## Multi-Device Adaptation Statement

| Device type | Behavior difference | Spec/constraint | Verification method | Evidence |
|----------|----------|-----------|----------|------|
| All devices | No difference | Plugin interface extension is at the C-ABI layer, device-agnostic | N/A | N/A |

## Global Feature Impact

| Feature | Applicable? | Conclusion | Related scenarios |
|------|--------|------|----------|
| Accessibility | No | C-ABI interface extension, no UI | N/A |
| Large font | No | No UI | N/A |
| Dark mode | No | No UI | N/A |
| Multi-window/split-screen | No | No UI | N/A |
| Multi-user | No | Plugin interface layer, not related to multi-user | N/A |
| Version upgrade | Yes | Plugin .so needs sync-upgrade | New symbols available after upgrade |
| Ecosystem compatibility | No | C-ABI internal contract | N/A |

## Spec Self-Review Checklist

- [x] No placeholders like "TBD", "TODO", etc. (except target version TBD, references manifest)
- [x] All ACs use WHEN/THEN format and can be tested independently
- [x] Scope boundaries are clear (what to do / what not to do is clear)
- [x] No semantically ambiguous statements
- [x] ACs are cross-consistent with business rules/exception rules/recovery contracts

## context-references

```yaml
context-queries:
  - repo: "openharmony/os_account"
    query: "domain_plugin.h PluginAuthResultInfo struct and PluginMethodEnum"
  - repo: "openharmony/os_account"
    query: "DomainPluginAdapter::LoadPlugin and GetAndCleanPluginAuthResultInfo"
  - repo: "openharmony/os_account"
    query: "DomainAuthCallbackAdapter::OnResult ATTR_SIGNATURE (ATTR_ROOT_SECRET not set)"
  - repo: "openharmony/os_account"
    query: "domain_account_common.h DomainAuthResult and DomainAccountAuthOptions"
```

**Key documents:** `design.md` §ADR-5 (plugin loading compatibility), §C-ABI plugin interface additions
