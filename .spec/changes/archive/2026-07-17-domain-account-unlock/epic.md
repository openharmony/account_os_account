# Epic Specification

> Overall planning for complex/critical cross-subsystem large features. Aimed at SIG groups and architects, guiding cross-repository decomposition and coordination.

## Overview

| Attribute | Value |
|------|-----|
| Feature Name | Device unlock using domain account (DomainAccount) information |
| Feature ID | EPIC-20260703-001 |
| Target | Support unlocking the device encrypted file system (EL2-EL4) via domain account authentication, and support enabling/disabling this capability per user |
| Business Value | In PC scenarios, users can use the domain account password to unlock the lock screen without maintaining an additional PIN; enterprise scenarios unify identity authentication and device unlock |
| Priority | P0 |
| Target Version | TBD (refer to manifest.target_release) |
| Complexity | Complex |

## Requirement Baseline

| Item | Content |
|----|------|
| Target | (1) Enable/disable domain account unlock capability per user + PIN flow adaptation + status query; (2) Domain account authentication with unlock intent → storage unlock (EL2+EL3/EL4) |
| Non-Goals | Public API changes, AuthCallback class modification, existing Auth/AuthUser non-DOMAIN path changes, local state persistence, new GN flag, plugin implementation logic |
| Success Metrics | SetDomainAuthUnlockEnabled available; GetUnlockDeviceConfig queryable; AuthWithUnlockIntent can trigger EL2+EL3/EL4 unlock; PIN flow auto-adapts; devices without plugin default to "not enabled" |

## SIG Ownership and Coordination

| Attribute | Value |
|------|-----|
| Lead SIG | SIG_Account |
| Participating SIG | None (all changes within the account subsystem) |
| Coordination Mechanism | No cross-SIG coordination needed |

## Affected Subsystems

| Subsystem | Component | Module | Impact Type | Owner |
|--------|------|------|----------|--------|
| account | os_account | AccountIAM (InnerKit + Service) | Modified (new SetDomainAuthUnlockEnabled API + IDL + business logic + PIN adaptation) | Account Team |
| account | os_account | DomainAccount (InnerKit + Service + Plugin Adapter) | Modified (AuthUser signature modification + AuthUserWithUnlockOptions IDL + GetUnlockDeviceConfig internal method + plugin C-ABI extension + unlock logic) | Account Team |
| account | os_account | Storage integration (InnerAccountIAMManager) | Modified (reuse existing ActivateUserKey/UnlockUserScreen/UpdateUserAuth) | Account Team |

## Feature Decomposition

### Feature Breakdown

| Feature ID | Name | Module | Priority | Dependencies | Estimated Effort |
|------------|------|----------|--------|------|-----------|
| F1 | Plugin interface extension | DomainAccount (C-ABI + Adapter) | P0 | None | 2 person-days |
| F2 | Domain account unlock capability switch | AccountIAM + DomainAccount | P0 | None (parallel with F1) | 3 person-days |
| F3 | Domain account unlock flow | AccountIAM + DomainAccount + Storage | P0 | F1 + F2 | 3 person-days |

### Feature Details

#### F1: Plugin Interface Extension

**Target:** Extend the domain account plugin C-ABI interface, add unlock authentication function and config query function, providing the plugin layer foundation for F2 and F3.

**Change Scope:**
- `domain_plugin.h`: `PluginAuthResultInfo` adds `secret` field; add `AuthWithUnlockIntentFunc`, `GetUnlockDeviceConfigResultFunc` function pointer types; add `PluginUnlockDeviceConfigResult` struct; add `UnlockDeviceMode` enum; `PluginMethodEnum` adds `AUTH_WITH_UNLOCK_INTENT`, `GET_UNLOCK_DEVICE_CONFIG`
- `domain_account_common.h`: `DomainAuthResult` adds `secret` field; add `DomainAccountUnlockOptions` struct (containing `challenge` + `authIntent`)
- `domain_plugin_adapter.cpp`: `METHOD_NAME_MAP` adds mapping; `LoadPlugin` iterates new enums; `GetAndCleanPluginAuthResultInfo` extracts `secret`; add `GetAndCleanPluginUnlockDeviceConfigResult`
- `account_iam_callback_service.cpp`: `DomainAuthCallbackAdapter::OnResult` does not set `ATTR_ROOT_SECRET`
- `mock_domain_so_plugin.cpp`: Add mock implementation

**AC Mapping:** AC-3.4 (secret field extraction), AC-3.6 (challenge passing), AC-2.1 (config query plugin call)

#### F2: Domain Account Unlock Capability Switch

**Target:** Provide InnerKit API to enable/disable domain account unlock, adapt PIN add/delete flows, support config query and feature isolation.

**Change Scope:**
- `account_iam_client.h/.cpp`: Add `SetDomainAuthUnlockEnabled` method
- `IAccountIAM.idl`: Add `SetDomainAuthUnlockEnabled` IDL method
- `account_iam_service.cpp`: Add stub implementation (permission check + delegate)
- `inner_account_iam_manager.cpp`: Business logic (uid check + parameter validation + storage key management)
- `inner_domain_account_manager.cpp`: Implement `GetUnlockDeviceConfig` internal method (calls plugin, not exposed externally)
- `account_iam_callback.cpp`: `AddCredCallback`/`DelCredCallback`/`VerifyTokenCallbackWrapper` PIN flow adaptation
- Feature isolation: `libHandle_ != nullptr` check

**AC Mapping:** AC-1.1~1.9 (switch flow), AC-2.1~2.2 (status query), AC-4.1~4.5 (PIN adaptation)

#### F3: Domain Account Unlock Flow

**Target:** Implement the domain account authentication flow with unlock intent, from plugin async authentication to storage unlock (EL2+EL3/EL4) complete chain.

**Change Scope:**
- `account_iam_client.cpp`: No separate client function; `AuthUser` calls `StartDomainAuth` for all DOMAIN auth (passing `DomainAccountUnlockOptions`); authIntent routing is server-side in `AuthUserWithUnlockOptions`
- `domain_account_client.h/.cpp`: Modify hook-based `AuthUser` signature (add `DomainAccountUnlockOptions` parameter)
- `IDomainAccount.idl`: Add `AuthUserWithUnlockOptions` IDL method
- `domain_account_manager_service.cpp`: Add `AuthUserWithUnlockOptions` stub
- `inner_domain_account_manager.h/.cpp`: Add `AuthUserWithUnlockOptions` business implementation (detect `authIntent=UNLOCK` and route to plugin `AuthWithUnlockIntent`); `InnerDomainAuthCallback` adds `authIntent_` member; insert unlock logic in `OnResult` (`ActivateUserKey` + `UnlockUserScreen` + `SetOsAccountIsVerified`)
- Binding + unlock check: call `GetUnlockDeviceConfig` to validate

**AC Mapping:** AC-3.1~3.10 (all unlock flow ACs)

### Dependency Relationships

```
F1 (Plugin interface extension) ──┐
                                   ├──▶ F3 (Domain account unlock flow)
F2 (Unlock capability switch)   ──┘

F1 and F2 have no dependencies and can be developed in parallel.
F3 depends on F1 (needs AuthWithUnlockIntent + secret field + GetUnlockDeviceConfigResult plugin interface)
F3 depends on F2 (needs GetUnlockDeviceConfig query method + libHandle_ feature isolation)
```

### Parallel Strategy

- F1 and F2 can be developed in parallel, with no file conflicts (F1 focuses on plugin.h + adapter + mock; F2 focuses on IAM client/service/manager + domain client)
- F3 must start after F1 and F2 complete
- F3 can be further split internally: skeleton Task (new IDL method + Client/Service framework) → behavior Task (plugin call + unlock logic) → test Task

## Cross-Repository Dependencies

| Repository | Branch | Role | Dependency Repository | Notes |
|------|------|------|----------|------|
| os_account | master | Main repository | - | Core implementation |
| Domain account plugin repository (external) | - | Dependent library | os_account | Plugin .so needs synchronous upgrade to export new symbols |
| storage_service (external) | - | Runtime dependency | - | Reuse existing StorageManager API, no modification needed |
| user_auth_framework (external) | - | Runtime dependency | - | Reuse existing UserAccessCtrlClient::VerifyAuthToken, no modification needed |

## Milestones

| Milestone | Target Date | Deliverables | Owner |
|--------|----------|--------|--------|
| M1: Requirement baseline passed | 2026-07-03 | proposal.md + epic.md + design.md + gate-define.md | Account Team |
| M2: F1 + F2 design review passed | TBD | F1/F2 spec.md + gate-design.md | Account Team |
| M3: F1 + F2 implementation complete | TBD | F1/F2 code + tests + execution-plan | Account Team |
| M4: F3 design review passed | TBD | F3 spec.md + gate-design.md (F3 depends on F1+F2 complete) | Account Team |
| M5: F3 implementation complete | TBD | F3 code + tests | Account Team |
| M6: Integration verification complete | TBD | Full AC verification + regression tests + gate-implement.md | Account Team |

## API Change Overview

| API Type | Count | Notes |
|----------|------|------|
| InnerKit API additions | 2 | SetDomainAuthUnlockEnabled, AuthUser signature modification |
| Internal method additions | 1 | InnerDomainAccountManager::GetUnlockDeviceConfig (not exposed externally) |
| New struct | 1 | DomainAccountUnlockOptions (challenge + authIntent) |
| IDL method additions | 2 | IAccountIAM::SetDomainAuthUnlockEnabled, IDomainAccount::AuthUserWithUnlockOptions |
| C-ABI plugin function additions | 2 | AuthWithUnlockIntent, GetUnlockDeviceConfigResult |
| C-ABI struct/enum additions | 3 | PluginUnlockDeviceConfigResult, UnlockDeviceMode, PluginAuthResultInfo.secret |
| C-ABI enum value additions | 2 | PluginMethodEnum::AUTH_WITH_UNLOCK_INTENT, GET_UNLOCK_DEVICE_CONFIG |
| InnerAPI struct extension | 1 | DomainAuthResult.secret |
| Public API additions | 0 | No Public API changes |
| API deprecations | 0 | None |

## Compatibility Statement

- **Forward compatible:** New fields (`secret`, `secret`) are added incrementally, existing authentication flows are not affected; new plugin functions are additions, do not affect existing `Auth`/`AuthWithPopup`/`AuthWithToken` calls
- **Backward compatible:** Plugin .so needs synchronous upgrade; old plugin .so will fail to load due to `LoadPlugin` iterating new enum values, need to ensure plugin is updated synchronously on devices
- **Compatibility guarantee:** `libHandle_` runtime check ensures devices without plugin default to "not enabled", does not affect existing features

## Risk Assessment

| Risk | Impact | Likelihood | Mitigation Measures |
|------|------|--------|----------|
| Plugin .so not upgraded synchronously causing load failure | High | Medium | Plugin team upgrades synchronously; `libHandle_` check ensures feature defaults to off when no plugin |
| Token zeroed at OnResult line 232 causing unlock failure | High | Low | Unlock logic inserted before line 232; self-zeroing after unlock |
| PIN flow adaptation querying plugin config introduces sync delay | Medium | Medium | `GetUnlockDeviceConfigResult` is a synchronous plugin call, need to assess performance impact; cache result if necessary |
| InnerDomainAuthCallback unlock logic inconsistent with existing PIN unlock path | Medium | Low | Mirror `UnlockAccount`/`UnlockUserScreen` logic; reuse the same `InnerAccountIAMManager` API |
| New IDL methods affect IPC serialization | Low | Low | IDL methods are additions, do not affect existing methods |

## context-references

```yaml
context-queries:
  - repo: "openharmony/os_account"
    query: "domain_plugin.h PluginAuthResultInfo struct and PluginMethodEnum"
  - repo: "openharmony/os_account"
    query: "InnerDomainAuthCallback::OnResult token zeroing at line 232"
  - repo: "openharmony/os_account"
    query: "DomainPluginAdapter::LoadPlugin method enumeration and dlsym"
  - repo: "openharmony/os_account"
    query: "InnerAccountIAMManager public unlock APIs: ActivateUserKey, UnlockUserScreen"
  - repo: "openharmony/os_account"
    query: "AccountIAMClient::AuthUser DOMAIN early-return at line 396-404"
```

**Key documents:** `./domain_unlock_overview.md` (design document), `.spec/changes/archive/2026-06-09-custom-auth-unlock/` (reference feature)
