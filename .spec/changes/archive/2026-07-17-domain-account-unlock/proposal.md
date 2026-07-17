# Requirements Document

> A document tracking the original requirement through to baseline conclusion. Content is appended by phase; it is not split into multiple separate files.

## 1. Original Requirement

### Basic Information

| Field | Content |
|------|------|
| Requirement ID | REQ-20260703-001 |
| Requirement Name | Use Domain Account (DomainAccount) information for device unlock |
| Source | ./domain_unlock_overview.md |
| Proposer | Account Team |
| Target Release | TBD |
| Candidate Profile | none |
| Priority | P0 |
| Status | Baselined |

### Original Description

**Original problem:** The system currently supports domain account authentication (`AuthType::DOMAIN = 1024`), but does not support using domain account authentication to unlock the device's encrypted file system. After DOMAIN authentication succeeds, `AuthCallback::HandleAuthResult()` (`account_iam_callback.cpp:289`) directly early-returns, without performing any storage unlock (`ActivateUserKey`/`UnlockUserScreen`). More importantly, the DOMAIN authentication path entirely bypasses `AuthCallback` — it goes through the `DomainAccountClient::AuthUser()` → `InnerDomainAccountManager::PluginAuth()` → `InnerDomainAuthCallback::OnResult()` independent path, and that callback contains no storage unlock logic. In the PC lock-screen scenario, users cannot use domain account credentials to unlock the system.

Two core capabilities are required:
1. **Enable/disable the domain account unlock capability** — Add a `SetDomainAuthUnlockEnabled` API for the domain account service to control whether domain account unlock is enabled, adapt the PIN add/delete flow, and query the unlock status via the plugin.
2. **Use the domain account to unlock the system** — Reuse the existing `Auth`/`AuthUser` interfaces, triggered with `authType=DOMAIN, authIntent=UNLOCK`, calling the new plugin function `AuthWithUnlockIntent` that returns a token + secret for storage unlock (EL2 + EL3/EL4).

**Pain points:**

| User type | Current pain point | Impact |
|----------|----------|------|
| End user (PC scenario) | Cannot use the domain account password to unlock the lock screen | PC lock screen can only be unlocked with a PIN; domain account users must maintain an additional PIN |
| Domain account service | No API to enable/disable domain account unlock per user | Cannot control whether domain account unlock is enabled for a specific user |
| System | PIN add/delete does not adapt to domain account unlock status | Storage key conflict when both PIN and domain account unlock are enabled |
| System | Cannot query the domain account unlock configuration status | Cannot determine whether domain account unlock is enabled before unlocking |

**Expected result:** Support `SetDomainAuthUnlockEnabled` to enable/disable domain account unlock per user; support querying the unlock configuration via the plugin `GetUnlockDeviceConfigResult`; support domain account authentication with an unlock intent via the `AuthWithUnlockIntent` plugin function, returning token + secret for full storage unlock (EL2-EL4); the PIN add/delete flow skips storage key management when `enableUnlockDevice==true && unlockDeviceMode==ONLINE_OFFLINE_AUTH_UNLOCK_DEVICE`.

### Background Evidence

| Evidence type | Link/Path | Description |
|----------|-----------|------|
| Design document | `./domain_unlock_overview.md` | Feature overview, including interface definitions and flow descriptions |
| Source analysis | `services/accountmgr/src/account_iam/account_iam_callback.cpp:289-291` | `HandleAuthResult()` early-returns for the DOMAIN auth type, not performing unlock |
| Source analysis | `services/accountmgr/src/domain_account/inner_domain_account_manager.cpp:199-243` | `InnerDomainAuthCallback::OnResult()` has no storage unlock logic; the token is zeroed on line 232 |
| Source analysis | `frameworks/account_iam/src/account_iam_client.cpp:396-404` | DOMAIN authentication early-returns in `AuthUser()`, completely bypassing `AuthCallback` and discarding `authIntent` |
| Source analysis | `interfaces/innerkits/domain_account/native/include/domain_plugin.h:58-64` | `PluginAuthResultInfo` has no `secret` field, cannot support storage unlock |
| Source analysis | `services/accountmgr/src/domain_account/domain_plugin_adapter.cpp:110-157` | `LoadPlugin` iterates all `PluginMethodEnum` values; a missing symbol causes the entire load to fail |
| Source analysis | `services/accountmgr/src/domain_account/inner_domain_account_manager.cpp:1827-1833` | `IsPluginAvailable()` checks `plugin_` + `libHandle_` |
| Source analysis | `services/accountmgr/src/account_iam/inner_account_iam_manager.cpp:433-448` | `CheckDomainAuthAvailable()` checks domain account binding + plugin availability |
| Reference feature | `.spec/changes/archive/2026-06-09-custom-auth-unlock/` | Similar feature: custom auth type unlock extension |

### Initial Scope

**May include:**
- `AccountIAMClient::SetDomainAuthUnlockEnabled` InnerKit API + IDL method
- `PluginAuthResultInfo` extension: new `secret` field
- `DomainAuthResult` extension: new `secret` field
- `AuthWithUnlockIntent` plugin function (C-ABI) + `PluginMethodEnum::AUTH_WITH_UNLOCK_INTENT`
- `PluginUnlockDeviceConfigResult` struct + `UnlockDeviceMode` enum + `GetUnlockDeviceConfigResult` plugin function (C-ABI)
- `PluginMethodEnum::GET_UNLOCK_DEVICE_CONFIG` enum value
- `DomainPluginAdapter`: `LoadPlugin` adaptation, `GetAndCleanPluginAuthResultInfo` extension, new config result conversion
- `InnerDomainAccountManager::GetUnlockDeviceConfig` internal method (not externally exposed, service-internal call only)
- `DomainAccountUnlockOptions` new struct (carries `challenge` + `authIntent`)
- `DomainAccountClient::AuthUser` modified hook-based overload signature (new `DomainAccountUnlockOptions` parameter, no new method name/overload)
- `IDomainAccount.idl` new `AuthUserWithUnlockOptions` method (userId + password + DomainAccountUnlockOptions + callback)
- `AccountIAMClient::AuthUser` routes DOMAIN+UNLOCK to the modified entry
- `InnerDomainAuthCallback::OnResult` unlock logic (`ActivateUserKey` + `UnlockUserScreen`), executed before the token is zeroed
- `InnerDomainAuthCallback` new `authIntent_` member
- PIN add flow adaptation (`AddCredCallback::OnResult`)
- PIN delete flow adaptation (`DelCredCallback`/`VerifyTokenCallbackWrapper`)
- `DomainAuthCallbackAdapter::OnResult` does not set `ATTR_ROOT_SECRET`; secret is used only in the service layer for storage unlock, not passed back to IDMCallback
- Mock plugin: `AuthWithUnlockIntent` + `GetUnlockDeviceConfigResult`
- Feature isolation: `libHandle_ != nullptr` runtime check

**Explicitly excluded:**
- Public/NAPI API changes (InnerKit only)
- Domain account plugin implementation logic (provided by the external plugin)
- Modifications to existing `Auth`/`AuthUser` non-DOMAIN paths
- `AuthCallback` class modifications (shared by PIN/Face/Fingerprint, risk too high)
- os_account local state persistence (state fully managed by the plugin)
- New GN feature flag (runtime `libHandle_` check, not compile-time)

### Initial Assumptions

| Assumption | Type | Verification method | Status |
|------|------|----------|------|
| The domain account plugin (.so) will be upgraded in sync, exporting `AuthWithUnlockIntent` and `GetUnlockDeviceConfigResult` symbols | Technical | Plugin team confirmation | Verified |
| The `PluginAuthResultInfo` field `accountToken` remains unchanged; only a new `secret` field is added | Technical | User confirmation | Verified |
| The token/secret of `SetDomainAuthUnlockEnabled` and the accountToken/secret returned by `AuthWithUnlockIntent` are the same set of keys | Technical | User confirmation | Verified |
| Domain account unlock should unlock EL2 + EL3/EL4 (consistent with PIN) | Technical | User confirmation | Verified |
| State is fully managed by the plugin; os_account does not persist locally | Technical | User confirmation | Verified |
| Feature isolation uses `libHandle_ != nullptr` (SO plugin only), rather than `IsPluginAvailable()` | Technical | User confirmation | Verified |
| `SetDomainAuthUnlockEnabled` only handles storage key management; the plugin state is set by the caller (domain account service uid 7058) itself | Technical | User confirmation | Verified |
| DOMAIN auth unlock adopts the A-1 + AuthUser signature modification approach (B-1-ext) | Technical | Deep code analysis | Verified |
| The `InnerAccountIAMManager` unlock APIs (`ActivateUserKey`/`UnlockUserScreen`) are already public and accessible from `InnerDomainAccountManager` | Technical | Source: `inner_domain_account_manager.cpp:43` already includes `inner_account_iam_manager.h` | Verified |
| `InnerDomainAuthCallback::OnResult` zeroes the token on line 232; the unlock logic must be inserted before this | Technical | Source: `inner_domain_account_manager.cpp:232` | Verified |
| `authIntent` is lost in the current DOMAIN auth path and must be passed via the AuthUser signature modification | Technical | Deep code analysis: `account_iam_client.cpp:396-399` discards authIntent | Verified |

### Initial Classification

| Item | Result | Basis |
|--------|------|------|
| Complexity | Complex | Single-repo multi-module (IAM + DomainAccount + Storage), new InnerKit API, new plugin C-ABI interface, security-related (token/secret/uid), requires Epic decomposition |
| Number of repos involved | 1 (os_account) | All changes are in this repo; the plugin .so is upgraded externally |
| Whether Public/System API is involved | No | InnerKit (InnerAPI) only, no Public API |
| Whether security/performance-critical path is involved | Yes | token/secret management, uid access control, storage key management, file system unlock |
| Whether it is cross-SIG | No | All changes are within the account subsystem |

### Entry Conditions for Clarification

- [x] Original problem and expected result recorded
- [x] Requirement source and owner identified
- [x] Initial scope and exclusions recorded
- [x] Key assumptions and open questions listed
- [x] Complexity assessed

---

## 2. Clarification Record

### Open Questions

| No. | Question | Why clarification is needed | Status |
|------|------|----------------|------|
| Q-1 | When adding `AUTH_WITH_UNLOCK_INTENT` and `GET_UNLOCK_DEVICE_CONFIG` to `PluginMethodEnum`, how is plugin load compatibility handled? | `LoadPlugin` iterates all enum values; a missing symbol causes the entire load to fail, breaking existing plugins | Clarified — plugins are upgraded in sync; all .so files must export the new symbols |
| Q-2 | Does `PluginAuthResultInfo.accountToken` need to be renamed to `userToken` per the document? | Renaming touches all references (adapter, mock, inner manager); keeping it unchanged is safer | Clarified — keep `accountToken` unchanged; only add the `secret` field |
| Q-3 | Is the status query interface included in this requirement? | The design document marked it as "to be supplemented" | Clarified — included; defined as the `GetUnlockDeviceConfigResult` plugin function returning `PluginUnlockDeviceConfigResult` |
| Q-4 | Is the state managed locally by os_account or by the plugin? | The design document mentions "update local state" but also has a plugin query interface | Clarified — state is fully managed by the plugin; os_account does not persist locally |
| Q-5 | Are the token/secret of `SetDomainAuthUnlockEnabled` and the accountToken/secret returned by `AuthWithUnlockIntent` the same set of keys? | Determines whether the key set at enable time is the same key used for unlock at auth time | Clarified — the same set of keys |
| Q-6 | Which encryption levels should domain account unlock cover? | PIN unlocks EL2+EL3/EL4; DOMAIN may have different permissions | Clarified — EL2 (`ActivateUserKey`) + EL3/EL4 (`UnlockUserScreen`), consistent with PIN |
| Q-7 | Which InnerKit client should the status query interface belong to? | AccountIAMClient or DomainAccountClient | Clarified (updated by Q-12) — originally DomainAccountClient, later confirmed not to expose an InnerKit API; service-internal call only |
| Q-8 | How is feature isolation implemented? | The design document says "only enabled when a domain account plugin exists" | Clarified — runtime check `libHandle_ != nullptr` (SO plugin only, excluding IPC plugin); defaults to "disabled" when no plugin is present |
| Q-9 | How is DOMAIN authentication with UNLOCK intent routed to storage unlock? | DOMAIN auth bypasses AuthCallback; the decision is where to add the unlock logic | Clarified — A-1 + AuthUser signature modification: call the unlock API directly within `InnerDomainAuthCallback::OnResult`; pass authIntent by modifying the `DomainAccountClient::AuthUser` signature (new `DomainAccountUnlockOptions`); do not modify the existing `Auth`/`AuthUser` non-DOMAIN chain or the `AuthCallback` class |
| Q-10 | How does `SetDomainAuthUnlockEnabled` set the plugin state? | The plugin state (enableUnlockDevice/unlockDeviceMode) must be set somewhere | Clarified — the caller (domain account service uid 7058) sets the plugin state itself; os_account only handles storage key management |
| Q-11 | What are the PIN adaptation conditions? | The updated design document specifies the two conditions enableUnlockDevice and unlockDeviceMode | Clarified — `enableUnlockDevice==true && unlockDeviceMode==ONLINE_OFFLINE_AUTH_UNLOCK_DEVICE` |
| Q-12 | Does `GetUnlockDeviceConfig` need to be exposed as an InnerKit API? | The original design placed it on DomainAccountClient as an InnerKit API, but the status query is only for service-internal use (PIN flow adaptation, unlock flow check) and does not need external callers to query directly | Clarified — no InnerKit API is exposed externally; `GetUnlockDeviceConfig` is only an internal method of `InnerDomainAccountManager` for service-internal calls; the query logic is provided by the domain account plugin's `GetUnlockDeviceConfigResult` C-ABI function |
| Q-13 | Does `AuthUserWithUnlockIntent` need to be exposed as a new InnerKit API? | The original B-1 option added an independent `DomainAccountClient::AuthUserWithUnlockIntent` method. However, the domain account password acquisition mechanism (`domainInputer_`) is an in-process client object that must go through the `DomainAccountClient` IPC path and cannot pass the password via the IAM IPC path. The question is whether the existing `AuthUser` method can be extended rather than adding a new method name | Clarified — no new independent method name; directly modify the existing hook-based `DomainAccountClient::AuthUser` signature (new `DomainAccountUnlockOptions` parameter); this hook-based overload is only called by `AccountIAMClient::StartDomainAuth` in production code, with no external usage points, so modifying the signature has no compatibility risk |
| Q-14 | Can `DomainAccountAuthOptions` be directly extended to carry challenge and authIntent? | `DomainAccountAuthOptions` is already used by the `AuthWithParameters` IDL method and has serialization logic; extending it directly would break compatibility | Clarified — do not extend `DomainAccountAuthOptions`; create a new `DomainAccountUnlockOptions` struct (containing `challenge_` + `authIntent_`), which does not conflict with existing structs |
| Q-15 | Should the domain account unlock trigger entry be restricted? | `DomainAccountClient::Auth`/`AuthUser` can be called directly by external callers for domain account authentication; if these paths also trigger unlock, there is a security risk (callers without `AccountIAMClient` permission verification directly trigger storage unlock) | Clarified — only domain account authentication triggered via `AccountIAMClient::Auth`/`AuthUser` (via the `AuthUserWithUnlockOptions` IDL path carrying `DomainAccountUnlockOptions.authIntent=UNLOCK`) can trigger unlock; authentication triggered via `DomainAccountClient::Auth`/`AuthUser` (non-overload, via existing IDL methods) only performs authentication, not unlock; the two flows are independent |
| Q-16 | Should secret be transmitted via DomainAuthResult serialization? | secret is high-security-level data (storage unlock key); if serialized via DomainAuthResult and then transmitted over IPC to the client, it would be exposed in the client process memory and IPC buffers | Clarified — secret is not serialized via DomainAuthResult; DomainAuthResult does not contain a secret field; AuthWithUnlockIntent uses an independent auth callback flow (PluginAuthWithUnlockIntentCallback → AuthWithUnlockIntentResultCallback → OnResultWithUnlock); secret is extracted directly on the server side for unlock, not serialized, not cross-process |

### Discussion Record

| Date | Participants | Topic | Conclusion | Follow-up action |
|------|--------|----------|------|----------|
| 2026-07-03 | Account Team | Plugin compatibility strategy | Plugins upgraded in sync; all .so files must export `AuthWithUnlockIntent` and `GetUnlockDeviceConfigResult` | Confirm with plugin team |
| 2026-07-03 | Account Team | PluginAuthResultInfo field naming | Keep `accountToken` unchanged; only add the `secret` field | Update design document field name |
| 2026-07-03 | Account Team | State management model | State fully managed by the plugin; os_account queries via `GetUnlockDeviceConfigResult`, no local persistence | Remove local persistence from design |
| 2026-07-03 | Account Team | Unlock routing approach | A-1 + AuthUser signature modification: `InnerDomainAuthCallback::OnResult` directly calls the `InnerAccountIAMManager` unlock API; passes authIntent by modifying the `DomainAccountClient::AuthUser` signature (new `DomainAccountUnlockOptions`) | Complete deep code analysis |
| 2026-07-03 | Account Team | Feature isolation mechanism | Use `libHandle_ != nullptr` (SO plugin only), more precise than `IsPluginAvailable()` (the latter also checks IPC plugins) | Update all feature isolation checkpoints |
| 2026-07-03 | Account Team | SetDomainAuthUnlockEnabled scope | Only handle storage key management (add/delete keys via StorageManager); the plugin state is set by the caller itself | Record in spec |
| 2026-07-03 | Account Team | GetUnlockDeviceConfig interface scope | No InnerKit API exposed externally; only an internal method of InnerDomainAccountManager for service-internal calls (PIN adaptation, unlock check); the query logic is provided by the plugin `GetUnlockDeviceConfigResult` | Update proposal API list and impact scope |
| 2026-07-03 | Account Team | AuthUser extension method | Do not add an independent `AuthUserWithUnlockIntent` method; directly modify the existing hook-based `DomainAccountClient::AuthUser` signature (new `DomainAccountUnlockOptions` parameter); this overload is only called by `StartDomainAuth` in production code, with no external usage points | Update ADR-2 and API list |
| 2026-07-03 | Account Team | DomainAccountAuthOptions compatibility | `DomainAccountAuthOptions` is already used by the `AuthWithParameters` IDL; extending it directly breaks compatibility; create a new `DomainAccountUnlockOptions` struct (containing `challenge_` + `authIntent_`) | Update API list and impact scope |
| 2026-07-03 | Account Team | Unlock trigger entry restriction | Only domain account authentication triggered by `AccountIAMClient::Auth`/`AuthUser` can unlock (via `AuthUserWithUnlockOptions` IDL, carrying `authIntent=UNLOCK`); `DomainAccountClient::Auth`/`AuthUser` (non-overload) only authenticates, does not unlock; the two flows are independent | Update AC and design |

### Functional Scope Confirmation

| Question | Answer | Confirmed by | Status |
|------|------|--------|------|
| What does the core functionality include? | (1) Enable/disable domain account unlock + PIN flow adaptation + status query; (2) Domain account authentication with unlock intent → storage unlock | Account Team | Confirmed |
| What is explicitly excluded? | Public API changes, AuthCallback class modifications, existing Auth/AuthUser non-DOMAIN path changes, local state persistence, new GN flag | Account Team | Confirmed |
| Is there a phasing strategy? | 3 Features: F1 (plugin interface extension) and F2 (unlock switch) in parallel; F3 (unlock flow) depends on F1+F2 | Account Team | Confirmed |

### Solution Exploration

> Complex level requires at least 2 solutions + trade-off rationale.

#### Decision 1: DOMAIN auth unlock routing solution

| No. | Solution overview | Advantages | Risks/costs | Selection result |
|------|----------|------|-----------|----------|
| A-1 | Directly call the `InnerAccountIAMManager` unlock API in `InnerDomainAuthCallback::OnResult`; pass authIntent by modifying the `DomainAccountClient::AuthUser` signature (B-1-ext, see ADR-2) | Changes concentrated in the domain module, does not affect the IAM callback shared class (PIN/Face/Fingerprint depend on it); the `InnerAccountIAMManager` unlock API is already public and included | Need to duplicate `UnlockAccount`/`UnlockUserScreen` logic; need to insert before the token is zeroed on line 232; need a new IDL method | **Recommended** |
| A-2 | Route the DOMAIN auth result back to the `AuthCallback` unlock flow | Reuse the existing tested unlock sequence | Modify the shared `AuthCallback` class (high regression risk); requires IDL change; double state setting; still requires the secret field | Abandoned |

**Trade-off rationale:** Solution A-1 has a smaller impact scope (1-2 files in the domain module), does not regress the PIN/Face/Fingerprint unlock paths, and the `InnerAccountIAMManager` unlock API is already public and directly callable. The main work is to copy the unlock sequence (mirroring `UnlockAccount` + `UnlockUserScreen`, from `account_iam_callback.cpp:210-284`) into `InnerDomainAuthCallback::OnResult` before the token is zeroed. By modifying the `DomainAccountClient::AuthUser` signature (new `DomainAccountUnlockOptions`) to pass `authIntent`, there is no need to modify the existing `Auth`/`AuthUser` non-DOMAIN chain.

#### Decision 2: authIntent passing solution

| No. | Solution overview | Advantages | Risks/costs | Selection result |
|------|----------|------|-----------|----------|
| B-1-ext | Directly modify the existing hook-based `DomainAccountClient::AuthUser` signature (new `DomainAccountUnlockOptions` parameter); new `DomainAccountUnlockOptions` struct (containing `challenge_` + `authIntent_`); new `IDomainAccount.idl::AuthUserWithUnlockOptions` IDL method | No new method name, no new overload (directly modify the signature); the hook-based `AuthUser` is only called by `StartDomainAuth` in production code, with no external usage points, so the modification has no compatibility risk; the password is passed via the `DomainAccountClient` IPC path (`domainInputer_` is an in-process client object that must go through this path) | 1 new IDL method + 1 new struct; existing tests need to update the signature in sync; the server side needs to detect `authIntent` routing | **Recommended** |
| B-1 | Add an independent `DomainAccountClient::AuthUserWithUnlockIntent` method + `IDomainAccount.idl::AuthUserWithUnlockIntent` IDL method | Clear semantics (unlock intent) | One more method name; poor extensibility (future new intents require additional methods) | Abandoned |
| B-2 | Pass `authIntent` in the existing `Auth`/`AuthUser` chain: modify `StartDomainAuth` signature, `DomainAccountClient::AuthUser`, `IDomainAccount.idl`, `InnerDomainAccountManager::AuthUser` | Unified path, no duplication | Invasive cross-layer modification; touches existing IDL contracts; affects all domain account authentication callers | Abandoned |

**Trade-off rationale:** B-1-ext is the best solution: (1) no new method name, no new overload (directly modify the hook-based `AuthUser` signature), the API surface is most concise; (2) this hook-based overload is only called by `AccountIAMClient::StartDomainAuth` in production code, with no external usage points, so modifying the signature has no compatibility risk; (3) `DomainAccountUnlockOptions` as an independent struct does not conflict with the existing `DomainAccountAuthOptions`, and as a unified extension point can carry `challenge` and `authIntent`; (4) the password must be passed via the `DomainAccountClient` IPC path (`domainInputer_` is an in-process `shared_ptr` that cannot cross processes) and cannot go through the IAM IPC path; (5) the new `AuthUserWithUnlockOptions` IDL method is necessary because the existing `AuthUser` IDL does not carry options, and the `AuthWithParameters` IDL uses `DomainAccountInfo` instead of `userId`.

### Context and Knowledge Source Retrieval Log

| No. | Source | Query/read content | Key findings | Confidence | Used for | Hit/Reason |
|------|------|---------------|----------|--------|------|-----------|
| K-1 | Source: `account_iam_callback.cpp:286-320` | `HandleAuthResult` DOMAIN early-return | DOMAIN auth returns directly on line 289, not performing any unlock; `ATTR_ROOT_SECRET` (secret) is unavailable for DOMAIN | High | Scope/API/Design | Hit |
| K-2 | Source: `inner_domain_account_manager.cpp:199-243` | `InnerDomainAuthCallback::OnResult` full analysis | Has `userId_` and `authResult->token`; token is zeroed on line 232; no `authIntent` member; no `secret` field; `inner_account_iam_manager.h` already included | High | Design/Routing | Hit |
| K-3 | Source: `account_iam_client.cpp:374-424` | DOMAIN auth path in `AuthUser` | DOMAIN returns on line 399, never reaching `proxy->AuthUser`; `authIntent` is discarded; `AuthCallback` is never created for DOMAIN | High | Design/Routing | Hit |
| K-4 | Source: `domain_plugin.h:58-64` | `PluginAuthResultInfo` struct | No secret field; only `accountToken`, remainTimes, freezingTime, localId, nextPhaseFreezingTime | High | API/Design | Hit |
| K-5 | Source: `domain_plugin_adapter.cpp:110-157` | `LoadPlugin` mechanism | Iterates all `PluginMethodEnum` values; a missing symbol causes the entire load to fail; new enum values require all plugins to export new symbols | High | API/Compatibility | Hit |
| K-6 | Source: `inner_domain_account_manager.cpp:1827-1833` | `IsPluginAvailable()` | Checks `plugin_` (IPC) and `libHandle_` (SO); new C-ABI functions are only available via the SO path | High | Feature isolation | Hit |
| K-7 | Source: `inner_account_iam_manager.h:62-80` | Public unlock API interface | `ActivateUserKey`, `UnlockUserScreen`, `GetLockScreenStatus`, `CheckNeedReactivateUserKey` are all public; accessible from the domain module | High | Design/Routing | Hit |
| K-8 | Source: `account_iam_callback.cpp:205-208` | `CheckAllowUnlockUserStorage` | Only allows PIN and CUSTOM_AUTH; DOMAIN is excluded from EL2 unlock | High | Design | Hit |
| K-9 | Source: `account_iam_callback_service.cpp:166-183` | `DomainAuthCallbackAdapter::OnResult` | Sets `ATTR_SIGNATURE` from `DomainAuthResult.token`; does not set `ATTR_ROOT_SECRET`; `DomainAuthResult` has no secret field | High | API/Design | Hit |
| K-10 | Source: `domain_account_common.h:160-172` | `DomainAuthResult` struct | Has `token`, `authStatusInfo`, `accountId`; no `secret` field | High | API/Design | Hit |
| K-11 | Source: `inner_domain_account_manager.cpp:638-695` | `AuthResultInfoCallback` and `PluginAuth` | The plugin callback converts `PluginAuthResultInfo` to `DomainAuthResult` via `GetAndCleanPluginAuthResultInfo`; only extracts `accountToken` → `result.token` | High | Design/Adapter | Hit |
| K-12 | Source: `os_account.gni:156` | `os_account_support_authorization` flag | GN flag, default false; controls `SUPPORT_AUTHORIZATION` define; this feature does not use it (uses runtime `libHandle_` check instead) | High | Feature isolation | Hit |
| K-13 | Source: `account_error_no.h:288-299` | Domain account error codes | Already has `ERR_DOMAIN_ACCOUNT_SERVICE_NOT_DOMAIN_ACCOUNT`, `ERR_DOMAIN_ACCOUNT_SERVICE_INVALID_CALLING_UID`, `ERR_DOMAIN_ACCOUNT_NOT_SUPPORT`; may need new error codes | High | Error codes | Hit |
| K-14 | Source: `./domain_unlock_overview.md` | Updated design document | Status query is defined: `PluginUnlockDeviceConfigResult`, `UnlockDeviceMode` enum, `GetUnlockDeviceConfigResult` plugin function; PIN adaptation conditions: `enableUnlockDevice && ONLINE_OFFLINE_AUTH_UNLOCK_DEVICE` | High | Scope/API | Hit |
| K-15 | Source: `inner_domain_account_manager.cpp:70-75` | Plugin library path and name | `LIB_PATH` = `/system/lib64/platformsdk/` (ARM64); `LIB_NAME` = `libdomain_account_plugin.z.so` | High | Feature isolation | Hit |

**Context conclusions:**
- High-confidence conclusions: DOMAIN authentication completely bypasses AuthCallback; the unlock API is accessible from the domain module; the plugin needs a `secret` field and new functions; `libHandle_` is the correct feature isolation check method; the AuthUser signature modification approach is feasible.
- Pending-confirmation conclusions: None — all key questions have been resolved through code analysis and user confirmation.
- Unused sources and reasons: `os_account_support_authorization` GN flag — not used because, per user decision, feature isolation is via the runtime `libHandle_` check.

### Subsystem Impact

| Question | Answer | Confirmed by | Status |
|------|------|--------|------|
| Which subsystems are involved? | account (os_account repo) — modules: AccountIAM, DomainAccount, Storage integration | Account Team | Confirmed |
| Is a new subsystem or component needed? | No | Account Team | Confirmed |

### API Change Assessment

| Question | Answer | Confirmed by | Status |
|------|------|--------|------|
| Does it require adding/modifying a Public API? | No — InnerKit (InnerAPI) only | Account Team | Confirmed |
| Does it require adding a System API? | No | Account Team | Confirmed |
| Does it deprecate an existing API? | No | Account Team | Confirmed |
| Does it require a new permission declaration? | No — uses the existing `ohos.permission.MANAGE_USER_IDM` and `ohos.permission.ACCESS_USER_AUTH_INTERNAL` | Account Team | Confirmed |

### Compatibility and Non-functional Requirements

| Category | Core question | Conclusion | Confirmed by | Status |
|------|----------|------|--------|------|
| Compatibility | Forward/backward compatibility requirements? Breaking changes? | The plugin .so needs to be upgraded in sync; new fields are added incrementally, with no impact on existing authentication flows; no breaking API changes | Account Team | Confirmed |
| Performance | Response time/memory/concurrency requirements? | No new long-latency paths; reuses the existing storage unlock flow; plugin calls are asynchronous (consistent with existing domain account authentication) | Account Team | Confirmed |
| Security | Permission/privacy/encryption/audit requirements? | uid 7058 whitelist + `MANAGE_USER_IDM` permission for `SetDomainAuthUnlockEnabled`; `ACCESS_USER_AUTH_INTERNAL` for authentication; token/secret zeroed after use; storage key management reuses the existing secure flow | Account Team | Confirmed |
| Reliability | Crash rate/fault tolerance/recovery requirements? | Reuses the existing 20×100ms retry mechanism for storage operations; token is zeroed after use to prevent leakage on failure | Account Team | Confirmed |

### Dependencies and Risks

| Dependency item | Type | Description | Status |
|--------|------|------|------|
| Domain account plugin (.so) | External | The plugin needs to be upgraded to export `AuthWithUnlockIntent` and `GetUnlockDeviceConfigResult` symbols | Confirmed |
| StorageManager | Runtime | `ActivateUserKey` (EL2) + `UnlockUserScreen` (EL3/EL4) + `UpdateUserAuth` (key management) — all existing APIs | Confirmed |
| UserAccessCtrlClient | Runtime | `VerifyAuthToken` used for token verification in `SetDomainAuthUnlockEnabled` — existing API from `user_auth_framework` | Confirmed |

| Risk | Type | Impact | Mitigation measure | Status |
|------|------|------|----------|------|
| Some devices' plugins not upgraded | External | Medium | `libHandle_` check gates the feature; defaults to "disabled" when no plugin is present | Confirmed |
| Token zeroed before unlock (line 232) | Technical | High | Insert unlock logic before line 232; zero token/secret yourself after unlock | Confirmed |
| Plugin async callback timing | Technical | Medium | Unlock logic executes in the `OnResult` callback; consistent with the existing domain account authentication async pattern | Confirmed |
| PIN and domain account unlock key conflict | Technical | Medium | Query `GetUnlockDeviceConfigResult` during PIN add/delete; when domain account unlock is enabled and in `ONLINE_OFFLINE_AUTH_UNLOCK_DEVICE` mode, skip storage key management | Confirmed |
| `AuthCallback` class regression risk (if A-2 chosen) | Technical | High | Avoided by choosing A-1; the AuthCallback class is not modified | Confirmed |

### AC Completeness

- [x] Every user story has acceptance criteria
- [x] All ACs use the WHEN/THEN format
- [x] Covers normal flows, exception flows, and boundary conditions
- [x] ACs are testable and measurable

### Clarification Conclusion

- [x] Functional scope is fully clarified
- [x] Subsystem impact identified
- [x] API changes assessed
- [x] Compatibility and non-functional requirements confirmed
- [x] Dependencies and risks identified with mitigation plans
- [x] ACs are complete and testable
- [x] Complex level has completed solution exploration (2 routing solutions + 3 authIntent passing solutions + unlock entry restriction constraint + trade-off rationale)

**Conclusion:** Pass (re-confirmed after Q-12/Q-13/Q-14/Q-15 updates: GetUnlockDeviceConfig is not externally exposed; modifying the AuthUser signature replaces an independent method; DomainAccountUnlockOptions replaces extending DomainAccountAuthOptions; unlock is only triggered by the AccountIAMClient entry, and the two flows are independent)

---

## 3. Requirement Baseline

> Frozen after clarification is complete. manifest.md is the source of truth; this section is the approval conclusion.

### Baseline Information

| Field | Content |
|------|------|
| Baseline version | v1.0 |
| Baseline date | 2026-07-03 |
| Owner | Account Team |
| Confirmed by | Account Team |
| Complexity | Complex |
| Profile | none |
| Target release | TBD (refers to manifest.target_release) |
| Version status | proposed |

### Problem Statement

The system currently supports domain account authentication but cannot use domain account authentication to unlock the device's encrypted file system. DOMAIN authentication returns directly after success, without performing storage unlock, and the DOMAIN authentication path entirely bypasses `AuthCallback`. PC lock-screen users cannot use domain account credentials to unlock the system. In addition, there is no API to enable/disable domain account unlock per user, and the PIN add/delete flow does not adapt to the domain account unlock status, creating a storage key conflict risk.

This feature adds two core capabilities: (1) `SetDomainAuthUnlockEnabled` to enable/disable domain account unlock per user, adapt the PIN flow, and query the unlock status via the plugin; (2) domain account authentication with an unlock intent via the `AuthWithUnlockIntent` plugin function, returning token + secret for full storage unlock (EL2-EL4).

### Goals and Success Metrics

| Goal | Success metric | Verification method |
|------|----------|----------|
| Enable/disable domain account unlock per user | `SetDomainAuthUnlockEnabled` returns success and the storage key has been added/deleted | Unit test + integration test |
| Query domain account unlock configuration | `InnerDomainAccountManager::GetUnlockDeviceConfig` returns the correct `enableUnlockDevice` and `unlockDeviceMode` | Unit test |
| Domain account auth unlocks EL2 | `ActivateUserKey` is called with the token+secret returned by `AuthWithUnlockIntent` | Unit test |
| Domain account auth unlocks EL3/EL4 | When the screen is locked, `UnlockUserScreen` is called | Unit test |
| Skip storage key when adding PIN and domain account unlock is enabled | `UpdateStorageUserAuth` is not called when `enableUnlockDevice && ONLINE_OFFLINE_AUTH_UNLOCK_DEVICE` | Unit test |
| Skip storage key deletion when deleting PIN and domain account unlock is enabled | Storage key is not deleted when domain account unlock is enabled | Unit test |
| Feature isolation takes effect | When `libHandle_` is nullptr, the function returns "disabled"/not supported | Unit test |
| token/secret zeroed after use | No token/secret residue in memory after unlock | Code review + security scan |

### Epic Decomposition

| Feature ID | Name | Goal | Dependencies | Estimated complexity |
|------------|------|------|------|-----------|
| F1 | Plugin interface extension | `PluginAuthResultInfo.secret`, `DomainAuthResult.secret`, `AuthWithUnlockIntent` + `GetUnlockDeviceConfigResult` plugin functions, `PluginMethodEnum` enum values, `DomainPluginAdapter` adaptation, `DomainAuthCallbackAdapter` extension, mock plugin | None | Medium |
| F2 | Domain account unlock capability switch | `SetDomainAuthUnlockEnabled` InnerKit API + IDL, permission/parameter validation, storage key management, `GetUnlockDeviceConfig` internal query (not externally exposed), PIN flow adaptation, feature isolation | None (parallel with F1) | High |
| F3 | Domain account unlock flow | `DomainAccountClient::AuthUser` signature modification + `AuthUserWithUnlockOptions` IDL (Client→IDL→Service→Plugin), DOMAIN+UNLOCK routing, binding + unlock check, async plugin call, `InnerDomainAuthCallback` unlock logic (EL2+EL3/EL4) | F1 + F2 | High |

**Dependency graph:**
```
F1 (Plugin interface extension) ──┐
                                  ├──▶ F3 (Domain account unlock flow)
F2 (Unlock capability switch) ────┘
```

F1 and F2 can be developed in parallel. F3 depends on F1 (plugin interface) and F2 (unlock status query + feature isolation).

### User Stories and AC

| Story ID | User story | Priority |
|----------|----------|--------|
| US-1 | As a domain account service, I want to enable/disable the domain account unlock capability per user, so that I can control whether domain account credentials can unlock the device | P0 |
| US-2 | As a system service, I want to query the domain account unlock configuration internally, so that during PIN flow adaptation and unlock flow checks I can determine the current user's unlock policy | P1 |
| US-3 | As an end user, I want to unlock the system with my domain account password on the PC lock screen, so that I do not need to maintain an additional PIN | P0 |
| US-4 | As the system, I want PIN add/delete to automatically adapt to the domain account unlock status, to avoid storage key conflicts | P0 |
| US-5 | As the system, I want domain account unlock to be gated by plugin availability, so that devices without a plugin default to "disabled" | P0 |

| AC No. | Acceptance criteria | Type | Related Story |
|--------|----------|------|-----------|
| AC-1.1 | WHEN the domain account service (uid 7058) with the `MANAGE_USER_IDM` permission calls `SetDomainAuthUnlockEnabled(localId, token, secret, true)` THEN the system should validate parameters and notify storage to add the key | Normal | US-1 |
| AC-1.2 | WHEN the caller uid is not 7058 THEN the system should reject the call and return a permission error | Exception | US-1 |
| AC-1.3 | WHEN the caller lacks the `MANAGE_USER_IDM` permission THEN the system should reject the call and return a permission error | Exception | US-1 |
| AC-1.4 | WHEN localId does not exist or is not bound to a domain account THEN the system should return `ERR_DOMAIN_ACCOUNT_SERVICE_NOT_DOMAIN_ACCOUNT` | Exception | US-1 |
| AC-1.5 | WHEN the token is invalid (VerifyAuthToken fails) THEN the system should return an auth token error | Exception | US-1 |
| AC-1.6 | WHEN enabling and the storage key already exists THEN the system should save the state and return success directly, without re-adding the key | Boundary | US-1 |
| AC-1.7 | WHEN disabling and the storage key exists THEN the system should notify storage to delete the key and return the result | Normal | US-1 |
| AC-1.8 | WHEN disabling and the storage key does not exist THEN the system should only update the state and return success | Boundary | US-1 |
| AC-1.9 | WHEN `libHandle_` is nullptr (no SO plugin) THEN `SetDomainAuthUnlockEnabled` should return a "not supported" error | Boundary | US-1, US-5 |
| AC-2.1 | WHEN the service internally calls `InnerDomainAccountManager::GetUnlockDeviceConfig(userId)` and the plugin is available THEN the system should query the plugin `GetUnlockDeviceConfigResult` and return `enableUnlockDevice` and `unlockDeviceMode` | Normal | US-2 |
| AC-2.2 | WHEN `libHandle_` is nullptr THEN `GetUnlockDeviceConfig` should return `enableUnlockDevice=false` as the default | Boundary | US-2, US-5 |
| AC-3.1 | WHEN a system app with the `ACCESS_USER_AUTH_INTERNAL` permission calls `AuthUser` with `authType=DOMAIN, authIntent=UNLOCK` THEN the system should route, via the modified `DomainAccountClient::AuthUser` (carrying `DomainAccountUnlockOptions`), to the `AuthUserWithUnlockOptions` IDL method, ultimately calling the `AuthWithUnlockIntent` plugin function | Normal | US-3 |
| AC-3.2 | WHEN the user is not bound to a domain account THEN the system should return an error and not attempt unlock | Exception | US-3 |
| AC-3.3 | WHEN domain account unlock is not enabled (`enableUnlockDevice=false`) THEN the system should return an error and not attempt unlock | Exception | US-3 |
| AC-3.4 | WHEN the `AuthWithUnlockIntent` plugin call succeeds and returns token+secret THEN the system should call `ActivateUserKey(userId, token, secret)` for EL2 decryption | Normal | US-3 |
| AC-3.5 | WHEN the `AuthWithUnlockIntent` plugin call succeeds and the screen is locked THEN the system should call `UnlockUserScreen(userId, token, secret)` for EL3/EL4 decryption | Normal | US-3 |
| AC-3.6 | WHEN the `AuthWithUnlockIntent` plugin call succeeds THEN the system should set `OsAccountIsVerified=true` | Normal | US-3 |
| AC-3.7 | WHEN the `AuthWithUnlockIntent` plugin call fails THEN the system should not perform any storage unlock and should return the error to the caller | Exception | US-3 |
| AC-3.8 | WHEN the target account is being deactivated or locked THEN the system should not perform storage unlock | Boundary | US-3 |
| AC-3.9 | WHEN `libHandle_` is nullptr THEN domain account unlock is unavailable, returning "not supported" | Boundary | US-3, US-5 |
| AC-3.10 | WHEN unlock is complete THEN the token and secret should be zeroed in memory (memset) | Security | US-3 |
| AC-4.1 | WHEN adding a PIN and `enableUnlockDevice==true && unlockDeviceMode==ONLINE_OFFLINE_AUTH_UNLOCK_DEVICE` THEN the system should not call `UpdateStorageUserAuth` (skip storage key add) | Normal | US-4 |
| AC-4.2 | WHEN adding a PIN and domain account unlock is not enabled or the mode is `OFFLINE_AUTH_UNLOCK_DEVICE` THEN the system should call `UpdateStorageUserAuth` normally | Normal | US-4 |
| AC-4.3 | WHEN adding a PIN and `libHandle_` is nullptr THEN the system should call `UpdateStorageUserAuth` normally (no domain account unlock) | Boundary | US-4, US-5 |
| AC-4.4 | WHEN deleting a PIN and `enableUnlockDevice==true && unlockDeviceMode==ONLINE_OFFLINE_AUTH_UNLOCK_DEVICE` THEN the system should not delete the storage key | Normal | US-4 |
| AC-4.5 | WHEN deleting a PIN and domain account unlock is not enabled or the mode is `OFFLINE_AUTH_UNLOCK_DEVICE` THEN the system should delete the storage key normally | Normal | US-4 |
| AC-4.6 | WHEN `AuthWithUnlockIntent` is called carrying a challenge value THEN the plugin should receive the challenge for authentication | Normal | US-3 |
| AC-3.11 | WHEN domain account authentication is triggered via `DomainAccountClient::Auth` or `DomainAccountClient::AuthUser` (non-overload) THEN the system should only perform authentication, not perform storage unlock (`ActivateUserKey`/`UnlockUserScreen` are not called) | Boundary | US-3 |
| AC-3.12 | WHEN domain account authentication is triggered via `AccountIAMClient::Auth` or `AccountIAMClient::AuthUser` (`authType=DOMAIN, authIntent=UNLOCK`) THEN the system should perform storage unlock (via the `AuthUserWithUnlockOptions` IDL path) | Normal | US-3 |

### Scope Boundary

**Included:**
- `AccountIAMClient::SetDomainAuthUnlockEnabled` InnerKit API + IDL
- `InnerDomainAccountManager::GetUnlockDeviceConfig` internal query method (InnerKit API not externally exposed)
- `DomainAccountUnlockOptions` new struct (containing `challenge` + `authIntent`)
- `DomainAccountClient::AuthUser` modified hook-based overload signature (new `DomainAccountUnlockOptions` parameter)
- `IDomainAccount.idl` new `AuthUserWithUnlockOptions` method
- `PluginAuthResultInfo.secret` field + `DomainAuthResult.secret` field
- `AuthWithUnlockIntent` + `GetUnlockDeviceConfigResult` plugin C-ABI functions
- `PluginUnlockDeviceConfigResult` struct + `UnlockDeviceMode` enum
- `PluginMethodEnum::AUTH_WITH_UNLOCK_INTENT` + `PluginMethodEnum::GET_UNLOCK_DEVICE_CONFIG`
- `DomainPluginAdapter`: LoadPlugin, GetAndCleanPluginAuthResultInfo, new config result conversion
- `DomainAuthCallbackAdapter::OnResult` does not set ATTR_ROOT_SECRET; secret is used only in the service layer for storage unlock, not passed back to IDMCallback
- `InnerDomainAuthCallback` authIntent_ + unlock logic (EL2+EL3/EL4)
- PIN add/delete flow adaptation
- Feature isolation: `libHandle_` runtime check
- Mock plugin update

**Excluded:**
- Public/NAPI API changes
- `AuthCallback` class modifications
- Existing `Auth`/`AuthUser` non-DOMAIN path changes
- os_account local state persistence
- New GN feature flag
- Domain account plugin implementation logic
- `os_account_control_file_manager.cpp` changes (no local persistence)

### Impact Scope

| Subsystem | Repo | Module/Path | Current responsibility | Impact type | Owner |
|--------|------|-----------|----------|----------|-------|
| account | os_account | `interfaces/innerkits/domain_account/native/include/domain_plugin.h` | C-ABI plugin struct/function definitions | Modified (new secret field, AuthWithUnlockIntent, GetUnlockDeviceConfigResult, PluginUnlockDeviceConfigResult, UnlockDeviceMode, PluginMethodEnum) | Account Team |
| account | os_account | `interfaces/innerkits/domain_account/native/include/domain_account_common.h` | DomainAuthResult + DomainAccountAuthOptions structs | Modified (DomainAuthResult new secret field; new DomainAccountUnlockOptions struct) | Account Team |
| account | os_account | `interfaces/innerkits/domain_account/native/include/domain_account_client.h` | DomainAccountClient InnerKit | Modified (modify hook-based AuthUser signature, new DomainAccountUnlockOptions parameter) | Account Team |
| account | os_account | `frameworks/domain_account/src/domain_account_client.cpp` | DomainAccountClient implementation | Modified (implement the modified AuthUser, internally call AuthUserWithUnlockOptions IDL) | Account Team |
| account | os_account | `frameworks/domain_account/IDomainAccount.idl` | Domain account IPC interface | Modified (new AuthUserWithUnlockOptions) | Account Team |
| account | os_account | `interfaces/innerkits/account_iam/native/include/account_iam_client.h` | AccountIAMClient InnerKit | Modified (new SetDomainAuthUnlockEnabled) | Account Team |
| account | os_account | `frameworks/account_iam/src/account_iam_client.cpp` | AccountIAMClient implementation | Modified (SetDomainAuthUnlockEnabled; AuthUser calls StartDomainAuth for all DOMAIN auth carrying DomainAccountUnlockOptions; DOMAIN+UNLOCK routing is server-side) | Account Team |
| account | os_account | `frameworks/account_iam/IAccountIAM.idl` | IAM IPC interface | Modified (new SetDomainAuthUnlockEnabled) | Account Team |
| account | os_account | `frameworks/account_iam/src/account_iam_callback_service.cpp` | DomainAuthCallbackAdapter | Modified (does not set ATTR_ROOT_SECRET; new OnAcquireInfo forwarding to IIDMCallback) | Account Team |
| account | os_account | `interfaces/innerkits/domain_account/native/include/domain_account_callback.h` | DomainAccountCallback base class | Modified (new OnAcquireInfo default empty implementation) | Account Team |
| account | os_account | `frameworks/domain_account/IDomainAccountCallback.idl` | Domain account callback IPC interface | Modified (new OnAcquireInfo method) | Account Team |
| account | os_account | `frameworks/domain_account/include/domain_account_callback_service.h` | DomainAccountCallbackService | Modified (new OnAcquireInfo override forwarding) | Account Team |
| account | os_account | `frameworks/domain_account/src/domain_account_callback_service.cpp` | DomainAccountCallbackService implementation | Modified (new OnAcquireInfo implementation, forwarding to innerCallback_) | Account Team |
| account | os_account | `services/accountmgr/src/account_iam/account_iam_service.cpp` | AccountIAMService stub | Modified (SetDomainAuthUnlockEnabled stub) | Account Team |
| account | os_account | `services/accountmgr/src/account_iam/inner_account_iam_manager.cpp` | InnerAccountIAMManager | Modified (SetDomainAuthUnlockEnabled logic, PIN adaptation) | Account Team |
| account | os_account | `services/accountmgr/src/account_iam/account_iam_callback.cpp` | AddCredCallback/DelCredCallback | Modified (PIN add/delete flow adaptation) | Account Team |
| account | os_account | `services/accountmgr/src/domain_account/inner_domain_account_manager.cpp` | InnerDomainAccountManager | Modified (AuthWithUnlockIntent, GetUnlockDeviceConfig, InnerDomainAuthCallback unlock logic) | Account Team |
| account | os_account | `services/accountmgr/include/domain_account/inner_domain_account_manager.h` | InnerDomainAccountManager header | Modified (new methods, InnerDomainAuthCallback authIntent_) | Account Team |
| account | os_account | `services/accountmgr/src/domain_account/domain_account_manager_service.cpp` | DomainAccountManagerService | Modified (new method stub) | Account Team |
| account | os_account | `services/accountmgr/src/domain_account/domain_plugin_adapter.cpp` | DomainPluginAdapter | Modified (METHOD_NAME_MAP, LoadPlugin, GetAndCleanPluginAuthResultInfo, new config conversion) | Account Team |
| account | os_account | `frameworks/domain_account/test/moduletest/src/mock_domain_so_plugin.cpp` | Mock SO plugin | Modified (AuthWithUnlockIntent, GetUnlockDeviceConfigResult mock) | Account Team |
| account | os_account | `interfaces/innerkits/common/include/account_error_no.h` | Error codes | Modified (new error codes if needed) | Account Team |

### API Change Item List

> Required when API changes are involved; serves as a shared anchor produced in parallel with design.md and spec.md.

| API name | Change type | Open scope | Summary description |
|----------|----------|----------|----------|
| `AccountIAMClient::SetDomainAuthUnlockEnabled` | New | InnerAPI | Enable/disable domain account authentication unlock per user |
| `DomainAccountClient::AuthUser` (signature modification) | Modified signature | InnerAPI | Modify the hook-based AuthUser signature, adding the `DomainAccountUnlockOptions` parameter; this overload is only called by `StartDomainAuth` in production code, with no compatibility risk |
| `DomainAccountUnlockOptions` | New struct | InnerAPI | Carries `challenge` and `authIntent`, as extended options for unlock authentication |
| `InnerDomainAccountManager::GetUnlockDeviceConfig` | New | Internal method (not externally exposed) | Service-internal query of the domain account unlock configuration, calling the plugin `GetUnlockDeviceConfigResult` |
| `IAccountIAM.idl::SetDomainAuthUnlockEnabled` | New | IDL | The IPC method for SetDomainAuthUnlockEnabled |
| `IDomainAccount.idl::AuthUserWithUnlockOptions` | New | IDL | The AuthUser IPC method carrying DomainAccountUnlockOptions |
| `PluginAuthResultInfo.secret` | New field | C-ABI | The secret field used for storage unlock |
| `DomainAuthResult.secret` | New field | InnerAPI | The secret field mirrored from the plugin |
| `AuthWithUnlockIntent` plugin function | New | C-ABI | Domain account plugin authentication with unlock intent, returning token+secret |
| `GetUnlockDeviceConfigResult` plugin function | New | C-ABI | Query the unlock device configuration from the plugin |
| `PluginUnlockDeviceConfigResult` struct | New | C-ABI | Unlock configuration result (enableUnlockDevice, unlockDeviceMode) |
| `UnlockDeviceMode` enum | New | C-ABI | OFFLINE_AUTH_UNLOCK_DEVICE=1, ONLINE_OFFLINE_AUTH_UNLOCK_DEVICE=2 |
| `PluginMethodEnum::AUTH_WITH_UNLOCK_INTENT` | New enum | C-ABI | The plugin method enum for AuthWithUnlockIntent |
| `PluginMethodEnum::GET_UNLOCK_DEVICE_CONFIG` | New enum | C-ABI | The plugin method enum for GetUnlockDeviceConfigResult |
| `DomainAccountCallback::OnAcquireInfo` | New method | InnerAPI | Domain account authentication callback adds `OnAcquireInfo(module, acquireInfo, const DomainAccountUnlockExtraInfo &)`, with a default empty implementation, backward compatible; returns the authentication result in advance before successful authentication unlock |
| `DomainAccountUnlockExtraInfo` | New struct | InnerAPI | Carries `successExtraInfo` (Uint8Array), carrying the authentication result JSON `{"authResult":0,"userId":<id>}` |
| `DomainAccountUnlockExtraInfoIdl` | New struct | IDL | IDL-layer mirror struct, auto-serialized |
| `IDomainAccountCallback::OnAcquireInfo` | New method | IDL | Domain account IPC callback adds `OnAcquireInfo(module, acquireInfo, DomainAccountUnlockExtraInfoIdl)` |
| `DomainAccountCallbackService::OnAcquireInfo` | New method | Framework | The IPC stub receives it, converts IDL→InnerKit, and forwards to the in-process `DomainAccountCallback` |
| `DomainAuthCallbackAdapter::OnAcquireInfo` | New method | InnerAPI | Wraps `ATTR_EXTRA_INFO` into `Attributes`, passing directly to `IDMCallback` (in-process, not Serialize) |
| `InnerDomainAuthCallback::OnAcquireInfo` | New method | Service | no-op implementation (the service side does not receive this callback) |

### Excluded Items Confirmation

| Dimension | Involved? | Basis | If involved, which downstream document |
|------|--------|------|--------------------------|
| Performance | No | No new long-latency paths, reuses existing unlock flow, plugin calls are asynchronous | N/A |
| Security and permissions | Yes | uid 7058 whitelist, MANAGE_USER_IDM/ACCESS_USER_AUTH_INTERNAL permissions, token/secret zeroing, storage key management | design.md / spec.md |
| Compatibility | Yes | Plugin .so upgraded in sync, new fields are added incrementally, no breaking changes | spec.md |
| API/SDK | Yes | New InnerKit (InnerAPI) methods, no Public API involved | design.md / spec.md |
| IPC/cross-process | Yes | New IDL methods (SetDomainAuthUnlockEnabled and AuthUserWithUnlockOptions); DomainAccountUnlockOptions must be serializable for IPC | design.md |
| Build and components | No | No new source files or components, no new GN flag | N/A |
| Internationalization/accessibility | No | No UI changes | N/A |
| Data migration | No | No storage format changes, no local persistence | N/A |

### Change Control

| Change type | Trigger condition | Handling rule |
|----------|----------|----------|
| Scope addition | New unlock mode or authentication flow | Re-assess complexity and design impact |
| AC change | Modify observable behavior or error codes | Re-approve baseline and Spec |
| API change | Add/modify InnerKit API | Trigger design approval |
| Non-functional metric change | Security threshold change | Re-confirm test plan |
| Plugin contract change | Modify C-ABI struct or function signature | Trigger plugin team coordination |

### Entry Conditions for Design/Spec

- [x] All P0/P1 user stories have ACs
- [x] Each AC is testable and measurable
- [x] In-scope/out-of-scope confirmed
- [x] `manifest.target_release` confirmed or explicitly TBD
- [x] `manifest.profile` confirmed or explicitly none
- [x] Involved repos, modules, SIGs identified
- [x] Excluded items marked N/A
- [x] Change control rules confirmed
- [x] Complex level has completed solution exploration (2 routing solutions + 2 authIntent passing solutions + trade-off rationale)
- [x] Context and knowledge source retrieval log filled in; reasons for not querying key sources recorded
- [x] Target repo Agent guide checked and key constraints recorded (AGENTS.md)

**Baseline conclusion:** Pass
