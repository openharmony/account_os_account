# Domain Account Module - Agent Instruction Guide

> Scope: **directory** `services/accountmgr/src/domain_account/` — Domain Account (enterprise
> domain account) service logic. Also covers the matching framework (`frameworks/domain_account/`),
> inner API (`interfaces/innerkits/domain_account/`), and NAPI (`interfaces/kits/napi/domain_account/`).
> Parent: [../../../../AGENTS.md](../../../../AGENTS.md) (root, §1–8 framework applies here too).
> Target: any coding agent editing this module.
> Feature flag: `os_account_support_domain_accounts` (master switch; default `true`).
> C++ define: `SUPPORT_DOMAIN_ACCOUNTS` (derived from the gni flag).

---

## 1. Code Map

### 1.0 Quick Reference — Most Common Tasks

> **Use this table first.** It maps the top tasks directly to file:line so you
> can hit the right file in one step. Detailed routing in §1.4 and §2.

| Task | File | What to read |
|------|------|--------------|
| Add/change an IPC method | `domain_account_manager_service.cpp` (stub) → `inner_domain_account_manager.cpp` (logic) | Permission map; delegate pattern |
| Add SO-plugin method | `domain_plugin.h` (enum+typedef) → `domain_plugin_adapter.cpp` (name map) → `inner_domain_account_manager.cpp` (`PluginXxx`) | Full §1.4 row |
| Add JS-plugin method | `domain_account_plugin.h` (virtual) → `IDomainAccountPlugin.idl` → `domain_account_plugin_service.cpp` → `inner_domain_account_manager.cpp` (`StartXxx`) | Full §1.4 row |
| Auth (password/popup/token) | `inner_domain_account_manager.cpp` `Auth()` / `AuthUser()` / `AuthWithPopup()` / `AuthWithToken()` | §2.4 call chain |
| Domain unlock (EL2/EL3/EL4) | `inner_domain_account_manager.cpp` `GetUnlockDeviceConfig()` / `AuthUserWithUnlockOptions()` / `HandleUnlockResult()` | §4.7; §2.4 call chain |
| Plugin register/unregister/died | `inner_domain_account_manager.cpp` `RegisterPlugin()`/`UnregisterPlugin()`/`OnPluginDied()` | §4.2 lifecycle |
| Bind/unbind domain↔OS | `inner_domain_account_manager.cpp` `BindDomainAccount()` / `UnbindDomainAccountSync()` | §2.4 call chain |
| Server config CRUD | `inner_domain_account_manager.cpp` all `no_sanitize("cfi")` methods | All `no_sanitize("cfi")` |
| Permission check | `domain_account_manager_service.cpp` `CheckPermission()` | §4.4 |
| DFX / HiSysEvent | `domain_hisysevent_utils.cpp`; `account_hisysevent_adapter.h` | §4.10 |
| Error codes | `account_error_no.h` (`ERR_DOMAIN_ACCOUNT_*`) | §4.12 |
| Locking rules | §4.5 below | 4 locks + hierarchy |
| Build & test commands | §5.1 (self-contained, copy-pasteable) | No hop to root |

### 1.1 Responsibility

The Domain Account module manages **enterprise domain accounts**: plugin-based
authentication (SO native plugin or JS/C++ IPC plugin), domain account binding
to OS accounts, access-token issuance, server-config management, status
subscription, and the domain-side storage-unlock path (EL2/EL3/EL4 unlock via
`AuthIntent == UNLOCK_INTENT`).

It does **not** own account persistence — domain account data is embedded in
`OsAccountInfo::domainInfo_` and persisted by the OS account storage layer
(`{userId}\account_info.json`). See §4.6 Data Persistence.

### 1.2 Directory Structure

Service logic: `services/accountmgr/src/domain_account/` (9 .cpp files incl. `inner_domain_account_manager.cpp`, `domain_account_manager_service.cpp`, `domain_plugin_adapter.cpp`, `domain_hisysevent_utils.cpp`, `status_listener_manager.cpp`).
Headers: `services/accountmgr/include/domain_account/`.
Framework: `frameworks/domain_account/` (client, plugin service, callback adapters, IDL files).
Inner API: `interfaces/innerkits/domain_account/native/include/` (8 headers: `domain_account_common.h`, `domain_plugin.h`, `domain_account_plugin.h`, `domain_account_callback.h`, `domain_auth_callback.h`, `domain_account_client.h`, etc.).
NAPI: `interfaces/kits/napi/domain_account/`.
Use `codegraph_files` or `ls` for full tree.

### 1.3 Key Entry Points

| Component | File | Notes |
|-----------|------|-------|
| Singleton orchestrator | [inner_domain_account_manager.cpp](inner_domain_account_manager.cpp) | All plugin dispatch; singleton via `GetInstance()` |
| IPC stub | [domain_account_manager_service.cpp](domain_account_manager_service.cpp) | Permission check → delegates to inner mgr |
| SO plugin loader | [domain_plugin_adapter.cpp](domain_plugin_adapter.cpp) | `dlopen`/`dlsym`; C-struct conversion |
| DFX | [domain_hisysevent_utils.cpp](domain_hisysevent_utils.cpp) | HiSysEvent reporting; gated by plugin-registered flags |
| Status listeners | [status_listener_manager.cpp](status_listener_manager.cpp) | Server-side listener set + async notify |
| Client facade | [frameworks/domain_account/src/domain_account_client.cpp](../../../../../../frameworks/domain_account/src/domain_account_client.cpp) | Singleton; sync/async IPC |

> **SA ID**: Domain Account is **not** a standalone SA. It is registered lazily
> inside `AccountMgrService::GetDomainAccountService()` (accountmgr SA 200,
> `account_mgr_service.cpp`), gated by `#ifdef SUPPORT_DOMAIN_ACCOUNTS`. Clients
> reach it via the accountmgr SA 200 and `DomainAccountClient::GetDomainAccountProxy()`.

### 1.4 Where to Look (task → path)

| Task | Start here |
|------|------------|
| Add/change an IPC method | `domain_account_manager_service.cpp` (stub) → `inner_domain_account_manager.cpp` (logic) |
| Plugin lifecycle (register/unregister/died) | `inner_domain_account_manager.cpp` `RegisterPlugin()`/`UnregisterPlugin()`/`OnPluginDied()` |
| Add a new SO-plugin method | `domain_plugin.h` (add to `PluginMethodEnum` + typedef) → `domain_plugin_adapter.cpp` (`METHOD_NAME_MAP` + conversion helpers) → `inner_domain_account_manager.cpp` (`PluginXxx` dispatcher) |
| Add a new JS-plugin method | `domain_account_plugin.h` (add pure virtual) → `IDomainAccountPlugin.idl` → `domain_account_plugin_service.cpp` (stub) → `inner_domain_account_manager.cpp` (`StartXxx` dispatch) |
| Auth flow (password/token/popup) | `inner_domain_account_manager.cpp` `Auth()` / `AuthUser()` / `AuthWithPopup()` / `AuthWithToken()` |
| Domain unlock (EL2/EL3/EL4) | `inner_domain_account_manager.cpp` `GetUnlockDeviceConfig()` / `AuthUserWithUnlockOptions()` / `HandleUnlockResult()` |
| Bind/unbind domain↔OS account | `inner_domain_account_manager.cpp` `BindDomainAccount()` / `UnbindDomainAccountSync()` |
| Crash-recovery of interrupted bind | `inner_domain_account_manager.cpp` `CheckAndRecoverBindDomainForUncomplete()` / `CleanUnbindDomainAccount()` |
| Server config (add/remove/update/get) | `inner_domain_account_manager.cpp` (all `__attribute__((no_sanitize("cfi")))`) |
| Access token issuance | `inner_domain_account_manager.cpp` `GetAccessToken()` |
| Status listener | `status_listener_manager.cpp` (server) / `frameworks/.../domain_account_status_listener_manager.cpp` (client) |
| DFX / HiSysEvent | `domain_hisysevent_utils.cpp`; `dfx/hisysevent_adapter/account_hisysevent_adapter.h` |
| Error codes | `interfaces/innerkits/common/include/account_error_no.h` (`ERR_DOMAIN_ACCOUNT_*`) |
| Locking / concurrency | §4.5 Lock Hierarchy below |

### 1.5 Nested AGENTS.md routing

When the task crosses modules, also read:
- **OS account bind/activate**: [../osaccount/AGENTS.md](../osaccount/AGENTS.md) — `BindDomainAccount` coordinates with `IInnerOsAccountManager`; account lifecycle.
- **IAM storage unlock**: [../account_iam/AGENTS.md](../account_iam/AGENTS.md) §3.4 — `HandleUnlockResult` calls `InnerAccountIAMManager::UnlockUserStorage` + `SetOsAccountIsVerified(true)` (Pitfall 7 in root AGENTS.md).
- **Distributed account**: [../distributed_account/AGENTS.md](../distributed_account/AGENTS.md) — *different module* (DVID/OHOS account), do not confuse with domain account.

---

## 2. Knowledge Routing

### 2.1 Task-based routing

| If the task involves… | Read this first |
|----------------------|-----------------|
| SO plugin (native C ABI) add/change | §4.3 SO Plugin vs JS Plugin; `domain_plugin.h`; `domain_plugin_adapter.cpp` |
| JS plugin (C++ IPC) add/change | §4.3 SO Plugin vs JS Plugin; `domain_account_plugin.h`; `IDomainAccountPlugin.idl` |
| Domain unlock (storage key) | §4.7 Domain Unlock Flow; `HandleUnlockResult()`; [account_iam/AGENTS.md](../account_iam/AGENTS.md) §3.4 |
| Plugin lifecycle / death recipient | §4.2 Plugin Lifecycle; `RegisterPlugin()`/`OnPluginDied()` |
| Locking / deadlock | §4.5 Lock Hierarchy; root AGENTS.md §3.4 Pitfall 6 |
| Sync (blocking) calls | §4.8 Sync Helpers — `*Sync` methods use `condition_variable` + XCollie 30s |
| Bind/unbind + crash recovery | §4.9 Bind/Unbind & Recovery; `CheckAndRecoverBindDomainForUncomplete()` |
| DFX / HiSysEvent | `domain_hisysevent_utils.cpp`; §4.10 DFX |
| Permission model | `domain_account_manager_service.cpp` `CheckPermission()`; §4.4 Permissions |
| Conditional compilation | §4.11 Conditional Compilation |
| Error codes | `account_error_no.h` (`ERR_DOMAIN_ACCOUNT_*`); §4.12 Error Codes |
| Test additions | §5 Verification; `frameworks/domain_account/test/moduletest/` |

### 2.2 Vocabulary routing

| Term / acronym | What it means | Read |
|---------------|---------------|------|
| SO plugin | Native C-ABI plugin loaded via `dlopen` into `libHandle_`; called by direct function pointer (`methodMap_`). Path: `/system/lib{,64}/platformsdk/libdomain_account_plugin.z.so` | §4.3; `domain_plugin.h` |
| JS plugin | C++ plugin registered via IPC; `plugin_` is `sptr<IDomainAccountPlugin>` proxy. Calls go through IPC. | §4.3; `domain_account_plugin.h` |
| `plugin_` | `sptr<IDomainAccountPlugin>` — the JS plugin proxy. Guarded by `mutex_`. | §4.5 |
| `libHandle_` | `void*` — the `dlopen` handle for the SO plugin. Guarded by `libMutex_`. | §4.5 |
| `methodMap_` | `std::map<PluginMethodEnum, void*>` — SO plugin function pointers. Guarded by `libMutex_`. | §4.5 |
| `PluginMethodEnum` | Enum of all SO-plugin methods (`AUTH`, `GET_UNLOCK_DEVICE_CONFIG`, …). Defined in `domain_plugin.h`. | §3.3 |
| `no_sanitize("cfi")` | Attribute on all SO-dispatch functions — calls cross a DSO boundary; CFI would otherwise abort. Do not remove. | §4.3 |
| `DomainAccountInfo` | Core struct: `domain_`, `accountName_`, `accountId_`, `serverConfigId_`, `status_`, `isAuthenticated`, `additionInfo_`. Embedded in `OsAccountInfo::domainInfo_`. | §4.6 |
| `UNLOCK_INTENT` (=1) | `AuthIntent` value marking a storage-unlock auth (EL2/EL3/EL4). Routes to `AuthUserWithUnlockOptions` (SO-only). | §4.7 |
| `DomainAccountStatus` | `LOGOUT(0)`, `LOGIN_BACKGROUND(1)`, `LOGIN(2)`, `LOG_END(3)`. | `domain_account_common.h` |
| `DomainAccountEvent` | `LOG_IN(0)`, `TOKEN_UPDATED(1)`, `TOKEN_INVALID(2)`, `LOG_OUT(3)`. | `domain_account_common.h` |
| `userTokenMap_` | In-memory token cache per user. Guarded by `tokenMutex_`. Zeroed with `memset_s`/`std::fill` after use. | §4.5; §4.6 |
| Domain-bound flag | Transactional file tracking in-progress bind/unbind for crash recovery. | §4.9 |
| `callingUid_` | UID that registered the JS plugin; only that UID may unregister. | §4.2 |

### 2.3 Pre-edit protocol

See root [AGENTS.md](../../../../AGENTS.md) §2.4. Before writing code, state:
1. **Task category** (IPC method / plugin lifecycle / SO-plugin dispatch / JS-plugin dispatch / unlock / bind / DFX / test / other).
2. **Documents read** (per §2.1–2.2 above).
3. **Constraints found** (§4 Do-not / Ask-before rules that apply).

### 2.4 Call Chain Key Nodes

> When tracing or modifying a flow, these are the **must-hit nodes**. Missing
> any node means the call chain is incomplete. Each `→` is a function call; a
> `|` marks a branching point.

**Plugin register (JS):**
```
DomainAccountClient::RegisterPlugin()
  → DomainAccountPluginService(plugin)              # wrap in IPC stub
  → proxy->RegisterPlugin(pluginService)            # IPC
  → DomainAccountManagerService::RegisterPlugin()   # CheckPermission(MANAGE_LOCAL_ACCOUNTS)
  → InnerDomainAccountManager::RegisterPlugin()    # lock(mutex_); set plugin_; callingUid_; SetJsPluginRegistered(true)
  → plugin->AsObject()->AddDeathRecipient(deathRecipient_)  # death monitoring
```

**Plugin unregister (JS):**
```
DomainAccountClient::UnregisterPlugin → proxy->UnregisterPlugin
  → DomainAccountManagerService::UnregisterPlugin()  # CheckPermission
  → InnerDomainAccountManager::UnregisterPlugin()   # verify callingUid_ match
  → ClearPlugin()                                    # null plugin_; SetJsPluginRegistered(false)
```

**Auth (password, both plugins):**
```
DomainAccountClient::Auth → proxy->Auth
  → DomainAccountManagerService::Auth()     # ACCESS_USER_AUTH_INTERNAL; memset password
  → InnerDomainAccountManager::Auth()
  |─ JS plugin path: plugin_ != nullptr → StartAuth() → plugin->Auth(...) via IPC
  |─ SO plugin path: libHandle_ != nullptr → PluginAuth() → (*AuthFunc)(methodMap_[AUTH])
  |     → (async callback) PluginAuthCallback() (no_sanitize("cfi"))
  |         → AuthResultInfoCallback()
  → (both) InnerDomainAuthCallback::OnResult()  # insert token; NotifyDomainAccountEvent(LOG_IN)
```

**Domain unlock (SO-only, EL2/EL3/EL4):**
```
DomainAccountClient::AuthUser(getPasswordHooks, callback, unlockOptions, contextId)
  → (spawns thread) proxy->AuthUserWithUnlockOptions
  → DomainAccountManagerService::AuthUserWithUnlockOptions()   # ACCESS_USER_AUTH_INTERNAL; route by authIntent==UNLOCK_INTENT
  → InnerDomainAccountManager::AuthUserWithUnlockOptions()
     1. IsJsPluginRegistered() → ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE      # JS guard (Pitfall D1)
     2. IsSoPluginLoaded()    → ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE      # SO guard
     3. GetDomainAccountInfoByUserId → ERR_DOMAIN_ACCOUNT_SERVICE_NOT_DOMAIN_ACCOUNT
     4. PluginGetUnlockDeviceConfigWithInfo → if !enableUnlockDevice → ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE
     5. PluginAuthWithUnlockIntent() → (*AuthWithUnlockIntentFunc)(...)  # SO direct call
     6. AddToContextMap(contextId, innerCallback)
  → (SO callback) InnerDomainAuthCallback::OnResultWithUnlock()
  → HandleUnlockResult(authResult)
     → InnerAccountIAMManager::UnlockUserStorage          # EL2
     → InnerAccountIAMManager::UnlockEnhancedStorage       # EL3/EL4
     → IInnerOsAccountManager::SetOsAccountIsVerified(true)  # MUST reach here (Pitfall 7)
```

**Bind domain↔OS account:**
```
OsAccountManager::CreateOsAccountForDomain → IInnerOsAccountManager
  → InnerDomainAccountManager::BindDomainAccount()     # lock createOrBindDomainAccountMutex_
  → CheckOsAccountCanBindDomainAccount()               # preconditions
  → OsAccountControlFileManager::SetDomainBoundFlag              # transactional flag (crash recovery)
  → PluginBindAccount() |─ JS: plugin->OnAccountBound  |─ SO: (*BindAccountFunc)(...)
  → (callback) → create/activate OS account via IInnerOsAccountManager
  → OsAccountControlFileManager::ClearDomainBoundFlag            # complete transaction
```
> Crash mid-bind → flag stays set → `CheckAndRecoverBindDomainForUncomplete()`
> runs during boot → resume or rollback.

**Crash recovery (boot):**
```
Boot → IInnerOsAccountManager init
  → InnerDomainAccountManager::CleanUnbindDomainAccount()  # iterate all accounts
  → CheckAndRecoverBindDomainForUncomplete()               # per-account: read flag → resume bind
```

---

## 3. Core Components

### 3.1 InnerDomainAccountManager — key methods

[inner_domain_account_manager.cpp](inner_domain_account_manager.cpp). Singleton
(`GetInstance()`).

**Plugin lifecycle:**

| Method | Description |
|--------|-------------|
| `RegisterPlugin(plugin)` | Register JS plugin; sets `callingUid_`; `SetJsPluginRegistered(true)` |
| `UnregisterPlugin()` | Verify `callingUid_` match → `ClearPlugin()` |
| `OnPluginDied()` | Called by death recipient → `ClearPlugin()` |
| `ClearPlugin()` | Null out `plugin_`/`callingUid_`/`deathRecipient_`; `SetJsPluginRegistered(false)` |
| `IsPluginAvailable()` | `plugin_ != nullptr || libHandle_ != nullptr` (locks both mutexes via `std::lock`) |
| `IsSoPluginLoaded()` | `libHandle_ != nullptr` |
| `IsJsPluginRegistered()` | `plugin_ != nullptr` |

**Auth:**

| Method | SO/JS | Notes |
|--------|-------|-------|
| `Auth(info, password, callback)` | Both | Dispatches by `IsPluginAvailable()` |
| `AuthWithParameters(...)` | Both | + `DomainAccountAuthOptions` |
| `AuthUser(userId, password, callback)` | Both | Resolve userId → domainInfo → `InnerAuth` |
| `AuthWithPopup(userId, callback)` | Both | |
| `AuthWithToken(userId, token)` | Both | |
| `CancelAuth(callback)` / `CancelAuth(contextId)` | Both | |
| `AuthResultInfoCallback(contextId, info, error)` | SO | SO-plugin async callback entry (via static trampoline `PluginAuthCallback()`) |

**Domain unlock (SO-only):**

| Method | Notes |
|--------|-------|
| `GetUnlockDeviceConfig(userId, enable, mode)` | JS plugin → returns disabled; SO → `PluginGetUnlockDeviceConfigWithInfo` |
| `AuthUserWithUnlockOptions(localId, password, options, callback)` | JS → `ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE`; SO → `PluginAuthWithUnlockIntent` |
| `HandleUnlockResult(authResult)` | `UnlockUserStorage` + `UnlockEnhancedStorage` + `SetOsAccountIsVerified(true)` |
| `PluginAuthWithUnlockIntent(info, password, challenge, contextId)` | SO direct call |

**Bind / unbind / recovery:**

| Method | Notes |
|--------|-------|
| `BindDomainAccount(localId, domainInfo, callback)` | Acquires `createOrBindDomainAccountMutex_` |
| `BindDomainAccountSync(info, localId)` | Blocking; `DomainAccountCallbackSync` + XCollie 30s |
| `UnbindDomainAccountSync(info, localId)` | Blocking; XCollie 30s |
| `GetDomainAccountInfoSync(localId, info, fullInfo)` | Blocking; XCollie 30s |
| `CheckAndRecoverBindDomainForUncomplete(accountInfo)` | Crash recovery during boot |
| `CleanUnbindDomainAccount()` | Iterate accounts, recover interrupted binds |
| `CheckOsAccountCanBindDomainAccount(osAccountInfo)` | |
| `CheckDomainAccountCanBindOsAccount(domainInfo)` | |

**Token management:**

| Method | Notes |
|--------|-------|
| `InsertTokenToMap(userId, token)` | Guarded by `tokenMutex_` |
| `GetTokenFromMap(userId, token)` | Guarded by `tokenMutex_` |
| `RemoveTokenFromMap(userId)` | Guarded by `tokenMutex_` |
| `UpdateAccountToken(info, token)` | Empty token → logout + remove from map |

**Server config (all `__attribute__((no_sanitize("cfi")))`):**
`AddServerConfig()`, `RemoveServerConfig()`, `UpdateServerConfig()`,
`GetServerConfig()`, `GetAllServerConfigs()`, `GetAccountServerConfig()`.

### 3.2 DomainAccountManagerService — IPC stub

[domain_account_manager_service.cpp](domain_account_manager_service.cpp). Inherits
`DomainAccountStub` (IDL-generated from `IDomainAccount.idl`). Each method does
`CheckPermission(code)` then forwards to `InnerDomainAccountManager::GetInstance()`.

**Permission check** (`CheckPermission()`):
- `uid == 0` (root) bypasses all checks.
- Codes in `NON_SYSTEM_API_SET` (server-config + `UpdateAccountInfo`) skip the
  system-app check (these are non-system-app APIs).
- All other codes require the caller to be a system app.
- `PERMISSIONMAP` maps each code to one or more permission strings;
  `std::any_of` means any one suffices.

### 3.3 DomainPluginAdapter — SO plugin loader

[domain_plugin_adapter.cpp](domain_plugin_adapter.cpp). Singleton.

**`PluginMethodEnum`** (`domain_plugin.h`): `ADD_SERVER_CONFIG(0)`,
`REMOVE_SERVER_CONFIG`, `UPDATE_SERVER_CONFIG`, `GET_SERVER_CONFIG`,
`GET_ALL_SERVER_CONFIGS`, `GET_ACCOUNT_SERVER_CONFIG`, `AUTH`, `AUTH_WITH_POPUP`,
`AUTH_WITH_TOKEN`, `GET_ACCOUNT_INFO`, `GET_AUTH_STATUS_INFO`, `BIND_ACCOUNT`,
`UNBIND_ACCOUNT`, `IS_ACCOUNT_TOKEN_VALID`, `GET_ACCESS_TOKEN`, `UPDATE_ACCOUNT_INFO`,
`IS_AUTHENTICATION_EXPIRED`, `SET_ACCOUNT_POLICY`, `GET_ACCOUNT_POLICY`,
`CANCEL_AUTH`, `AUTH_WITH_SERVER_CONFIG`, `AUTH_WITH_UNLOCK_INTENT`,
`GET_UNLOCK_DEVICE_CONFIG`, `COUNT`.

**`METHOD_NAME_MAP`** maps each enum to the C symbol exported by
the SO (e.g. `AUTH → "Auth"`, `GET_UNLOCK_DEVICE_CONFIG → "GetUnlockDeviceConfigResult"`).

**`LoadPlugin(libHandle, methodMap, path, libName)`**: `dlopen` + iterate
all `COUNT` symbols via `dlsym`; if any missing → `dlclose` + clear; on success
`SetNativePluginRegistered(true)`.

**`ClosePlugin(libHandle, methodMap)`**: `dlclose` + clear + `SetNativePluginRegistered(false)`.

**Conversion helpers**: `SetPluginString`/`CleanPluginString`, `SetPluginUint8Vector`/
`GetAndCleanPluginUint8Vector`, `GetAndCleanPluginBusinessError`, `SetPluginDomainAccountInfo`/
`CleanPluginDomainAccountInfo`, `GetAndCleanPluginAuthResultInfo`, `GetAndCleanPluginAuthStatusInfo`,
`GetAndCleanPluginUnlockDeviceConfigResult`, `GetAndCleanPluginDomainAccountPolicy`,
`SetPluginGetDomainAccessTokenOptions`, `ParsePluginConfigInfoList`.

### 3.4 DomainAccountClient — client facade

`frameworks/domain_account/src/domain_account_client.cpp`. Singleton.
All real work gated by `#ifdef SUPPORT_DOMAIN_ACCOUNTS`; without it, methods
return `ERR_DOMAIN_ACCOUNT_NOT_SUPPORT`.

Key methods: `RegisterPlugin`, `UnregisterPlugin`, `Auth`, `AuthUser` (sync +
unlock variants), `AuthWithPopup`, `CancelAuth`, `HasAccount`, `UpdateAccountToken`,
`IsAuthenticationExpired`, `GetAccessToken`, `GetAccountStatus`,
`GetDomainAccountInfo`, `UpdateAccountInfo`, `RegisterAccountStatusListener`,
server config CRUD, `SetAccountPolicy`/`GetAccountPolicy`,
`IsDomainAccountSupported`.

`AuthProxyInit()` creates a `DomainAccountCallbackService`, gets the
proxy, generates a `contextId`. On SA restart, `RestoreListenerRecords()` and
`RestorePlugin()` re-register.

### 3.5 Callbacks (what each does)

| Class | Role |
|-------|------|
| `DomainAccountCallback` | Abstract base; `OnResult(errCode, Parcel&)` + `OnAcquireInfo(...)` |
| `DomainAuthCallback` | Abstract base returning typed `DomainAuthResult` |
| `GetAccessTokenCallback` | Abstract base for `GetAccessToken` |
| `DomainAccountStatusListener` | Abstract base for status change notifications |
| `DomainAccountCallbackService` | IPC stub wrapping a `shared_ptr<DomainAccountCallback>` |
| `DomainAccountCallbackClient` | Adapter: `sptr<IDomainAccountCallback>` proxy → `DomainAccountCallback` |
| `InnerDomainAuthCallback` | Service-internal callback (`DomainAccountCallbackStub`); inserts token, fires events, handles unlock (`HandleUnlockResult`) |
| `DomainHasDomainInfoCallback` | Wraps `HasDomainAccount` result; verifies match |
| `CheckUserTokenCallback` | Sync callback for `CheckUserToken` (condition_variable) |
| `UpdateAccountInfoCallback` | Sync callback for `GetDomainAccountInfoSync` |
| `DomainAccountCallbackSync` | Generic sync callback (guards against double-call) |
| `GetAccessTokenCallbackAdapter` | Adapts `DomainAccountCallback` → `GetAccessTokenCallback` |

---

## 4. Constraints & Boundaries

### 4.1 Do not (without explicit user escalation)

Each rule below is tagged with a **static-check** pattern where applicable — use
`grep` to verify compliance before submitting.

- **Do not change `DomainAccountInfo` field names/types** (`domain_account_common.h`)
  — embedded in `OsAccountInfo::domainInfo_` and persisted in
  `{userId}\account_info.json`; breaks upgrade compatibility (root AGENTS.md §3.1).
  <br>`grep -rn 'domain_\|accountName_\|accountId_\|serverConfigId_' interfaces/innerkits/domain_account/native/include/domain_account_common.h`
- **Do not change `PluginMethodEnum` existing values/order** (`domain_plugin.h`)
  — the SO plugin exports symbols matched by enum index; reordering breaks the
  `dlsym` lookup and the SO ABI.
  <br>`grep -n 'PluginMethodEnum' interfaces/innerkits/domain_account/native/include/domain_plugin.h`
- **Do not remove `__attribute__((no_sanitize("cfi")))` from SO-dispatch
  functions** — they call across a DSO boundary; removing CFI annotation causes
  aborts at runtime.
  <br>`grep -rn 'no_sanitize.*cfi' services/accountmgr/src/domain_account/` — every `Plugin*` dispatcher must retain the attribute.
- **Do not remove or weaken permission checks** in `DomainAccountManagerService`
  (`CheckPermission()`) — security boundary (root AGENTS.md §3.1).
  <br>`grep -n 'CheckPermission\|PERMISSIONMAP\|AccountPermissionManager' services/accountmgr/src/domain_account/domain_account_manager_service.cpp`
- **Do not change `callingUid_` ownership semantics** — only the registering UID
  may `UnregisterPlugin` / `UpdateAccountToken`; changing this breaks the
  plugin-unregistration trust model.
- **Do not hold `mutex_`/`libMutex_`/`tokenMutex_` during IPC or disk I/O** —
  risk of deadlock or IPC thread exhaustion (root AGENTS.md §3.4 Pitfall 6).
  <br>`grep -n 'lock_guard.*mutex_\|lock_guard.*libMutex_\|lock_guard.*tokenMutex_' services/accountmgr/src/domain_account/inner_domain_account_manager.cpp` — verify no external call follows within the same scope.
- **Do not remove token/secret zeroing** (`memset_s`/`std::fill(...,0)` on
  `password`/`token`/`secret`) — security boundary (Pitfall 3). IPC marshalling
  may copy buffers.
  <br>`grep -rn 'memset_s\|std::fill' services/accountmgr/src/domain_account/` — password/token/secret buffers must be zeroed.
- **Do not change `DomainAccountStatus` / `DomainAccountEvent` enum values**
  (`domain_account_common.h`) — persisted and used across IPC.
- **Do not change HiSysEvent operation-name strings** (`Constants::DOMAIN_OPT_*`
  in `account_hisysevent_adapter.h`) — existing fault attribution depends on them.
- **Do not change the SO plugin library name/path**
  (`libdomain_account_plugin.z.so` under `platformsdk/`) without coordinating
  with the SO-plugin vendor — runtime `dlopen` depends on this exact name.
- **Do not change `UNLOCK_INTENT = 1`** — persisted `AuthIntent` value; the
  unlock routing in `DomainAccountManagerService::AuthUserWithUnlockOptions`
  depends on it.
- **Do not omit `IsJsPluginRegistered()` guard on SO-only interfaces** (Pitfall D1)
  — JS plugin takes priority; both plugins can coexist.
  <br>`grep -n 'IsJsPluginRegistered\|IsSoPluginLoaded' services/accountmgr/src/domain_account/inner_domain_account_manager.cpp` — every `Plugin*` entry point must show `IsJsPluginRegistered` before `IsSoPluginLoaded`.

### 4.2 Plugin Lifecycle

- **SO plugin**: loaded in `InnerDomainAccountManager` constructor
  via `dlopen`; retries `MAX_RETRY_TIMES` with `RETRY_SLEEP_MS`. Active immediately
  at boot if the SO file exists.
- **JS plugin**: registered at runtime via `RegisterPlugin` IPC; stores
  `sptr<IDomainAccountPlugin> plugin_` + `DomainAccountPluginDeathRecipient`.
- **Mutual exclusivity is *not* enforced in code**: both `plugin_` and
  `libHandle_` can be non-null simultaneously. In practice a device ships with
  one or the other. `IsPluginAvailable()` returns true if either is present.
  The unlock path (`GetUnlockDeviceConfig`/`AuthUserWithUnlockOptions`)
  **prioritizes the JS-plugin guard** — when `IsJsPluginRegistered()` is true,
  unlock returns disabled/unsupported even if the SO plugin is also loaded
  (the JS plugin does not support unlock).
- **Plugin death**: `OnPluginDied` → `ClearPlugin()`. The SO plugin has no
  death recipient (it lives in-process); only the JS plugin gets a
  `DomainAccountPluginDeathRecipient`.

### 4.3 SO Plugin vs JS Plugin

| Aspect | SO plugin (native C ABI) | JS plugin (C++ IPC) |
|--------|--------------------------|---------------------|
| Storage | `libHandle_` (`void*`), `methodMap_` (`map<enum,void*>`) | `plugin_` (`sptr<IDomainAccountPlugin>`) |
| Mutex | `libMutex_` | `mutex_` |
| Loaded | `dlopen` in constructor | `RegisterPlugin` IPC at runtime |
| Calls | Direct function-pointer call (no IPC) | IPC proxy call |
| CFI | `__attribute__((no_sanitize("cfi")))` required | Normal CFI applies |
| Async callback | Static `PluginAuthCallback` trampoline → `AuthResultInfoCallback` | `DomainAccountCallbackService` stub |
| Unlock support | Yes (`GET_UNLOCK_DEVICE_CONFIG`, `AUTH_WITH_UNLOCK_INTENT`) | **No** — returns disabled/`ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE` |
| HiSysEvent flag | `SetNativePluginRegistered` | `SetJsPluginRegistered` |

**When adding a new plugin method**: add to BOTH the SO ABI (`domain_plugin.h`:
enum + typedef + result struct) **and** the JS contract
(`domain_account_plugin.h` + `IDomainAccountPlugin.idl`), unless the method is
SO-only (like unlock) or JS-only.

### 4.4 Permissions

| Permission | Operations |
|-----------|------------|
| `MANAGE_LOCAL_ACCOUNTS` | RegisterPlugin, UnregisterPlugin, HasDomainAccount, UpdateAccountToken, IsAuthenticationExpired, SetAccountPolicy, GetAccountPolicy, Auth (alt), server configs (alt) |
| `ACCESS_USER_AUTH_INTERNAL` | Auth, AuthWithParameters, AuthUser, AuthUserWithUnlockOptions, AuthWithPopup, CancelAuth |
| `GET_LOCAL_ACCOUNTS` | GetAccountStatus, RegisterAccountStatusListener, UnregisterAccountStatusListener |
| `GET_DOMAIN_ACCOUNTS` | GetDomainAccountInfo |
| `MANAGE_DOMAIN_ACCOUNTS` | UpdateAccountInfo (non-system API) |
| `MANAGE_DOMAIN_ACCOUNT_SERVER_CONFIGS` | Add/Remove/Update/Get/GetAll server configs (non-system API) |
| `INTERACT_ACROSS_LOCAL_ACCOUNTS` | IsAuthenticationExpired (alt) |

EDM UID whitelist: `{3057}` for `SetAccountPolicy`/`GetAccountPolicy`.
Min user id: `START_USER_ID = 100` for `AuthUser`/`AuthUserWithUnlockOptions`.
`uid == 0` (root) bypasses all checks.

### 4.5 Lock Hierarchy

Four locks in `InnerDomainAccountManager`:

| Mutex | Type | Protects | Notes |
|-------|------|----------|-------|
| `mutex_` | `std::mutex` | `plugin_`, `callingUid_`, `deathRecipient_` (JS state) | Taken briefly to snapshot `plugin_`; never held during IPC/IO |
| `libMutex_` | `std::mutex` | `methodMap_`, `libHandle_` (SO state) | Taken in ctor/dtor during load/close; never held during SO calls |
| `tokenMutex_` | `std::mutex` | `userTokenMap_` | `Insert/Get/RemoveTokenFromMap` |
| `authContextIdMapMutex_` | `std::recursive_mutex` | `authContextIdMap_`, `contextIdCount_` | Recursive because `AuthResultInfoCallback`/`InnerDomainAuthCallback::OnResult` re-enter the manager |

**Rules:**
1. `IsPluginAvailable()` acquires `mutex_` + `libMutex_` together via
   `std::lock(mutex_, libMutex_)` then adopts with `std::lock_guard(..., std::adopt_lock)`
   — deadlock-free combined acquisition. Do not change this pattern.
2. SO-dispatch functions (`PluginAuth`, `PluginAuthWithUnlockIntent`, etc.)
   read `methodMap_` **without** `libMutex_` and call the SO directly. This is
   intentional (the lock would be held across an external call — Pitfall 6).
   The `no_sanitize("cfi")` attribute compensates for the cross-DSO call.
3. `BindDomainAccount` additionally locks
   `IInnerOsAccountManager::createOrBindDomainAccountMutex_` to serialize
   create/bind across modules.
4. `DomainAccountClient` uses separate locks: `pluginServiceMutex_` (plugin
   proxy), `contextIdMutex_` (recursive; context map), `mutex_`/`recordMutex_`.

### 4.6 Data Persistence

Domain account info is **not** in a separate file — it is embedded in
`OsAccountInfo::domainInfo_` (`os_account_info.h`) and persisted by the OS
account storage layer in `{userId}\account_info.json`. When `accountName_` is
empty, the account is treated as not a domain account
(`ERR_DOMAIN_ACCOUNT_SERVICE_NOT_DOMAIN_ACCOUNT`).

**Domain-bound flag file** (transactional recovery):
`OsAccountControlFileManager::SetDomainBoundFlag`/`GetDomainBoundFlag` track
in-progress bind/unbind so a crash mid-bind is recovered by
`CheckAndRecoverBindDomainForUncomplete` during boot. On bad JSON it resets the
flag.

**In-memory token cache**: `userTokenMap_` (`map<int32_t, vector<uint8_t>>`)
holds the most recent auth token per user. Tokens zeroed with `memset_s`/
`std::fill` after use (Pitfall 3).

### 4.7 Domain Unlock Flow

Triggered by `UserAuth.auth()` with `AuthIntent == UNLOCK_INTENT`:

```
DomainAccountClient::AuthUser(getPasswordHooks, callback, unlockOptions, contextId)
  → (spawns thread) proxy->AuthUserWithUnlockOptions(localId, password, idlOptions, callbackService)
  → DomainAccountManagerService::AuthUserWithUnlockOptions()  # permission check; routes by authIntent
  → InnerDomainAccountManager::AuthUserWithUnlockOptions()
       1. IsJsPluginRegistered() → ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE (JS doesn't support unlock)
       2. IsSoPluginLoaded() → ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE if not loaded
       3. GetDomainAccountInfoByUserId → ERR_DOMAIN_ACCOUNT_SERVICE_NOT_DOMAIN_ACCOUNT if not bound
       4. PluginGetUnlockDeviceConfigWithInfo → if !enableUnlockDevice → ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE
       5. IsOsAccountDeactivatingOrLocking → ERR_IAM_BUSY
       6. PluginAuthWithUnlockIntent(domainInfo, password, challenge, contextId)
       7. AddToContextMap(contextId, innerCallback)
  → (SO calls back) AuthResultInfoCallback / InnerDomainAuthCallback::OnResultWithUnlock
       → HandleUnlockResult(authResult)
            → UnlockUserStorage (EL2)
            → UnlockEnhancedStorage (EL3/EL4)
            → SetOsAccountIsVerified(true)  [if isUpdateVerifiedStatus — see Pitfall 7]
```

> **Pitfall 7 link**: `SetOsAccountIsVerified(true)` must be reached on every
> unlock path, including no-password/auto-unlock. When modifying unlock code,
> trace that `HandleUnlockResult()` eventually calls
> `SetOsAccountIsVerified(true)`. See root AGENTS.md §3.4 Pitfall 7 and
> [account_iam/AGENTS.md](../account_iam/AGENTS.md) §3.3.

### 4.8 Sync Helpers

`BindDomainAccountSync`, `UnbindDomainAccountSync`, `GetDomainAccountInfoSync`
are blocking wrappers using `condition_variable` + `XCollie` 30s watchdog
(gated by `HICOLLIE_ENABLE`). They use `DomainAccountCallbackSync` /
`UpdateAccountInfoCallback` which guard against double-call (`isCalled_`).

> **Do not** call these on the IPC thread — they block up to 30s. They are
> intended for boot/recovery paths, not request handling.

### 4.9 Bind / Unbind & Recovery

- `BindDomainAccount()` acquires `createOrBindDomainAccountMutex_`
  (cross-module serialization with `IInnerOsAccountManager`), sets the
  domain-bound flag, calls `PluginBindAccount`, creates the OS account if
  needed, and clears the flag on completion.
- A crash mid-bind leaves the flag set → `CheckAndRecoverBindDomainForUncomplete()`
  runs during boot (`CleanUnbindDomainAccount()`) and
  resumes or rolls back the operation.
- `CheckOsAccountCanBindDomainAccount` / `CheckDomainAccountCanBindOsAccount`
  validate preconditions (account not active, not already bound, etc.).

### 4.10 DFX

[domain_hisysevent_utils.cpp](domain_hisysevent_utils.cpp). Domain
`0xD001B00`; tag `accountmgr`/`DomainAccountFwk`.

- All reporting gated by `IsPluginRegistered()` (`jsPluginRegistered_ ||
  nativePluginRegistered_`) — no events until a plugin is registered.
- `ReportStatistic(optName/enum, userId, domainInfo)` — success statistics.
  Skips `GET_CONFIG`/`GET_INFO`/`GET_POLICY` (high-frequency, would flood).
- `ReportFail(errCode, msg, optName/enum, userId, domainInfo)` — failure with
  context. Macro `REPORT_DOMAIN_ACCOUNT_FAIL` (header).
- Operation-name strings: `Constants::DOMAIN_OPT_*` in
  `dfx/hisysevent_adapter/account_hisysevent_adapter.h` (e.g.
  `DOMAIN_OPT_REGISTER="registerPlugin"`, `DOMAIN_OPT_AUTH="auth"`,
  `DOMAIN_OPT_BIND="bind"`, `DOMAIN_OPT_AUTH_WITH_UNLOCK_INTENT="authWithUnlockIntent"`).
- Do not change event names/params/domains — existing consumers depend on them
  (root AGENTS.md §3.1).

### 4.11 Conditional Compilation

| Flag / Define | Source | Effect |
|----------------|--------|--------|
| `os_account_support_domain_accounts` (gni) | `os_account.gni` (default `true`) | Master switch; adds `-DSUPPORT_DOMAIN_ACCOUNTS`; gates service + framework sources |
| `SUPPORT_DOMAIN_ACCOUNTS` (C++) | derived from gni flag | Gates all real domain-account code; without it, `DomainAccountClient` methods return `ERR_DOMAIN_ACCOUNT_NOT_SUPPORT` |
| `HAS_CES_PART` | `os_account.gni` | Gates `COMMON_EVENT_DOMAIN_ACCOUNT_STATUS_CHANGED` publishing in `status_listener_manager.cpp` |
| `HICOLLIE_ENABLE` | `os_account.gni` | Gates 30s XCollie timers in sync helpers |
| `HAS_HISYSEVENT_PART` | `os_account.gni` | Gates real HiSysEvent reporting; else no-op stubs |
| `SUPPORT_LOCK_OS_ACCOUNT` | `os_account.gni` (default `false`) | `IsOsAccountDeactivatingOrLocking` also checks lock state |
| `_ARM64_` | compiler-defined | SO path `/system/lib64/platformsdk/` vs `/system/lib/platformsdk/` |
| `FUZZ_TEST` | `services/accountmgr/BUILD.gn` | Suppresses thread-name constants |

The SO plugin presence is a **runtime** condition (`access(soPath, F_OK)` +
`dlopen`), not a compile flag.

### 4.12 Error Codes

`interfaces/innerkits/common/include/account_error_no.h` (`ERR_DOMAIN_ACCOUNT_*`).
Offset: `DOMAIN_ACCOUNT_ERR_OFFSET = ErrCodeOffset(SUBSYS_ACCOUNT, ACCOUNT_MODULE_DOMAIN_ACCOUNT_SERVICE)`.

| Code | Meaning |
|------|---------|
| `ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_ALREADY_EXIST` | JS plugin already registered |
| `ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST` | No plugin (SO missing symbol / JS not registered) |
| `ERR_DOMAIN_ACCOUNT_SERVICE_NOT_DOMAIN_ACCOUNT` | OS account has no bound domain info |
| `ERR_DOMAIN_ACCOUNT_SERVICE_LISTENER_NOT_EXIT` | Listener not in records |
| `ERR_DOMAIN_ACCOUNT_SERVICE_INVALID_CALLING_UID` | Unregister/UpdateAccountToken called by wrong uid |
| `ERR_DOMAIN_ACCOUNT_NOT_SUPPORT_BACKGROUND_ACCOUNT_REQUEST` | Background-frozen account blocked from network |
| `ERR_DOMAIN_ACCOUNT_NOT_SUPPORT` | Feature disabled (`SUPPORT_DOMAIN_ACCOUNTS` off) |
| `ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE` | Unlock requested but JS plugin active / SO not loaded / unlock disabled |

### 4.13 Ask before

- Changing `PluginMethodEnum` values/order (§4.1) — breaks SO ABI.
- Changing the lock hierarchy (§4.5) — deadlock risk.
- Changing conditional compilation macros (`SUPPORT_DOMAIN_ACCOUNTS`,
  `HAS_CES_PART`, `HICOLLIE_ENABLE`, `HAS_HISYSEVENT_PART`).
- Changing the SO plugin library name/path.
- Changing sync helper timeouts (30s XCollie).
- Adding a new `DomainAccountStatus` / `DomainAccountEvent` value.

### 4.14 Pitfalls

**Pitfall D1 — When adding SO-plugin interfaces, always consider the JS plugin scenario; priority is JS > SO, and both plugins can coexist.**

`InnerDomainAccountManager` does **not** enforce mutual exclusivity between the
JS plugin and the SO plugin: `plugin_` (JS, guarded by `mutex_`) and `libHandle_`
(SO, guarded by `libMutex_`) are independent members that can both be non-null
at the same time. Although a device typically ships with one or the other,
**coexistence is a valid runtime state** — e.g. the SO plugin is loaded via
`dlopen` in the constructor at boot, then a JS plugin registers
later via `RegisterPlugin` IPC, leaving both active simultaneously.

**Priority rule**: when both plugins coexist, the **JS plugin takes precedence
over the SO plugin**. This means any new SO-plugin-related interface (`PluginXxx`
directly calling SO function pointers) must call `IsJsPluginRegistered()` at the
entry point to check whether a JS plugin is registered first:
- If the JS plugin is registered, the SO-only interface should return "unsupported"
  (`ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE`) or return a disabled/default config,
  and **must not** fall through to the SO plugin path.
- If the JS plugin is not registered, then check `IsSoPluginLoaded()` to decide
  whether to proceed with the SO plugin path.

**Correct pattern**:
```cpp
// GetUnlockDeviceConfig — correct pattern
enableUnlockDevice = false;
unlockDeviceMode = 0;
if (IsJsPluginRegistered()) {              // 1. Check JS plugin first
    ACCOUNT_LOGI("JS plugin is in use, domain unlock is not supported");
    return ERR_OK;                         //    Return disabled config; do NOT fall through to SO path
}
if (!IsSoPluginLoaded()) {                // 2. Then check SO plugin
    return ERR_OK;
}
// 3. Proceed with SO plugin path: PluginGetUnlockDeviceConfigWithInfo(...)
```

**Anti-pattern (must avoid)**: When adding a new SO plugin interface, only
checking `IsSoPluginLoaded()` while omitting the `IsJsPluginRegistered()` check.
When both plugins coexist, this incorrectly falls through to the SO plugin path,
causing the JS plugin's capability to be ignored and JS-unsupported features to
be invoked via the SO path, resulting in undefined behavior or crashes.

**Checklist** (verify item-by-item when adding/modifying SO plugin interfaces):
- [ ] Is `IsJsPluginRegistered()` called at the entry point?
- [ ] When the JS plugin is registered, does the interface return the correct
  error code / default value (instead of falling through to the SO path)?
- [ ] Is the check order `IsJsPluginRegistered()` → `IsSoPluginLoaded()` → SO path?
- [ ] Is a test case added covering the "JS plugin registered + SO plugin loaded"
  coexistence scenario?
- [ ] Is the interface truly SO-only? If the JS plugin should also support it,
  add it to the JS plugin path (`StartXxx` / `domain_account_plugin.h` /
  `IDomainAccountPlugin.idl`) as well.

**⚠ 常见遗漏**:
- ① 新增 SO-plugin 接口时只检查 `IsSoPluginLoaded()`，漏 `IsJsPluginRegistered()` 先检查
- ② 误以为 SO 和 JS 插件互斥，未考虑共存场景导致 SO 路径覆盖 JS 插件能力
- ③ `PluginAuthCallback` 是静态 trampoline（跨 DSO 调用），忘记加 `no_sanitize("cfi")`
- ④ 持锁（`mutex_`/`libMutex_`）期间调 IPC/`dlopen`，触发 Pitfall 6 死锁

  Historical: "Domain unlock incorrectly fell through to the SO plugin path when
  the JS plugin was registered — `GetUnlockDeviceConfig`/`AuthUserWithUnlockOptions`
  lacked the `IsJsPluginRegistered()` guard, causing the unsupported SO unlock path
  to be invoked in the JS plugin scenario"

---

## 5. Verification

### 5.1 Build commands (self-contained — copy-pasteable)

> Run from the **OpenHarmony root** (the repo that contains `build.sh`).
> Common products: `rk3568`, `hi3516`, `ohos-sdk`.

**Incremental ninja build (one target):**
```bash
cd {OpenHarmonyRoot}
ninja -C out/rk3568 obj/base/account/os_account/services/accountmgr/src/domain_account/accountmgr/inner_domain_account_manager.o
```

**Full subsystem build:**
```bash
./build.sh --product-name rk3568 --build-target os_account account_build_unittest account_build_moduletest
```

### 5.2 Test commands

> Run from `{OpenHarmonyRootFolder}/test/testfwk/developer_test`.

```bash
# All domain account tests
./start.sh run -p rk3568 -t UT MST -tp os_account

# Specific suites (most relevant to this module)
./start.sh run -p rk3568 -t UT MST -tp os_account -ts DomainAccountClientModuleTest
./start.sh run -p rk3568 -t UT MST -tp os_account -ts DomainAccountClientMockPluginSoModuleTest
./start.sh run -p rk3568 -t UT MST -tp os_account -ts DomainAccountManagerInnerServiceTest
./start.sh run -p rk3568 -t UT MST -tp os_account -ts DomainAccountPluginServiceTest
```

### 5.3 Cheapest verification by change type

| Change type | Cheapest check | Command |
|-------------|---------------|---------|
| Service logic (`inner_domain_account_manager.cpp`) | ninja single target | `ninja -C out/rk3568 obj/.../inner_domain_account_manager.o` |
| New SO-plugin interface | ninja + mock-plugin-so test | ninja → `DomainAccountClientMockPluginSoModuleTest` |
| IPC stub (`domain_account_manager_service.cpp`) | Build + service test | `os_account` build → `DomainAccountManagerInnerServiceTest` |
| Plugin ABI (`domain_plugin.h`) | Full build (flag on/off) | `os_account` build with `SUPPORT_DOMAIN_ACCOUNTS` both on and off |
| DFX (`domain_hisysevent_utils.cpp`) | ninja + grep event names | ninja → `grep -rn 'DOMAIN_OPT_' dfx/hisysevent_adapter/` |

### 5.4 Done definition

A change is **done** when:
1. Build succeeds: `./build.sh --product-name rk3568 --build-target os_account` (no errors).
2. Relevant test suite passes — report suite name + pass/fail counts.
3. No new compiler warnings in changed files (treat warnings as errors).
4. If `DomainAccountInfo` fields, `PluginMethodEnum` values, `DomainAccountStatus`/
   `DomainAccountEvent` values, or HiSysEvent operation-name strings changed:
   **escalate to user** (compatibility/ABI boundary, §4.1).
5. If permission checks, token/secret zeroing, or `no_sanitize("cfi")` annotations
   removed/changed: **escalate to user** (security/safety boundary, §4.1).
6. If unlock path (`HandleUnlockResult`) modified: trace that
   `SetOsAccountIsVerified(true)` is still reached (Pitfall 7).
7. If a new SO-plugin interface (`PluginXxx`) added: verify `IsJsPluginRegistered()`
   guard is at the entry point, and a "JS plugin registered + SO plugin loaded"
   coexistence test case is added (§4.14 Pitfall D1).

### 5.5 Fallback

See root [AGENTS.md](../../../../AGENTS.md) §5.7.

---

See root [AGENTS.md](../../../../AGENTS.md) for Pre-edit protocol (§2.4),
architecture invariants (§3.3), Pitfalls 1-10 (§3.4), and coding standards (§8).
