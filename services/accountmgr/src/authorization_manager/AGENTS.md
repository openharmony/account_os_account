# Authorization Manager Module - Agent Instruction Guide

> Scope: **directory** `services/accountmgr/src/authorization_manager/` — privilege
> authorization service logic (TEE token issuance, privilege cache, UI-extension
> connection orchestration).
> Parent: [../../../../AGENTS.md](../../../../AGENTS.md) (root, §1–8 framework applies here too).
> Target: any coding agent editing this module.
> Feature flag: `os_account_support_authorization` (default `false`).
> C++ define: `SUPPORT_AUTHORIZATION` (derived from the gni flag).
> Side-effect: enabling this flag forces `os_account_support_posix_adapter = true`.

---

## 1. Code Map

### 1.1 Responsibility

The Authorization Manager implements a **privilege-authorization subsystem**:
applications request authorization for privileged operations (e.g. raw network
packet capture), the service verifies permissions, optionally pops a system
dialog UI extension, calls the TEE (Trusted Execution Environment) to issue an
authorization token, and caches the granted privilege (with expiry) — persisting
the cache to a HUKS-digest-protected JSON file.

There is also an **admin authorization** path that authenticates an admin OS
account via UserIAM, then issues a TA token.

### 1.2 Directory Structure

Service logic: `services/accountmgr/src/authorization_manager/` (5 .cpp files).
Headers: `services/accountmgr/include/authorization_manager/`.
Framework: `frameworks/authorization/` (client proxy, callback services, IDL files).
Inner API: `interfaces/innerkits/authorization/native/include/` (client + data structures).
NAPI: `interfaces/kits/napi/authorization_public/`.

### 1.3 Key Entry Points

| Component | File | Notes |
|-----------|------|-------|
| IPC stub (service) | `authorization_manager_service.cpp` | `AuthorizationManagerService : AuthorizationStub`; permission check + param validation, delegates to inner mgr |
| Inner manager (singleton) | `inner_authorization_manager.cpp` | `InnerAuthorizationManager::GetInstance()`; TEE communication, cache updates, connection orchestration |
| Privilege cache (singleton) | `privilege_cache_manager.cpp` | `PrivilegeCacheManager::GetInstance()`; in-memory + persisted cache |
| UI-extension connection (singleton) | `service_extension_connect.cpp` | `SessionAbilityConnection::GetInstance()`; modal/system dialog connection lifecycle |
| Privilege utilities | `privilege_utils.cpp` | pidfd, /proc/stat process-start-time, ACL ioctl |
| Client facade | `frameworks/authorization/src/authorization_client.cpp` | `AuthorizationClient::GetInstance()`; IPC proxy holder |
| NAPI public | `interfaces/kits/napi/authorization_public/src/napi_authorization_public_manager.cpp` | `requestAuthorization` / `hasAuthorization` |

> **SA ID**: Authorization Manager is **not** a standalone SA. It is registered
> lazily inside `AccountMgrService::GetAuthorizationService()`
> (`account_mgr_service.cpp:770-781`), gated by `#ifdef SUPPORT_AUTHORIZATION`.
> Clients reach it via the accountmgr SA 200 and `AuthorizationClient`.

### 1.4 Where to Look (task → path)

| Task | Start here |
|------|------------|
| Add/change an IPC method | `IAuthorization.idl` → regenerate stub/proxy → `authorization_manager_service.cpp` (stub) → `inner_authorization_manager.cpp` (logic) |
| Change TEE token issuance | `inner_authorization_manager.cpp` `ApplyTaAuthorization()` / `CallTaAuthorization()` |
| Change privilege cache logic | `privilege_cache_manager.cpp` `AddCache()` / `AddCacheAndNotifyKernel()` / `CheckPrivilege()` |
| Change UI extension connection | `service_extension_connect.cpp` `SessionConnectExtension()` / `OnAbilityConnectDone()` |
| Change persistence (privilege_cache.json) | `privilege_cache_manager.cpp` `FromPersistFile()` / `ToPersistFile()` |
| Add a new privilege | `authorization_privilege.h` `PRIVILEGE_MAP` → `privileges_map.h` helpers |
| Change NAPI public API | `napi_authorization_public_manager.cpp` + matching `.d.ts` (public API — do-not-break) |
| Permission check | `authorization_manager_service.cpp` (4 permission constants at lines 36–40) |

---

## 2. Layering (dependency direction)

```
NAPI (interfaces/kits/napi/authorization_public)
  └─ NapiAuthorizationPublicManager → AuthorizationClient
Inner API (interfaces/innerkits/authorization/native/include)
  └─ authorization_client.h / authorization_common.h / authorization_callback.h
Framework (frameworks/authorization/src)
  └─ authorization_client.cpp [IPC proxy] → IAuthorization.idl
IDL (frameworks/authorization/*.idl) → generated stub/proxy (do NOT hand-edit)
Service (services/accountmgr/src/authorization_manager)
  └─ authorization_manager_service.cpp [AuthorizationStub impl]
       └─ inner_authorization_manager.cpp [singleton, TEE/cache logic]
            └─ privilege_cache_manager.cpp [singleton, persist + kernel notify]
            └─ service_extension_connect.cpp [SessionAbilityConnection singleton]
            └─ privilege_utils.cpp [pidfd/proc/stat/acl helpers]
            └─ OsAccountTeeAdapter / KernelAuthorizationAdapter (TEE + /dev kernel)
```

### 2.1 IDL files

Generated via `idl_gen_interface("authorization_interface")` in
`frameworks/authorization/BUILD.gn:56-68`. 5 IDL sources:

| IDL file | Interface |
|----------|-----------|
| `IAuthorization.idl` | `OHOS.AccountSA.IAuthorization` — all service methods |
| `IAuthorizationCallback.idl` | `IAuthorizationCallback` — `[oneway] OnResult`, `OnConnectAbility` |
| `IAdminAuthorizationCallback.idl` | `IAdminAuthorizationCallback` — `[oneway] OnResult(AdminAuthorizationResult)` |
| `IConnectAbilityCallback.idl` | `IConnectAbilityCallback` — `OnResult(resultCode, iamToken, accountId, iamResultCode)` |
| `IAuthRemoteObject.idl` | `IAuthRemoteObject` — empty marker interface |

**Do not hand-edit generated files** — change the `.idl` and regenerate (see root AGENTS.md §3.1).

---

## 3. Permission Model

All permission checks use `AccountPermissionManager` (no direct `AccessTokenKit`
calls in this module).

| Permission string | Constant | Check sites |
|------------------|----------|-------------|
| `ohos.permission.ACQUIRE_LOCAL_ACCOUNT_AUTHORIZATION` | `authorization_manager_service.cpp:36` | `AcquireAuthorization`, `AcquireAdminAuthorization` |
| `ohos.permission.REQUEST_LOCAL_ACCOUNT_AUTHORIZATION` | `authorization_manager_service.cpp:37` | `AcquireAuthorizationForPublic` (public API) |
| `ohos.permission.START_SYSTEM_DIALOG` | `authorization_manager_service.cpp:39` | `RegisterAuthAppRemoteObject`, `UnRegisterAuthAppRemoteObject` |
| `ohos.permission.ACCESS_USER_AUTH_INTERNAL` | `authorization_manager_service.cpp:40` | `RegisterAuthAppRemoteObject`, `AcquireAdminAuthorization` |

System-app checks (`AccountPermissionManager::CheckSystemApp`) gate most methods.

**Widget-bundle secondary gating**: `inner_authorization_manager.cpp:496` —
`VerifyPermission(bundleInfo.applicationInfo.accessTokenId, PERMISSION_START_SYSTEM_DIALOG)`
verifies the auth-app bundle holds the dialog permission (distinct from caller
permission check).

> **Pitfall 11 compliance**: Permission results gate *whether* to proceed/return
> errors, not *what* data value to return. `CheckAuthorization`/
> `HasAuthorizationForPublic` return the same `isAuthorized` bool regardless of
> caller identity.

---

## 4. Data Structures

### 4.1 Privilege cache

**`PrivilegeCacheManager::processPrivilegeMap_`** —
`std::map<int32_t pid, std::shared_ptr<ProcessPrivilegeRecord>>`, guarded by
`std::recursive_mutex mapMutex_`.

**`ProcessPrivilegeRecord`** (`privilege_cache_manager.h:68`):
- `pid_`, `uid_`, `processStartTime_` (detects PID recycling)
- `SmartPidFd pidFdPtr_` — `unique_ptr<int32_t, fdsan-closing deleter>`
- `remoteObject_`, `deathRecipient_` (auto-cleanup on process death)
- `privilegeRecordMap_` — `std::map<uint32_t privilegeIdx, std::shared_ptr<PrivilegeRecord>>`, guarded by `std::recursive_mutex mutex_`

**`PrivilegeRecord`** (`privilege_cache_manager.h:38`):
- `privilegeIdx_`, `expiredTime_` (boot-ms), `safeStartTime_`
- `authStatus_` — `PrivilegeAuthStatus` enum (`NOT_REQUIRED`/`UNCONFIRMED`/`AUTHORIZED`, `:29-33`)

### 4.2 Privilege map

Defined in `authorization_privilege.h:24` (`PRIVILEGE_MAP`):
- `PRIVILEGE_OPERATE_RAW_NET_PACKETS` → `"ohos.privilege.operate_raw_net_packets"`

Helpers in `privileges_map.h`: `TransferPrivilegeToCode`, `TransferCodeToPrivilege`,
`IsDefinedPrivilege`, `GetPrivilegeBriefDef`, `GetDefPrivilegesSize`.

### 4.3 IPC data structures

Defined in `interfaces/innerkits/authorization/native/include/authorization_common.h`:

| Structure | Line | Fields |
|-----------|------|--------|
| `CheckAuthorizationResult` | `:25` | `isAuthorized`, `challenge`, `iamToken` |
| `ConnectAbilityInfo` | `:40` | `privilege`, `description`, `bundleName`, `abilityName`, `callingUid/Pid`, `challenge`, `sessionId`, `timeout`, `isPublicApi` |
| `AuthorizationResultCode` | `:90` | enum: `SUCCESS=0`, `CANCELED=12300301`, `INTERACTION_NOT_ALLOWED=12300302`, `DENIED=12300303`, `SERVICE_BUSY=12300304`, `PRIVILEGE_NOT_SUPPORTED=12300305` |
| `AuthorizationResult` | `:110` | `privilege`, `resultCode`, `isReused`, `validityPeriod`, `token` |
| `AcquireAuthorizationOptions` | `:148` | `hasContext`, `challenge`, `isReuseNeeded`, `isInteractionAllowed`, `isContextValid`, `isPublicApi` |
| `AdminAuthorizationResult` | `:192` | `resultCode`, `token` |

### 4.4 NAPI public API

Exposed namespace `account.osAccount.authorization`:
- `requestAuthorization(privilege, uiAbilityContext)` → async `AcquireAuthorization`
- `hasAuthorization(privilege)` → async `HasAuthorization`
- `Privilege` enum (from `PRIVILEGE_MAP`)
- `AuthorizationResultCode` enum: `GRANTED(0)`, `CANCELED(12300301)`, `DENIED(12300303)`, `NOT_SUPPORTED(12300305)`

---

## 5. Thread Safety

| Lock | Type | Scope | Protects |
|------|------|-------|----------|
| `g_mutex` | `std::mutex` (file-scope) | `inner_authorization_manager.cpp:57` | `g_callbackMap`, `g_requestRemoteObjectMap`, `g_connectbackMap`, `g_pidToUidMap`, `g_pidFdMap`, `g_sessionIdToPidMap` |
| `PrivilegeCacheManager::mapMutex_` | `std::recursive_mutex` | `privilege_cache_manager.h:147` | `processPrivilegeMap_` |
| `ProcessPrivilegeRecord::mutex_` | `std::recursive_mutex` | `privilege_cache_manager.h:90` | `privilegeRecordMap_` |

**Modal vs non-modal connection**:
- Modal-system (single connection): `SessionAbilityConnection` singleton holds one connection.
- Non-modal (multi-connection): `g_connectbackMap` + `g_sessionIdToPidMap` keyed by sessionId.

---

## 6. Persistence

### 6.1 privilege_cache.json

Located at `/data/service/el1/public/account/privilege_cache.json`
(`privilege_cache_manager.cpp:48-49`).

**Write** (`ToPersistFile`, `:909`): serializes map → JSON, generates HUKS digest
(`:1049`, 6s XCollie timeout `:50`), writes with
`InputFileByPathAndContentWithTransaction`.

**Read** (`FromPersistFile`, `:813`): loads + validates — HUKS digest verification
(`:1049`), update-time monotonicity check (`:955`). Rejects tampered files.

**Schema fields** (per `PrivilegeRecord::ToJson`, `:37-40`):
`privilegeName`, `expiredTimeStamp`, `safeStartTime`, `authStatus`.

### 6.2 Cache lifecycle

- `CheckPrivilege` (`:495`): in-memory lookup → ACL fallback (`/dev/encaps` ioctl) → triggers async `StartCleanTask`.
- `AddCache` (`:555`): TA-backed privilege; creates/updates record, persists.
- `AddCacheAndNotifyKernel` (`:674`): kernel-backed; `UNCONFIRMED` → kernel query → `AUTHORIZED` (or rollback).
- `CleanExpiredPrivilegesAndSaveToFile` (`:1066`): periodic cleanup on detached thread `"StartCleanTask"`.

---

## 7. Security Considerations

Sensitive vectors (`token`, `challenge`, `iamToken`) are zeroed with `memset_s` /
`std::fill` at:

| Location | What is cleared |
|----------|----------------|
| `authorization_manager_service.cpp:427` | token (in `CheckAuthorizationToken`) |
| `inner_authorization_manager.cpp:580` | token (in `UpdateAuthInfo`) |
| `inner_authorization_manager.cpp:851` | outToken (in `VerifyToken`) |
| `inner_authorization_manager.cpp:965-967,1001,1009,1014,1020` | iamToken, taToken, challenge (in `AdminAuthCallback`) |
| `authorization_common.cpp:111,180,269` | challenge, token (in destructors of `ConnectAbilityInfo`, `AuthorizationResult`, `AdminAuthorizationResult`) |

IPC marshalling may copy buffers — explicit zeroing defeats compiler optimization
(see root AGENTS.md Pitfall 3).

---

## 8. Fallback (non-SUPPORT_AUTHORIZATION)

When the feature flag is off, `authorization_client.cpp` `#else` branches perform
`CheckSystemApp` + `VerifyPermission` but return `isAuthorized=true` /
`AUTHORIZATION_PRIVILEGE_NOT_SUPPORTED` rather than real authorization — keeps
the API contract without the privileged backend.

---

## 9. DFX

HiSysEvent operation tags (`privilege_hisysevent_utils.h:23-29`):
`persistPrivilegeCache`, `recoverPersistCache`, `acquireAuth`,
`releasePrivilegeAuth`, `verifyPrivilegeToken`, `acquireAuthForPublic`,
`verifyPrivilegeForPublic`.

---

## 10. Build & Test

```bash
# Build (from OpenHarmony root)
./build.sh --product-name rk3568 --build-target accountmgr

# Tests
cd {OpenHarmonyRootFolder}/test/testfwk/developer_test
./start.sh run -p rk3568 -t UT MST -tp os_account
```

> **Feature flag**: toggle `os_account_support_authorization` in `os_account.gni`
> to enable/disable this module. Full build with the flag both on and off is
> required when changing the flag (root AGENTS.md §5.2).
