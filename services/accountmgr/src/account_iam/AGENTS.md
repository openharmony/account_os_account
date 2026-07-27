# Account IAM Module - Agent Instruction Guide

> Scope: **directory** `services/accountmgr/src/account_iam/` — Identity and Access Management (IAM) service logic.
> Parent: [../../../../AGENTS.md](../../../../AGENTS.md) (root, §1–8 framework applies here too).
> Target: any coding agent editing this module.
> IAM fault flag path: `/data/service/el1/public/account/{userId}/iam_fault`

---

## 1. Code Map

### 1.1 Responsibility

The `account_iam` module implements user authentication, credential management,
and secure user session handling with multi-level encryption support (EL2/EL3/EL4).
It integrates with the User IAM framework (`user_auth_framework`) and Storage
Manager for key management.

### 1.2 Three-Layer Design

1. **Service Layer** (`AccountIAMService`): IPC interface, permission checks, system-app validation.
2. **Manager Layer** (`InnerAccountIAMManager`): Singleton, state machine, UserIam/StorageManager integration.
3. **Callback Layer**: Async wrappers handling IAM framework callbacks with account-unlocking logic.

### 1.3 Key Files

| File | Responsibility | Thread Safety |
|------|----------------|---------------|
| [account_iam_service.cpp](account_iam_service.cpp) | IPC service layer; permission validation; account ID normalization | Stateless IPC stub (binder threads) |
| [inner_account_iam_manager.cpp](inner_account_iam_manager.cpp) | Core IAM business logic; state machine; storage key operations | `operatingMutex_` (map lock), `userLocks_[userId]` (per-user lock), `mutex_` (state lock) |
| [account_iam_callback.cpp](account_iam_callback.cpp) | Async operation callbacks; auth result processing; unlock logic | Relies on manager locks; cond-var wait pattern (5s secure UID / 6s re-enroll) |

### 1.4 Where to Look (task → path)

| Task | Start here |
|------|------------|
| Add/change an IAM IPC method | `account_iam_service.cpp` → `inner_account_iam_manager.cpp` |
| Credential management (add/update/delete) | `inner_account_iam_manager.cpp` §2.2 |
| Authentication flow | `AuthUser()` + `AuthCallback::OnResult()` |
| EL2/EL3/EL4 unlock logic | `inner_account_iam_manager.cpp` §3.4 (Storage Key Management) |
| IAM state machine | `inner_account_iam_manager.cpp` — `userStateMap_` with `GetState()/SetState()` |
| Remote auth | `PrepareRemoteAuth()` |
| Callback wrappers | `account_iam_callback.cpp` §6 (Callbacks table) |
| Token validity | `VerifyTokenCallbackWrapper()` |
| Data types (AuthType, AuthTrustLevel, etc.) | `interfaces/innerkits/account_iam/native/include/account_iam_info.h` |

---

## 2. Knowledge Routing

### 2.1 Task-based routing

| If the task involves… | Read this first |
|----------------------|-----------------|
| Credential add/update/delete | §3.2 Credential Management; §5.1 Credential Update Flow |
| Authentication (PIN/face/fingerprint) | §3.3 User Authentication; §5.2 Authentication Flow |
| EL2/EL3/EL4 encryption unlock | §3.4 Storage Key Management; §5.2 Authentication Flow (step 4) |
| IAM state machine | §3.1 IAM State Machine |
| Token/secret sanitization | §4.4 Security (Token/Secret Sanitization) |
| IAM fault flag / crash recovery | §4.5 IAM Fault Flag; `HandleFileKeyException()` |
| Locking / deadlock prevention | §4.2 Lock Hierarchy |
| Permission model | §4.3 Permission Model |
| Conditional compilation / feature flags | §4.7 Conditional Compilation |
| PIN re-enrollment | §5.3 PIN Re-enrollment |
| Remote auth | §3.5 Remote & Recovery |
| Error codes / retry | §4.6 Error Handling |
| Domain account integration | §3.5 (SUPPORT_DOMAIN_ACCOUNTS) |

### 2.2 Vocabulary routing

| Term | Meaning | Read |
|------|---------|------|
| EL1/EL2/EL3/EL4 | Encryption levels: EL1=system (no key), EL2=user key, EL3/EL4=screen-lock key | §3.4 Storage Key Management |
| `IAMState` | Enum tracking operation state: IDLE, AFTER_OPEN_SESSION, DURING_AUTHENTICATE, etc. | §3.1 IAM State Machine |
| `AuthType` | PIN/face/fingerprint/recovery-key/private-pin/domain auth enum | §8 Key Data Types |
| `AuthTrustLevel` | ATL1–ATL4 security tiers (ATL3 default) | §8 Key Data Types |
| `AuthIntent` | DEFAULT/UNLOCK/SILENT_AUTH/QUESTION_AUTH/ABANDONED_PIN_AUTH | §8 Key Data Types |
| IAM fault flag | File at `/data/service/el1/public/account/{userId}/iam_fault` marking users needing key restoration | §4.5 IAM Fault Flag |
| Token validity | 60-second window for credential deletion operations | §4.5 Token Validity |
| `operatingMutex_` → `userLocks_[userId]` → `mutex_` | Lock hierarchy to prevent deadlock | §4.2 Lock Hierarchy |
| `ATTR_RE_ENROLL_FLAG` | IAM-set flag triggering PIN re-enrollment | §5.3 PIN Re-enrollment |

### 2.3 Pre-edit protocol

See root [AGENTS.md](../../../../AGENTS.md) §2.3. Before writing code, state:
1. **Task category** (credential / auth / storage key / state machine / callback / permission / other).
2. **Documents read** (per §2.1–2.2 above).
3. **Constraints found** (§4 Do-not / Ask-before rules that apply).

---

## 3. Core Functionality

### 3.1 IAM State Machine

```cpp
enum IAMState {
    IDLE = 0,                // Initial state
    AFTER_OPEN_SESSION,         // Session opened
    DURING_AUTHENTICATE,       // Authentication in progress
    DURING_ADD_CRED, DURING_UPDATE_CRED, DURING_DEL_CRED,  // Operations in progress
    AFTER_ADD_CRED, AFTER_UPDATE_CRED, AFTER_DEL_CRED,     // Success states
    ROLL_BACK_DEL_CRED,       // Rolling back
    DURING_DEL_USER,           // User deletion
};
```

### 3.2 Credential Management

| Function | Purpose | Key Points |
|----------|---------|-------------|
| `AddCredential()` | Enroll PIN/fingerprint/face | Creates IAM fault flag, updates storage auth, activates EL2 |
| `UpdateCredential()` | Change credential | Validates token, handles re-enrollment, supports recovery key |
| `DelCred()` | Delete specific credential | Resets PIN credentialId to 0, updates storage |
| `DelUser()` | Delete all credentials | Verifies token (60s validity), creates fault flag |

### 3.3 User Authentication

| Function | Purpose |
|----------|---------|
| `AuthUser()` | Start authentication, return contextId for cancel |
| `AuthCallback::OnResult()` | Handle auth result: extract token/secret, unlock EL2/EL3/EL4, update verified status |
| `CancelAuth()` | Cancel ongoing authentication |

**Authentication unlock flow:**
1. Check IAM fault flag → restore key context if present
2. Check reactivation need → `ActivateUserKey()` for EL2 decryption
3. Check lock status → `UnlockUserScreen()` for EL3/EL4 decryption
4. Handle re-enrollment if `ATTR_RE_ENROLL_FLAG` is set
5. Update account verified/logged-in status

### 3.4 Storage Key Management

| Function | Purpose | Retry |
|----------|---------|--------|
| `UpdateStorageUserAuth()` | Update auth keys in storage service | 20×100ms |
| `UpdateStorageKeyContext()` | Update encryption context after credential changes | 20×100ms |
| `ActivateUserKey()` | Activate user key for EL2 decryption | 20×100ms |
| `UnlockUserScreen()` | Unlock EL3/EL4 encrypted files | 20×100ms |
| `GetLockScreenStatus()` | Query lock state before unlock | 20×100ms |
| `PrepareStartUser()` | Prepare user environment | 20×100ms |

**Encryption levels:**
- **EL1**: System level (no key)
- **EL2**: User key encryption → `ActivateUserKey()` after auth
- **EL3/EL4**: Enhanced encryption → `UnlockUserScreen()` after auth

### Code details that must be verified
- The `UpdateStorageUserAuth` + `UpdateStorageKeyContext` calls inside `HandleFileKeyException` (both contain a 20×100ms IPC retry loop).
- The `needActivateKey` branch condition of `UnlockUserStorage` (`isVerified && !CheckNeedReactivateUserKey → false → skips isUpdateVerifiedStatus=true`).
- The 4 early-return paths of `OnResult` (auth failed / private PIN / remote auth / account being deactivated, before `SetOsAccountIsVerified`).
- `preVerified` secondary gating (the `if(!preVerified && isVerified)` transition detection inside `SetOsAccountIsVerified`).
- `try_lock` downgrade point (`HandleFileKeyException`'s `try_lock` → `ERR_ACCOUNT_COMMON_BUSY`).

### 3.5 Query & Property Operations

| Function | Purpose |
|----------|---------|
| `GetCredentialInfo()` | Get enrolled credentials (includes domain if available) |
| `GetEnrolledId()` | Get credential ID for auth type |
| `GetAvailableStatus()` | Check if auth type/trust level available |
| `GetProperty()` | Get auth properties (remain times, freeze time) |
| `SetProperty()` | Set auth properties (freeze, update algorithm) |
| `GetPropertyByCredentialId()` | Query credential without userId |

### 3.6 Remote & Recovery

| Function | Purpose |
|----------|---------|
| `PrepareRemoteAuth()` | Prepare cross-device auth (phone→tablet) |
| `HandleFileKeyException()` | Restore key context when IAM fault flag exists |
| `UpdateUserAuthWithRecoveryKey()` | Update auth using recovery key (dynamically loads `librecovery_key_service_client`) |

---

## 4. Constraints & Boundaries

### 4.1 Do not (without explicit user escalation)

- **Do not change `AuthType` enum values** (PIN=1, FACE=2, FINGERPRINT=4,
  RECOVERY_KEY=8, PRIVATE_PIN=16, DOMAIN=1024) — persisted and used across IPC;
  changing values breaks compatibility.
- **Do not change `AuthTrustLevel` values** (ATL1=10000, ATL2=20000, ATL3=30000,
  ATL4=40000) — applications and the IAM framework depend on these.
- **Do not change token validity duration** (60000ms / 60s) — security/usability
  boundary; credential deletion depends on it.
- **Do not change retry parameters** (`MAX_RETRY_TIMES=20`, `DELAY_FOR_EXCEPTION=100ms`)
  without escalation — tuned for StorageManager startup timing (~2s).
- **Do not change the IAM fault flag path**
  (`/data/service/el1/public/account/{userId}/iam_fault`) — crash-recovery
  mechanism depends on this exact path.
- **Do not remove token/secret zeroing** (`std::fill(vector.begin(), vector.end(), 0)`)
  — security boundary; IPC marshalling may copy buffers.
- **Do not remove or weaken permission checks** in `AccountIAMService`
  (§4.3 Permission Model).
- **Do not hold `mutex_` while calling external services** (UserIam, StorageManager)
  — risk of deadlock (§4.2 Lock Hierarchy).
- **Do not change `IAMState` enum values** — state machine persistence and
  validity checks depend on them.
- **Verify-state on every unlock path (incl. no-password):** See root Pitfall 7.
  Trace that `SetOsAccountIsVerified(true)` is reached at `AuthCallback::OnResult()`.
- **Per-user lock during slow storage ops; use `try_lock` in recovery:** See root
  Pitfall 8. `HandleFileKeyException()` must not hold the per-user lock during
  storage IPC (`UpdateStorageUserAuth` + `UpdateStorageKeyContext`).

### 4.2 Ask before

- Changing the lock hierarchy (`operatingMutex_` → `userLocks_[userId]` → `mutex_`).
- Changing conditional compilation macros (`SUPPORT_DOMAIN_ACCOUNTS`,
  `HAS_STORAGE_PART`, `SUPPORT_LOCK_OS_ACCOUNT`, `HAS_PIN_AUTH_PART`,
  `HICOLLIE_ENABLE`).
- Changing timeout values (`TIME_WAIT_TIME_OUT=5s`, `REENROLL_TIME_OUT=6s`).
- Adding new `AuthIntent` values.

### 4.3 Permission Model

| Permission | Purpose | Operations |
|-----------|---------|--------------|
| `MANAGE_USER_IDM` | Manage credentials | OpenSession, CloseSession, AddCredential, UpdateCredential, DelCred, DelUser, Cancel |
| `USE_USER_IDM` | Query credentials | GetCredentialInfo, GetEnrolledId |
| `ACCESS_USER_AUTH_INTERNAL` | Internal auth operations | AuthUser, CancelAuth, GetAvailableStatus, GetProperty, SetProperty, PrepareRemoteAuth |

**System app required**: All operations except `GetAccountState` and `AuthUser`.
**Location**: `AccountIAMService` permission-check entry (see `account_iam_service.cpp`).

### 4.4 Lock Hierarchy

```
operatingMutex_ → userLocks_[userId] → mutex_
(Map lock)       (Per-user lock)     (State lock)
```

**Rules (prevent deadlock):**
1. Always acquire `operatingMutex_` first when accessing `userLocks_` map.
2. Never hold `mutex_` while calling external services (UserIam, StorageManager).
3. Per-user locks are independent — different users operate concurrently.

**Protected by per-user lock**: AddCredential, UpdateCredential, DelUser, ActivateUserKey.

**Synchronous wait pattern**: Callbacks use condition variables with timeout
(5s for secure UID, 6s for re-enroll).

**Death recipients**:
- `IDMCallbackDeathRecipient`: Client dies → `UserIdmClient::Cancel(userId)`
- `AuthCallbackDeathRecipient`: Client dies → `UserAuthClient::CancelAuthentication(contextId)`

### 4.5 Security

**Token/secret sanitization**: All sensitive data (tokens, secrets) zeroed after
use via `std::fill(vector.begin(), vector.end(), 0)`. IPC marshalling may copy
buffers — explicit zeroing ensures clearing even with compiler optimizations.

**IAM fault flag**:
- Path: `/data/service/el1/public/account/{userId}/iam_fault`
- Purpose: Marks users needing key context restoration.
- Created: Before credential operations.
- Deleted: After successful restoration in `HandleFileKeyException()`.

**Token validity**: 60 seconds. Checked before credential deletion via
`VerifyTokenCallbackWrapper`.

### 4.6 Error Handling

**Retry mechanism**:
- Max retries: 20 · Delay: 100ms · Retryable: `E_IPC_ERROR`, `E_IPC_SA_DIED`
- Applied to: All StorageManager operations

**Critical errors:**

| Code | Description | Recovery |
|-------|-------------|------------|
| SUCCESS (0) | Operation succeeded | — |
| FAIL (1) | General failure | Retry |
| CANCELED (3) | User canceled | Cleanup |
| NOT_ENROLLED (10) | No credential | Enroll first |
| LOCKED (9) | Too many failed attempts | Wait for freeze time |
| BUSY (7) | Operation in progress | Wait/retry |

### 4.7 Conditional Compilation & Constants

**Conditional macros** (see `os_account.gni`): `SUPPORT_DOMAIN_ACCOUNTS` (domain),
`HAS_STORAGE_PART` (storage manager), `SUPPORT_LOCK_OS_ACCOUNT` (account lock),
`HAS_PIN_AUTH_PART` (PIN auth), `HICOLLIE_ENABLE` (re-enroll watchdog).

**Tuned constants** (do not change without escalation, §4.1 / §4.2):
`DELAY_FOR_EXCEPTION=100ms`, `MAX_RETRY_TIMES=20` (~2s StorageManager startup),
`TIME_WAIT_TIME_OUT=5s`, `TOKEN_ALLOWABLE_DURATION=60000ms` (60s, security vs
usability), `REENROLL_TIME_OUT=6s`. Retry parameters apply to all StorageManager
operations (retryable codes: `E_IPC_ERROR`, `E_IPC_SA_DIED`).

---

## 5. Key Concepts

### 5.1 Credential Update Flow
1. Add new credential with old token.
2. IAM validates and enrolls new credential.
3. Update storage auth with new secret.
4. Delete old credential.
5. Update key context.

### 5.2 Authentication Flow
1. BeginAuth → return contextId.
2. User authenticates via PIN/face/fingerprint.
3. OnResult: extract token and secret.
4. Unlock: ActivateUserKey (EL2) → UnlockUserScreen (EL3/EL4).
5. Update verified/logged-in status.

### 5.3 PIN Re-enrollment
Triggered when IAM sets `ATTR_RE_ENROLL_FLAG`:
1. AuthCallback detects flag.
2. Calls `UpdateCredential()` with re-enrollment.
3. 6s timeout with HiCollie watchdog.
4. Updates PIN while maintaining same credentialId.

---

## 6. Callbacks

All callbacks live in `account_iam_callback.cpp`; look up by class name via codegraph.

| Callback | Purpose |
|----------|---------|
| `AuthCallback` | Auth results, unlocks EL2/EL3/EL4, handles re-enroll |
| `AddCredCallback` | Add credential, updates storage auth |
| `UpdateCredCallback` | Update credential, deletes old credential |
| `DelCredCallback` | Delete credential results |
| `CommitCredUpdateCallback` | Commit update after new credential active |
| `CommitDelCredCallback` | Commit deletion cleanup |
| `VerifyTokenCallbackWrapper` | Verify 60s token validity before delete |
| `GetCredInfoCallbackWrapper` | Get credential info with domain support |
| `GetPropCallbackWrapper` / `SetPropCallbackWrapper` | Property get/set wrappers |
| `GetSecUserInfoCallbackWrapper` | Extract enrolled ID from secure user info |
| `PrepareRemoteAuthCallbackWrapper` | Remote auth preparation result |
| `GetDomainAuthStatusInfoCallback` | Domain auth status (frozen time, remaining attempts) |

---

## 7. Integration Points

### 7.1 UserIam Framework
- **UserIdmClient**: Credential operations (Add/Update/Delete, GetInfo, Cancel)
- **UserAuthClient**: Authentication (Begin/Cancel, GetStatus, Get/SetProperty, PrepareRemote)
- **UserAccessCtrlClient**: Token verification (60s window)

### 7.2 StorageManager
- `UpdateUserAuth`: Update auth keys
- `UpdateKeyContext`: Re-encrypt files after credential changes
- `ActiveUserKey`: Activate EL2 decryption
- `UnlockUserScreen`: Unlock EL3/EL4
- `GetLockScreenStatus`: Query lock state
- `PrepareStartUser`: Prepare user environment
- `GetUserNeedActiveStatus`: Check reactivation need

### 7.3 Domain Account (Conditional: `SUPPORT_DOMAIN_ACCOUNTS`)
- `IsPluginAvailable`: Check plugin loaded
- `GetAuthStatusInfo`: Get domain auth status
- `AuthWithToken`: Domain offline auth

### 7.4 OS Account Manager
- Account existence validation, deactivating/locking state checks
- Get/Set verified status, Get/Set logged-in status
- Get/Set credential ID, Get foreground user

---

## 8. Key Data Types

Enum definitions (`AuthType`, `AuthTrustLevel`, `AuthIntent`) and `ResultCode`
values live in `account_iam_info.h` / the User IAM framework
(`iam_common_defines.h`). **Values are persisted across IPC and on disk — do
not change them (§4.1).** Look up current values there or via codegraph rather
than relying on this doc.

---

## 9. Verification

### 9.1 Minimum checks

See root [AGENTS.md](../../../../AGENTS.md) §5.1 for build commands. For this module:

```bash
# Build
./build.sh --product-name rk3568 --build-target os_account account_build_unittest account_build_moduletest

# Run IAM test suites
cd {OpenHarmonyRootFolder}/test/testfwk/developer_test
./start.sh run -p rk3568 -t UT MST -tp os_account -ts AccountIAMModuleTest
```

### 9.2 Task-specific validation

| If you changed… | Also check |
|----------------|------------|
| `account_iam_service.cpp` (IPC/permission) | Verify permission checks present; verify system-app validation; run service tests |
| `inner_account_iam_manager.cpp` (credential/auth) | Run credential tests; verify state machine transitions; verify EL2/EL3/EL4 unlock |
| `account_iam_callback.cpp` (callbacks) | Verify token/secret zeroing intact; verify death recipients; test async wait timeouts |
| `AuthType` / `AuthTrustLevel` / `AuthIntent` enums | Verify no existing value changed (§4.1) |
| Retry/timeout constants | Verify values unchanged (§4.7); test StorageManager retry path |
| Lock hierarchy | Trace all lock acquisitions; verify no `mutex_` held during external calls |
| Conditional compilation macros | Build with each macro on and off |

### 9.3 Done definition

A change is **done** when:
1. Build succeeds: `./build.sh --product-name rk3568 --build-target os_account` (no errors).
2. Relevant test suite passes — report suite name + pass/fail counts.
3. No new compiler warnings in changed files.
4. If `AuthType`, `AuthTrustLevel`, `AuthIntent` enum values, token validity,
   retry constants, or IAM fault flag path changed: **escalate to user**
   (compatibility/security boundary, §4.1).
5. If token/secret zeroing or permission checks removed/changed: **escalate to
   user** (security boundary, §4.1).

### 9.4 Fallback

If build/tests cannot run locally, state "I could not run the build/tests because
\<reason\>" and ask the user to run §9.1 commands. Do not claim the change is verified.
