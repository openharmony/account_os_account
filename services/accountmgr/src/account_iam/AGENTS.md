# Account IAM Module Documentation

## Overview

The `account_iam` module is a core component of OpenHarmony OS Account subsystem, responsible for **Identity and Access Management (IAM)** functionality. It provides user authentication, credential management, and secure user session handling with multi-level encryption support (EL2/EL3/EL4).

**Location:** `base/account/os_account/services/accountmgr/src/account_iam/`

**Files:**
- `account_iam_service.cpp` - IPC service layer, permission validation, account ID normalization
- `inner_account_iam_manager.cpp` - Core IAM business logic, state machine, storage key operations
- `account_iam_callback.cpp` - Async operation callbacks, auth result processing

## Architecture

### Three-Layer Design

1. **Service Layer** (`AccountIAMService`): IPC interface, permission checks, system app validation
2. **Manager Layer** (`InnerAccountIAMManager`): Singleton pattern, state machine, UserIam/StorageManager integration
3. **Callback Layer**: Async wrappers handling IAM framework callbacks with account unlocking logic

### IAM State Machine

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

## Core Functionality

### 1. Session Management

| Function | Purpose | File |
|----------|---------|-------|
| `OpenSession()` | Generate 16-32 byte challenge for replay protection | [account_iam_service.cpp:99](account_iam_service.cpp#L99) |
| `CloseSession()` | Close session, cleanup state (user 0 stays IDLE) | [account_iam_service.cpp:116](account_iam_service.cpp#L116) |

### 2. Credential Management

| Function | Purpose | Key Points | File |
|----------|---------|-------------|-------|
| `AddCredential()` | Enroll PIN/fingerprint/face | Creates IAM fault flag, updates storage auth, activates EL2 | [inner_account_iam_manager.cpp:114](inner_account_iam_manager.cpp#L114) |
| `UpdateCredential()` | Change credential | Validates token, handles re-enrollment, supports recovery key | [inner_account_iam_manager.cpp:149](inner_account_iam_manager.cpp#L149) |
| `DelCred()` | Delete specific credential | Resets PIN credentialId to 0, updates storage | [inner_account_iam_manager.cpp:182](inner_account_iam_manager.cpp#L182) |
| `DelUser()` | Delete all credentials | Verifies token (60s validity), creates fault flag | [inner_account_iam_manager.cpp:204](inner_account_iam_manager.cpp#L204) |

### 3. User Authentication

| Function | Purpose | File |
|----------|---------|-------|
| `AuthUser()` | Start authentication, return contextId for cancel | [inner_account_iam_manager.cpp:297](inner_account_iam_manager.cpp#L297) |
| `AuthCallback::OnResult()` | Handle auth result: extract token/secret, unlock EL2/EL3/EL4, update verified status | [account_iam_callback.cpp:356](account_iam_callback.cpp#L356) |
| `CancelAuth()` | Cancel ongoing authentication | [inner_account_iam_manager.cpp:343](inner_account_iam_manager.cpp#L343) |

**Authentication Unlock Flow:**
1. Check IAM fault flag → restore key context if present
2. Check reactivation need → `ActivateUserKey()` for EL2 decryption
3. Check lock status → `UnlockUserScreen()` for EL3/EL4 decryption
4. Handle re-enrollment if `ATTR_RE_ENROLL_FLAG` is set
5. Update account verified/logged-in status

### 4. Storage Key Management

| Function | Purpose | Retry | File |
|----------|---------|--------|-------|
| `UpdateStorageUserAuth()` | Update auth keys in storage service | 20×100ms | [inner_account_iam_manager.cpp:593](inner_account_iam_manager.cpp#L593) |
| `UpdateStorageKeyContext()` | Update encryption context after credential changes | 20×100ms | [inner_account_iam_manager.cpp:559](inner_account_iam_manager.cpp#L559) |
| `ActivateUserKey()` | Activate user key for EL2 decryption | 20×100ms | [inner_account_iam_manager.cpp:723](inner_account_iam_manager.cpp#L723) |
| `UnlockUserScreen()` | Unlock EL3/EL4 encrypted files | 20×100ms | [inner_account_iam_manager.cpp:688](inner_account_iam_manager.cpp#L688) |
| `GetLockScreenStatus()` | Query lock state before unlock | 20×100ms | [inner_account_iam_manager.cpp:655](inner_account_iam_manager.cpp#L655) |
| `PrepareStartUser()` | Prepare user environment | 20×100ms | [inner_account_iam_manager.cpp:759](inner_account_iam_manager.cpp#L759) |

**Encryption Levels:**
- **EL1**: System level (no key)
- **EL2**: User key encryption → `ActivateUserKey()` after auth
- **EL3/EL4**: Enhanced encryption → `UnlockUserScreen()` after auth

### 5. Query & Property Operations

| Function | Purpose | File |
|----------|---------|-------|
| `GetCredentialInfo()` | Get enrolled credentials (includes domain if available) | [inner_account_iam_manager.cpp:228](inner_account_iam_manager.cpp#L228) |
| `GetEnrolledId()` | Get credential ID for auth type | [inner_account_iam_manager.cpp:467](inner_account_iam_manager.cpp#L467) |
| `GetAvailableStatus()` | Check if auth type/trust level available | [inner_account_iam_manager.cpp:349](inner_account_iam_manager.cpp#L349) |
| `GetProperty()` | Get auth properties (remain times, freeze time) | [inner_account_iam_manager.cpp:416](inner_account_iam_manager.cpp#L416) |
| `SetProperty()` | Set auth properties (freeze, update algorithm) | [inner_account_iam_manager.cpp:454](inner_account_iam_manager.cpp#L454) |
| `GetPropertyByCredentialId()` | Query credential without userId | [inner_account_iam_manager.cpp:441](inner_account_iam_manager.cpp#L441) |

### 6. Remote & Recovery

| Function | Purpose | File |
|----------|---------|-------|
| `PrepareRemoteAuth()` | Prepare cross-device auth (phone→tablet) | [inner_account_iam_manager.cpp:261](inner_account_iam_manager.cpp#L261) |
| `HandleFileKeyException()` | Restore key context when IAM fault flag exists | [inner_account_iam_manager.cpp:481](inner_account_iam_manager.cpp#L481) |
| `UpdateUserAuthWithRecoveryKey()` | Update auth using recovery key (dynamically loads librecovery_key_service_client) | [inner_account_iam_manager.cpp:630](inner_account_iam_manager.cpp#L630) |

## Key Data Types

### AuthType
| Type | Value | Description |
|-------|--------|-------------|
| PIN | 1 | 6-digit/4-digit/mixed password |
| FACE | 2 | Face recognition |
| FINGERPRINT | 4 | Fingerprint |
| RECOVERY_KEY | 8 | Recovery key for forgotten PIN |
| PRIVATE_PIN | 16 | Private PIN for secure ops |
| DOMAIN | 1024 | Domain account auth |

### AuthTrustLevel
| Level | Value | Use Case |
|-------|--------|-----------|
| ATL1 | 10000 | Low security, convenience |
| ATL2 | 20000 | Medium-low |
| ATL3 | 30000 | Default for most ops |
| ATL4 | 40000 | High security, sensitive ops |

### AuthIntent
| Intent | Value | Purpose |
|---------|--------|---------|
| DEFAULT | 0 | Normal authentication |
| UNLOCK | 1 | Device/screen unlock |
| SILENT_AUTH | 2 | Background auth (no UI) |
| QUESTION_AUTH | 3 | Security question |
| ABANDONED_PIN_AUTH | 4 | Abandoned PIN fallback |

## Callbacks

| Callback | Purpose | File |
|----------|---------|-------|
| `AuthCallback` | Auth results, unlocks EL2/EL3/EL4, handles re-enroll | [account_iam_callback.cpp:73](account_iam_callback.cpp#L73) |
| `AddCredCallback` | Add credential, updates storage auth | [account_iam_callback.cpp:426](account_iam_callback.cpp#L426) |
| `UpdateCredCallback` | Update credential, deletes old credential | [account_iam_callback.cpp:527](account_iam_callback.cpp#L527) |
| `DelCredCallback` | Delete credential results | [account_iam_callback.cpp:754](account_iam_callback.cpp#L754) |
| `CommitCredUpdateCallback` | Commit update after new credential active | [account_iam_callback.cpp:702](account_iam_callback.cpp#L702) |
| `CommitDelCredCallback` | Commit deletion cleanup | [account_iam_callback.cpp:672](account_iam_callback.cpp#L672) |
| `VerifyTokenCallbackWrapper` | Verify 60s token validity before delete | [account_iam_callback.cpp:615](account_iam_callback.cpp#L615) |
| `GetCredInfoCallbackWrapper` | Get credential info with domain support | [account_iam_callback.cpp:811](account_iam_callback.cpp#L811) |
| `GetPropCallbackWrapper` / `SetPropCallbackWrapper` | Property get/set wrappers | [account_iam_callback.cpp:872](account_iam_callback.cpp#L872) |
| `GetSecUserInfoCallbackWrapper` | Extract enrolled ID from secure user info | [account_iam_callback.cpp:906](account_iam_callback.cpp#L906) |
| `PrepareRemoteAuthCallbackWrapper` | Remote auth preparation result | [account_iam_callback.cpp:946](account_iam_callback.cpp#L946) |
| `GetDomainAuthStatusInfoCallback` | Domain auth status (frozen time, remaining attempts) | [account_iam_callback.cpp:965](account_iam_callback.cpp#L965) |

## Thread Safety

### Lock Hierarchy

```
operatingMutex_ → userLocks_[userId] → mutex_
(Map lock)       (Per-user lock)     (State lock)
```

### Rules (Prevent Deadlock)
1. Always acquire `operatingMutex_` first when accessing `userLocks_` map
2. Never hold `mutex_` while calling external services (UserIam, StorageManager)
3. Per-user locks are independent - different users operate concurrently

### Protected by Per-User Lock
- AddCredential, UpdateCredential, DelUser, ActivateUserKey

### Synchronous Wait Pattern
Callbacks use condition variables with timeout (5s for secure UID, 6s for re-enroll)

### Death Recipients
- `IDMCallbackDeathRecipient`: Client dies → `UserIdmClient::Cancel(userId)`
- `AuthCallbackDeathRecipient`: Client dies → `UserAuthClient::CancelAuthentication(contextId)`

## Permission Model

| Permission | Purpose | Operations |
|-----------|---------|--------------|
| `MANAGE_USER_IDM` | Manage credentials | OpenSession, CloseSession, AddCredential, UpdateCredential, DelCred, DelUser, Cancel |
| `USE_USER_IDM` | Query credentials | GetCredentialInfo, GetEnrolledId |
| `ACCESS_USER_AUTH_INTERNAL` | Internal auth operations | AuthUser, CancelAuth, GetAvailableStatus, GetProperty, SetProperty, PrepareRemoteAuth |

**System App Required:** All except `GetAccountState` and `AuthUser`

**Location:** [account_iam_service.cpp:351](account_iam_service.cpp#L351)

## Error Handling

### Retry Mechanism
- **Max Retries:** 20
- **Delay:** 100ms
- **Retryable:** `E_IPC_ERROR`, `E_IPC_SA_DIED`
- **Applied to:** All StorageManager operations

### Critical Errors
| Code | Description | Recovery |
|-------|-------------|------------|
| SUCCESS (0) | Operation succeeded | - |
| FAIL (1) | General failure | Retry |
| CANCELED (3) | User canceled | Cleanup |
| NOT_ENROLLED (10) | No credential | Enroll first |
| LOCKED (9) | Too many failed attempts | Wait for freeze time |
| BUSY (7) | Operation in progress | Wait/retry |

## Security

### Token/Secret Sanitization
All sensitive data (tokens, secrets) zeroed after use via `std::fill(vector.begin(), vector.end(), 0)`

**Why:** IPC marshalling may copy buffers; explicit zeroing ensures clearing even with compiler optimizations

### IAM Fault Flag
- **Path:** `/data/service/el2/account_user_{userId}/iam_fault`
- **Purpose:** Marks users needing key context restoration
- **Created:** Before credential operations
- **Deleted:** After successful restoration in `HandleFileKeyException()`

### Token Validity
- **Duration:** 60 seconds
- **Checked:** Before credential deletion via `VerifyTokenCallbackWrapper`

## Integration Points

### UserIam Framework
- **UserIdmClient**: Credential operations (Add/Update/Delete, GetInfo, Cancel)
- **UserAuthClient**: Authentication (Begin/Cancel, GetStatus, Get/SetProperty, PrepareRemote)
- **UserAccessCtrlClient**: Token verification (60s window)

### StorageManager
- **UpdateUserAuth**: Update auth keys
- **UpdateKeyContext**: Re-encrypt files after credential changes
- **ActiveUserKey**: Activate EL2 decryption
- **UnlockUserScreen**: Unlock EL3/EL4
- **GetLockScreenStatus**: Query lock state
- **PrepareStartUser**: Prepare user environment
- **GetUserNeedActiveStatus**: Check reactivation need

### Domain Account (Conditional: `SUPPORT_DOMAIN_ACCOUNTS`)
- **IsPluginAvailable**: Check plugin loaded
- **GetAuthStatusInfo**: Get domain auth status
- **AuthWithToken**: Domain offline auth

### OS Account Manager
- Account existence validation, deactivating/locking state checks
- Get/Set verified status, Get/Set logged-in status
- Get/Set credential ID, Get foreground user

## Conditional Compilation

| Macro | Purpose |
|-------|---------|
| `SUPPORT_DOMAIN_ACCOUNTS` | Domain account support |
| `HAS_STORAGE_PART` | Storage manager integration |
| `SUPPORT_LOCK_OS_ACCOUNT` | Account locking |
| `HAS_PIN_AUTH_PART` | PIN authentication |
| `HICOLLIE_ENABLE` | Re-enroll watchdog |

## Important Constants

```cpp
DELAY_FOR_EXCEPTION = 100      // Retry delay (ms)
MAX_RETRY_TIMES = 20            // Maximum retries
TIME_WAIT_TIME_OUT = 5           // Wait timeout (seconds)
TOKEN_ALLOWABLE_DURATION = 60000  // Token validity (ms)
REENROLL_TIME_OUT = 6            // Re-enroll timeout (seconds)
```

**Design Rationale:**
- 20 retries: ~2s StorageManager startup time
- 100ms delay: Responsiveness vs retry frequency
- 60s token: Security vs usability tradeoff

## Design Patterns

| Pattern | Purpose | Implementation |
|---------|---------|----------------|
| Singleton | Single IAM manager instance | `InnerAccountIAMManager::GetInstance()` |
| Callback Wrapper | Bridge UserIam callbacks with custom logic | `*CallbackWrapper` classes |
| State Machine | Track operation state for validity checks | `userStateMap_` with `GetState()/SetState()` |
| Death Recipient | Clean up on client process death | `IDMCallbackDeathRecipient`, `AuthCallbackDeathRecipient` |

## Key Concepts

### Credential Update Flow
1. Add new credential with old token
2. IAM validates and enrolls new credential
3. Update storage auth with new secret
4. Delete old credential
5. Update key context

### Authentication Flow
1. BeginAuth → return contextId
2. User authenticates via PIN/face/fingerprint
3. OnResult: extract token and secret
4. Unlock: ActivateUserKey (EL2) → UnlockUserScreen (EL3/EL4)
5. Update verified/logged-in status

### PIN Re-enrollment
Triggered when IAM sets `ATTR_RE_ENROLL_FLAG`:
1. AuthCallback detects flag
2. Calls `UpdateCredential()` with re-enrollment
3. 6s timeout with HiCollie watchdog
4. Updates PIN while maintaining same credentialId

## Related Files

- [IAM Info](../../../interfaces/innerkits/account_iam/native/include/account_iam_info.h) - Data types
- [IAM Common Defines](../../../../../useriam/user_auth_framework/interfaces/inner_api/iam_common_defines.h) - AuthType/ResultCode enums
- [Inner OS Account Manager](../osaccount/inner_os_account_manager.cpp) - Account operations
- [Domain Account Manager](../domain_account/inner_domain_account_manager.cpp) - Domain support

---

*Generated for OpenHarmony AI Knowledge Base*
