# Distributed Account Module - AI Knowledge Base

## Overview

Distributed Account (OHOS Account) module provides account management for OpenHarmony distributed scenarios. Features: login/logout, state management, event subscription, data persistence, and account anonymization.

**Entry Points:**
- [account_mgr_service.cpp](../account_mgr_service.cpp):143 - AccountMgrService (SA 1401)
- [ohos_account_manager.cpp](../ohos_account_manager.cpp):219 - OhosAccountManager

## Architecture

```
Client App -> AccountMgrService -> OhosAccountManager -> OhosAccountDataDeal -> JSON Files
                                           |
                                           v
                                   DistributedAccountSubscribeManager -> Subscribers
```

**Data Location:** `/data/service/el1/public/account/{userId}/account.json`

## State Machine

```
UNBOUND --[LOGIN]--> LOGIN --[LOGOUT/LOGOFF/TOKEN_INVALID]--> UNBOUND
```

| State | Value | Description |
|--------|---------|-------------|
| UNBOUND | 0 | Not logged in |
| LOGIN | 1 | Logged in/bound |
| LOGOUT | 2 | Logged out |
| TOKEN_INVALID | 3 | Token expired |

**State Transition:** [ohos_account_manager.cpp:453-489](../ohos_account_manager.cpp#L453-L489)

## Core Components

### AccountMgrService ([account_mgr_service.cpp](../account_mgr_service.cpp))

| Method | Lines | Description |
|---------|-------|-------------|
| `SetOhosAccountInfo()` | 185-204 | Login with event string |
| `GetOhosAccountInfo()` | 297-310 | Query current account |
| `GetOsAccountDistributedInfo()` | 312-360 | Query by userId |
| `QueryDistributedVirtualDeviceId()` | 237-266 | Get DVID |
| `SubscribeDistributedAccountEvent()` | 417-431 | Subscribe events |
| `UnsubscribeDistributedAccountEvent()` | 433-447 | Unsubscribe events |

**Permissions:** MANAGE_DISTRIBUTED_ACCOUNTS, GET_DISTRIBUTED_ACCOUNTS, DISTRIBUTED_DATASYNC, MANAGE_USERS

### OhosAccountManager ([ohos_account_manager.cpp](../ohos_account_manager.cpp))

| Method | Lines | Description |
|---------|-------|-------------|
| `OnInitialize()` | 731-754 | Load account data |
| `LoginOhosAccount()` | 511-566 | Process login, save to JSON |
| `LogoutOhosAccount()` | 576-615 | Process logout |
| `HandleOhosAccountTokenInvalidEvent()` | 673-712 | Handle token invalid |
| `GetOhosAccountDistributedInfo()` | 372-395 | Get with anonymization |
| `QueryDistributedVirtualDeviceId()` | 283-303 | Generate DVID |

**Key Flows:**
1. **Login:** CheckCanBind -> Gen SHA256 UID -> UpdateState -> SaveJSON -> PublishEvent
2. **Query:** CheckSystemApp -> ReturnFull or Anonymized

### OhosAccountDataDeal ([ohos_account_data_deal.cpp](../ohos_account_data_deal.cpp))

| Method | Lines | Description |
|---------|-------|-------------|
| `Init()` | 156-197 | Load/create JSON files |
| `AccountInfoFromJson()` | 199-206 | Deserialize from JSON |
| `AccountInfoToJson()` | 208-215 | Serialize to JSON |
| `SaveAccountInfo()` | 217-259 | Persist to file |
| `BuildJsonFileFromScratch()` | 395-413 | Create default file |

**JSON Schema:**
```json
{
  "version": int,
  "bind_time": int,
  "user_id": int,
  "account_name": string,
  "raw_uid": string,
  "open_id": string,        // SHA256(raw_uid)
  "bind_status": int,        // State: 0-3
  "calling_uid": int,
  "account_nickname": string,
  "account_scalableData": string
}
```

**File Watcher (ENABLE_FILE_WATCHER):** Detects tampering via SHA256 digest comparison

### DistributedAccountSubscribeManager ([distributed_account_subscribe_manager.cpp](../distributed_account_subscribe_manager.cpp))

| Method | Lines | Description |
|---------|-------|-------------|
| `SubscribeDistributedAccountEvent()` | 41-68 | Add listener |
| `UnsubscribeDistributedAccountEvent()` | 70-95 | Remove listener |
| `Publish()` | 154-177 | Notify all subscribers (async with retry) |

**Events:** LOGIN, LOGOUT, LOGOFF, TOKEN_INVALID

## Key Algorithms

### DVID Generation ([ohos_account_manager.cpp:124-154](../ohos_account_manager.cpp#L124-L154))

```cpp
DVID = PBKDF2_HMAC-SHA256(raw_uid, bundleName, 1000, 32)
```
- Per-app unique ID for privacy
- Prevents cross-app tracking

### Account Anonymization ([ohos_account_manager.cpp:349-370](../ohos_account_manager.cpp#L349-L370))

**System Apps:** Full data (raw UID, full name)
**Normal Apps:**
- UID -> DVID (app-specific)
- Name -> FirstChar + "**********"
- Nickname -> FirstChar + "**********"
- Avatar -> "**********"
- ScalableData -> Empty

## Usage Scenarios

### 1. Login Flow
```
App -> SetOhosAccountInfo(name, uid, LOGIN)
     -> Permission check
     -> Gen OHOS_UID = SHA256(uid)
     -> State: UNBOUND -> LOGIN
     -> Save to JSON
     -> Publish to subscribers (DistributedKV, DSoftbus)
     -> Send CommonEvents
```

### 2. Query with Anonymization
```
App -> GetOhosAccountInfo()
     -> Check if system app
         -> YES: Return full data
         -> NO:  Return DVID + masked name
```

### 3. Token Invalid Handling
```
Server Token Expire -> Auth App callback
     -> SetOhosAccountInfo(TOKEN_INVALID)
     -> State: LOGIN -> TOKEN_INVALID
     -> Notify subscribers (stop sync)
     -> Apps re-authenticate user
```

### 4. DVID for Cross-Device Sync
```
DistributedKV -> QueryDistributedVirtualDeviceId()
     -> Gen DVID = PBKDF2(uid, bundleName)
     -> Use as key: "dist_db_{DVID}"
     -> Sync across devices via same DVID
```

## System Ability Interactions

| SA | Purpose | Code |
|----|-----------|-------|
| StorageManager | Wait ready, create dirs | [account_mgr_service.cpp:616](../account_mgr_service.cpp#L616) |
| BundleManager | Get bundle name for DVID | [account_mgr_service.cpp:624](../account_mgr_service.cpp#L624) |
| AbilityManager | Activate default account | [account_mgr_service.cpp:620](../account_mgr_service.cpp#L620) |
| DistributedKV | Data migration on ready | [account_mgr_service.cpp:629](../account_mgr_service.cpp#L629) |
| DSoftbus | Get account for discovery | Permission: DISTRIBUTED_DATASYNC |

## Error Codes

| Code | Description |
|------|-------------|
| `ERR_OK` | Success |
| `ERR_ACCOUNT_COMMON_PERMISSION_DENIED` | Permission check failed |
| `ERR_ACCOUNT_COMMON_INVALID_PARAMETER` | Invalid parameters |
| `ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR` | Account not found |
| `ERR_ACCOUNT_ZIDL_ACCOUNT_SERVICE_ERROR` | Internal error |
| `ERR_ACCOUNT_DATADEAL_JSON_FILE_CORRUPTION` | JSON corrupted (auto-retry) |
| `ERR_OHOSACCOUNT_KIT_NO_SPECIFIED_CALLBACK_HAS_BEEN_REGISTERED` | Subscription not found |

## Dependencies

**Internal:** AccountStateMachine, AccountFileOperator, IInnerOsAccountManager
**External:** OpenSSL (SHA256, PBKDF2), AccessTokenKit, IPCSkeleton, HiSysEvent, CommonEvent

## Configuration

| Flag | Purpose |
|--------|-----------|
| `HAS_CES_PART` | Enable common events |
| `ENABLE_FILE_WATCHER` | Enable tampering detection |
| `HAS_HUKS_PART` | Enable HUKS digest |
| `ACCOUNT_TEST` | Use test directory |

## Thread Safety

- `OhosAccountManager::mgrMutex_` - State changes
- `OhosAccountDataDeal::mutex_` / `accountInfoFileLock_` - File I/O
- `DistributedAccountSubscribeManager::subscribeRecordMutex_` - Subscription list

## Troubleshooting

| Issue | Check |
|-------|--------|
| Login fails "already bound" | Check bind_status in JSON, verify not stuck in LOGIN state |
| JSON corrupted | Auto-retry enabled (MAX_RETRY_TIMES=2), check file integrity |
| No events received | Verify system app, death recipient registered, correct event type |
| DVID empty | Check OpenSSL loaded, UID length < 512 |

**Debug Commands:**
```bash
cat /data/service/el1/public/account/{userId}/account.json | jq
hidumper -s accountmgr -a
grep "ohos_account" /var/log/hisysevent/*.log
```

## FAQ

**Q1: LOGOUT vs LOGOFF?** A: LOGOUT = unbind (can re-login), LOGOFF = remove from device

**Q2: Why DVID differs per app?** A: PBKDF2 uses bundleName as salt for privacy

**Q3: Same OHOS account on multiple users?** A: Blocked by [CheckOhosAccountCanBind](../ohos_account_manager.cpp#L789)

**Q4: How tampering detected?** A: inotify + SHA256 digest comparison

**Q5: Crash recovery?** A: Reload JSON, restore state, re-register subscriptions

**Q6: Anonymized data?** A: Non-system apps get DVID + masked names

**Q7: Account sync across devices?** A: Not by this service. DistributedKV uses DVID as sync key

**Q8: Query other users?** A: Only with MANAGE_USERS or INTERACT_ACROSS_LOCAL_ACCOUNTS permission

**Q9: Max retry for events?** A: Constants::MAX_RETRY_TIMES (typically 3)

**Q10: Version migration?** A: Check `version` field in JSON, upgrade format accordingly

## References

- **SA ID:** 1401
- **Data Path:** `/data/service/el1/public/account/{userId}/`
- **Events:** OHOS_ACCOUNT_EVENT_LOGIN/LOGOUT/LOGOFF/TOKEN_INVALID
