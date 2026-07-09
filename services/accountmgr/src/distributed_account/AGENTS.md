# Distributed Account Module - Agent Instruction Guide

> Scope: **directory** `services/accountmgr/src/distributed_account/` — Distributed Account (OHOS Account) service logic.
> Parent: [../../../../AGENTS.md](../../../../AGENTS.md) (root, §1–8 framework applies here too).
> Target: any coding agent editing this module.
> Data location: `/data/service/el1/public/account/{userId}/account.json`
> SA ID: 1401

---

## 1. Code Map

### 1.1 Responsibility

Distributed Account (OHOS Account) provides account management for OpenHarmony
distributed scenarios: login/logout, state management, event subscription, data
persistence, and account anonymization for privacy.

### 1.2 Architecture

```
Client App -> AccountMgrService -> OhosAccountManager -> OhosAccountDataDeal -> JSON Files
                                           |
                                           v
                                   DistributedAccountSubscribeManager -> Subscribers
```

### 1.3 Entry Points

| Component | File | Lines |
|-----------|------|-------|
| AccountMgrService (SA 1401) | [../account_mgr_service.cpp](../account_mgr_service.cpp) | :143 |
| OhosAccountManager | [../ohos_account_manager.cpp](../ohos_account_manager.cpp) | :219 |

### 1.4 Where to Look (task → path)

| Task | Start here |
|------|------------|
| Login/logout/token-invalid logic | `../ohos_account_manager.cpp` → `LoginOhosAccount` / `LogoutOhosAccount` / `HandleOhosAccountTokenInvalidEvent` |
| DVID generation | `../ohos_account_manager.cpp:124-154` |
| Account anonymization | `../ohos_account_manager.cpp:349-370` |
| JSON persistence (read/write/schema) | `../ohos_account_data_deal.cpp` |
| Event subscription / publishing | `distributed_account_subscribe_manager.cpp` |
| State machine transitions | `../ohos_account_manager.cpp:453-489` |
| SA interactions (StorageManager, BundleManager, etc.) | `../account_mgr_service.cpp:616-629` |

---

## 2. Knowledge Routing

### 2.1 Task-based routing

| If the task involves… | Read this first |
|----------------------|-----------------|
| Login / logout / token invalid flow | §3.2 Usage Scenarios (Login, Token Invalid); §4.5 State Machine |
| DVID / cross-device ID | §4.1 DVID Generation |
| Anonymization / privacy | §4.2 Account Anonymization |
| JSON schema / persistence | §4.3 JSON Schema; §4.4 OhosAccountDataDeal |
| Event subscription | §1.4 DistributedAccountSubscribeManager row |
| File watcher / tamper detection | §4.4 (ENABLE_FILE_WATCHER) |
| Thread safety / locking | §4.6 Thread Safety |
| Permission checks | Root AGENTS.md §3.1 (Do-not: permission checks); §4.7 Permissions |
| State machine | §4.5 State Machine |
| Debugging / troubleshooting | §6 Troubleshooting |

### 2.2 Vocabulary routing

| Term | Meaning | Read |
|------|---------|------|
| DVID | Distributed Virtual Device ID = `PBKDF2_HMAC-SHA256(raw_uid, bundleName, 1000, 32)`; per-app unique ID for privacy | §4.1 DVID Generation |
| OHOS_UID | `SHA256(uid)` — the device-level account identifier | §5.1 Login Flow |
| `bind_status` | Account state field in JSON: 0=UNBOUND, 1=LOGIN, 2=LOGOUT, 3=TOKEN_INVALID | §4.5 State Machine |
| Anonymization | Non-system apps get DVID + masked names instead of raw data | §4.2 Account Anonymization |
| File watcher | inotify + SHA256 digest comparison to detect JSON tampering (`ENABLE_FILE_WATCHER` flag) | §4.4 OhosAccountDataDeal |
| LOGOUT vs LOGOFF | LOGOUT = unbind (can re-login); LOGOFF = remove from device | §7 FAQ Q1 |

### 2.3 Pre-edit protocol

See root [AGENTS.md](../../../../AGENTS.md) §2.4. Before writing code, state:
1. **Task category** (login/state machine / DVID / anonymization / persistence / events / other).
2. **Documents read** (per §2.1–2.2 above).
3. **Constraints found** (§4.8 Do-not / Ask-before rules that apply).

---

## 3. Core Components

### 3.1 AccountMgrService — distributed account methods

| Method | Lines | Description |
|---------|-------|-------------|
| `SetOhosAccountInfo()` | 185-204 | Login with event string |
| `GetOhosAccountInfo()` | 297-310 | Query current account |
| `GetOsAccountDistributedInfo()` | 312-360 | Query by userId |
| `QueryDistributedVirtualDeviceId()` | 237-266 | Get DVID |
| `SubscribeDistributedAccountEvent()` | 417-431 | Subscribe events |
| `UnsubscribeDistributedAccountEvent()` | 433-447 | Unsubscribe events |

### 3.2 OhosAccountManager — key methods

| Method | Lines | Description |
|---------|-------|-------------|
| `OnInitialize()` | 731-754 | Load account data |
| `LoginOhosAccount()` | 511-566 | Process login, save to JSON |
| `LogoutOhosAccount()` | 576-615 | Process logout |
| `HandleOhosAccountTokenInvalidEvent()` | 673-712 | Handle token invalid |
| `GetOhosAccountDistributedInfo()` | 372-395 | Get with anonymization |
| `QueryDistributedVirtualDeviceId()` | 283-303 | Generate DVID |

**Key flows**:
1. **Login**: CheckCanBind → Gen SHA256 UID → UpdateState → SaveJSON → PublishEvent
2. **Query**: CheckSystemApp → ReturnFull or Anonymized

### 3.3 OhosAccountDataDeal

| Method | Lines | Description |
|---------|-------|-------------|
| `Init()` | 156-197 | Load/create JSON files |
| `AccountInfoFromJson()` | 199-206 | Deserialize from JSON |
| `AccountInfoToJson()` | 208-215 | Serialize to JSON |
| `SaveAccountInfo()` | 217-259 | Persist to file |
| `BuildJsonFileFromScratch()` | 395-413 | Create default file |

### 3.4 DistributedAccountSubscribeManager

| Method | Lines | Description |
|---------|-------|-------------|
| `SubscribeDistributedAccountEvent()` | 41-68 | Add listener |
| `UnsubscribeDistributedAccountEvent()` | 70-95 | Remove listener |
| `Publish()` | 154-177 | Notify all subscribers (async with retry) |

Events: LOGIN, LOGOUT, LOGOFF, TOKEN_INVALID

---

## 4. Constraints & Boundaries

### 4.1 DVID Generation

[../ohos_account_manager.cpp:124-154](../ohos_account_manager.cpp)

```cpp
DVID = PBKDF2_HMAC-SHA256(raw_uid, bundleName, 1000, 32)
```
- Per-app unique ID for privacy — prevents cross-app tracking.
- **Do not change** the algorithm, iteration count, or salt — existing DVIDs
  across devices and apps depend on this exact computation.

### 4.2 Account Anonymization

[../ohos_account_manager.cpp:349-370](../ohos_account_manager.cpp#L349-L370)

| Caller type | Raw UID | Name | Nickname | Avatar | ScalableData |
|-------------|---------|------|----------|--------|--------------|
| System app | Full | Full | Full | Full | Full |
| Normal app | DVID | FirstChar + `**********` | FirstChar + `**********` | `**********` | Empty |

**Do not change** anonymization rules — privacy guarantees depend on them.

### 4.3 JSON Schema (on-disk, compatibility-sensitive)

[../ohos_account_data_deal.cpp](../ohos_account_data_deal.cpp)

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

**Do not change** field names, types, or the `version` field semantics — breaks
upgrade compatibility (Root AGENTS.md §3.1). Version migration: check `version`
field and upgrade format accordingly (§7 FAQ Q10).

### 4.4 File Watcher (ENABLE_FILE_WATCHER)

Detects tampering via inotify + SHA256 digest comparison. Do not disable without
escalation — security boundary.

### 4.5 State Machine

```
UNBOUND --[LOGIN]--> LOGIN --[LOGOUT/LOGOFF/TOKEN_INVALID]--> UNBOUND
```

| State | Value | Description |
|--------|---------|-------------|
| UNBOUND | 0 | Not logged in |
| LOGIN | 1 | Logged in/bound |
| LOGOUT | 2 | Logged out |
| TOKEN_INVALID | 3 | Token expired |

State transition: [../ohos_account_manager.cpp:453-489](../ohos_account_manager.cpp#L453-L489)

### 4.6 Thread Safety

| Mutex | Protects |
|-------|----------|
| `OhosAccountManager::mgrMutex_` | State changes |
| `OhosAccountDataDeal::mutex_` / `accountInfoFileLock_` | File I/O |
| `DistributedAccountSubscribeManager::subscribeRecordMutex_` | Subscription list |

Do not hold `mgrMutex_` during IPC or disk I/O (Root AGENTS.md §3.4 Pitfall 6).

### 4.7 Permissions

- `MANAGE_DISTRIBUTED_ACCOUNTS` — manage distributed accounts
- `GET_DISTRIBUTED_ACCOUNTS` — query distributed accounts
- `DISTRIBUTED_DATASYNC` — cross-device data sync
- `MANAGE_USERS` — query other users

Do not remove or weaken permission checks (Root AGENTS.md §3.1).

### 4.8 Do not (without explicit user escalation)

- **Do not change the JSON schema** (field names, types, `version` semantics) —
  breaks upgrade compatibility (§4.3).
- **Do not change the DVID algorithm** (PBKDF2, iterations=1000, keylen=32,
  salt=bundleName) — existing cross-device sync depends on it (§4.1).
- **Do not change anonymization rules** — privacy boundary (§4.2).
- **Do not change event names** (LOGIN, LOGOUT, LOGOFF, TOKEN_INVALID) —
  subscribers depend on them.
- **Do not change state values** (0=UNBOUND, 1=LOGIN, 2=LOGOUT, 3=TOKEN_INVALID)
  — persisted in JSON `bind_status` field.
- **Do not disable file watcher** without escalation — tamper detection boundary.

### 4.9 Ask before

- Changing state machine transitions (§4.5) — affects login/logout flows.
- Changing retry count (`MAX_RETRY_TIMES`) for event publishing.
- Changing `ENABLE_FILE_WATCHER` / `HAS_CES_PART` / `HAS_HUKS_PART` flags.

### 4.10 Error Codes

| Code | Description |
|------|-------------|
| `ERR_OK` | Success |
| `ERR_ACCOUNT_COMMON_PERMISSION_DENIED` | Permission check failed |
| `ERR_ACCOUNT_COMMON_INVALID_PARAMETER` | Invalid parameters |
| `ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR` | Account not found |
| `ERR_ACCOUNT_ZIDL_ACCOUNT_SERVICE_ERROR` | Internal error |
| `ERR_ACCOUNT_DATADEAL_JSON_FILE_CORRUPTION` | JSON corrupted (auto-retry) |
| `ERR_OHOSACCOUNT_KIT_NO_SPECIFIED_CALLBACK_HAS_BEEN_REGISTERED` | Subscription not found |

---

## 5. Usage Scenarios

### 5.1 Login Flow
```
App -> SetOhosAccountInfo(name, uid, LOGIN)
     -> Permission check
     -> Gen OHOS_UID = SHA256(uid)
     -> State: UNBOUND -> LOGIN
     -> Save to JSON
     -> Publish to subscribers (DistributedKV, DSoftbus)
     -> Send CommonEvents
```

### 5.2 Query with Anonymization
```
App -> GetOhosAccountInfo()
     -> Check if system app
         -> YES: Return full data
         -> NO:  Return DVID + masked name
```

### 5.3 Token Invalid Handling
```
Server Token Expire -> Auth App callback
     -> SetOhosAccountInfo(TOKEN_INVALID)
     -> State: LOGIN -> TOKEN_INVALID
     -> Notify subscribers (stop sync)
     -> Apps re-authenticate user
```

### 5.4 DVID for Cross-Device Sync
```
DistributedKV -> QueryDistributedVirtualDeviceId()
     -> Gen DVID = PBKDF2(uid, bundleName)
     -> Use as key: "dist_db_{DVID}"
     -> Sync across devices via same DVID
```

---

## 6. Troubleshooting

| Issue | Check |
|-------|--------|
| Login fails "already bound" | Check `bind_status` in JSON, verify not stuck in LOGIN state |
| JSON corrupted | Auto-retry enabled (`MAX_RETRY_TIMES=2`), check file integrity |
| No events received | Verify system app, death recipient registered, correct event type |
| DVID empty | Check OpenSSL loaded, UID length < 512 |

**Debug commands:**
```bash
cat /data/service/el1/public/account/{userId}/account.json | jq
hidumper -s accountmgr -a
grep "ohos_account" /var/log/hisysevent/*.log
```

---

## 7. FAQ

**Q1: LOGOUT vs LOGOFF?** LOGOUT = unbind (can re-login), LOGOFF = remove from device.

**Q2: Why DVID differs per app?** PBKDF2 uses bundleName as salt for privacy.

**Q3: Same OHOS account on multiple users?** Blocked by `CheckOhosAccountCanBind` ([../ohos_account_manager.cpp#L789](../ohos_account_manager.cpp#L789)).

**Q4: How tampering detected?** inotify + SHA256 digest comparison.

**Q5: Crash recovery?** Reload JSON, restore state, re-register subscriptions.

**Q6: Anonymized data?** Non-system apps get DVID + masked names.

**Q7: Account sync across devices?** Not by this service. DistributedKV uses DVID as sync key.

**Q8: Query other users?** Only with `MANAGE_USERS` or `INTERACT_ACROSS_LOCAL_ACCOUNTS` permission.

**Q9: Max retry for events?** `Constants::MAX_RETRY_TIMES` (typically 3).

**Q10: Version migration?** Check `version` field in JSON, upgrade format accordingly.

---

## 8. Verification

### 8.1 Minimum checks

See root [AGENTS.md](../../../../AGENTS.md) §5.1 for build commands. For this module:

```bash
# Build
./build.sh --product-name rk3568 --build-target os_account account_build_unittest account_build_moduletest

# Run distributed account test suites
cd {OpenHarmonyRootFolder}/test/testfwk/developer_test
./start.sh run -p rk3568 -t UT MST -tp os_account -ts OhosAccountManagerModuleTest
```

### 8.2 Task-specific validation

| If you changed… | Also check |
|----------------|------------|
| `ohos_account_manager.cpp` (login/logout) | Verify state machine transitions intact; run manager module tests |
| DVID generation (`ohos_account_manager.cpp:124-154`) | Verify algorithm unchanged (§4.1); test cross-device sync |
| Anonymization (`ohos_account_manager.cpp:349-370`) | Verify rules unchanged (§4.2); test system vs normal app paths |
| `ohos_account_data_deal.cpp` (JSON) | Verify schema unchanged (§4.3); test reboot-restore; test version migration |
| `distributed_account_subscribe_manager.cpp` | Verify event names unchanged; test subscriber death handling |
| File watcher flag | Test tamper detection path |

### 8.3 Done definition

A change is **done** when:
1. Build succeeds: `./build.sh --product-name rk3568 --build-target os_account` (no errors).
2. Relevant test suite passes — report suite name + pass/fail counts.
3. No new compiler warnings in changed files.
4. If JSON schema, DVID algorithm, anonymization rules, event names, or state
   values changed: **escalate to user** (compatibility/privacy boundary, §4.8).
5. If file watcher or permission checks changed: **escalate to user** (§4.8).

### 8.4 Fallback

If build/tests cannot run locally, state "I could not run the build/tests because
\<reason\>" and ask the user to run §8.1 commands. Do not claim the change is verified.

---

## 9. Configuration

| Flag | Purpose |
|--------|-----------|
| `HAS_CES_PART` | Enable common events |
| `ENABLE_FILE_WATCHER` | Enable tampering detection |
| `HAS_HUKS_PART` | Enable HUKS digest |
| `ACCOUNT_TEST` | Use test directory |

---

## Version History

| Version | Date | Changes | Maintainer |
|---------|------|---------|------------|
| v1.0 | 2026-01-31 | Initial AGENTS.md creation | AI Assistant |
| v2.0 | 2026-07-09 | Rewritten per agent-instruction quality review: added code map, knowledge routing, constraints, verification | AI Assistant |
