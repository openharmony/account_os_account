# OS Account SubProfile Subscribe Module - Agent Instruction Guide

> Scope: **directory** `services/accountmgr/src/os_account_subprofile/` — SubProfile
> event subscription and notification logic.
> Parent: [../../../../AGENTS.md](../../../../AGENTS.md) (root, §1–8 framework applies here too).
> Target: any coding agent editing this module.
> Feature flag: `os_account_enable_multiple_os_account_sub_profiles` (default `false`).
> C++ define: `ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE` (note: "SUBSPACE", not "SUB_PROFILES").

---

## 1. Code Map

### 1.1 Responsibility

This module owns the **SubProfile event subscription and notification**
pipeline: maintaining the subscriber registry, dispatching events async over
IPC with retry, and auto-cleaning dead subscribers via a death recipient.

It does **not** own the SubProfile lifecycle (create/remove/switch) — that
logic lives in `OsAccountSubProfileManager`
(`services/accountmgr/src/distributed_account/os_account_subspace_manager.cpp`).
This module is the *publish/subscribe* side only; publishers call
`OsAccountSubProfileSubscribeManager::GetInstance().Publish(...)` and this
module handles the rest.

### 1.2 Directory Structure

Service logic: `services/accountmgr/src/os_account_subprofile/` (2 .cpp files).
Headers: `services/accountmgr/include/os_account_subprofile/`.
Inner API (event types + callback interface):
`interfaces/innerkits/os_account_subspace/native/include/os_account_sub_profile_subscribe_callback.h`.
Framework: `frameworks/os_account_subspace/` (callback impl + parcelables).

### 1.3 Key Entry Points

| Component | File | Notes |
|-----------|------|-------|
| Subscribe manager (singleton) | `os_account_sub_profile_subscribe_manager.cpp` | `GetInstance()`; registry + async dispatch |
| Death recipient | `os_account_sub_profile_subscribe_death_recipient.cpp` | Auto-unsubscribe on caller death |
| Event type enum + callback iface | `interfaces/innerkits/os_account_subspace/native/include/os_account_sub_profile_subscribe_callback.h` | `OsAccountSubProfileEventType`, `OsAccountSubProfileSubscribeCallback` |

> **SA ID**: SubProfile subscribe is **not** a standalone SA. The IPC stub
> lives in `services/accountmgr/src/distributed_account/os_account_subspace_manager_service.cpp`
> and forwards to `OsAccountSubProfileSubscribeManager`.

### 1.4 Where to Look (task → path)

| Task | Start here |
|------|------------|
| Add a new event type | `os_account_sub_profile_subscribe_callback.h` (enum) → `frameworks/os_account_subspace/src/os_account_sub_profile_subscribe_callback.cpp` (`IsValidOsAccountSubProfileEventType`) → publishers |
| Change subscribe/unsubscribe logic | `os_account_sub_profile_subscribe_manager.cpp` `SubscribeOsAccountSubProfileEvents()` / `UnsubscribeOsAccountSubProfileEvents()` |
| Change publish/dispatch | `os_account_sub_profile_subscribe_manager.cpp` `Publish()` / `ExecuteSubProfileEventNotifyAsync()` |
| Debug missing notifications | `GetSubscribersToNotify()` (filter logic); `SendSubProfileEventNotify()` (retry logic) |
| Death cleanup | `os_account_sub_profile_subscribe_death_recipient.cpp` `OnRemoteDied()` |

---

## 2. Data Structures

### 2.1 OsAccountSubProfileEventType

Defined at `interfaces/innerkits/os_account_subspace/native/include/os_account_sub_profile_subscribe_callback.h:25`:

| Value | Name | When published |
|-------|------|----------------|
| 0 | `CREATED` | SubProfile or OS account created |
| 1 | `DELETED` | SubProfile or OS account removed |
| 2 | `SWITCHING` | Before foreground subprofile switch |
| 3 | `SWITCHED` | After foreground subprofile switch |
| 4 | `INVALID_TYPE` | Sentinel — not a valid event |

Validator: `IsValidOsAccountSubProfileEventType(int32_t)` — valid range is `[CREATED, INVALID_TYPE)`.

### 2.2 SubProfileEventData

Parcelable at `os_account_sub_profile_subscribe_callback.h:35`:
- `type_` — the event type
- `osAccountId_` — the owning OS account
- `subProfileId_` — the target subprofile
- `previousSubProfileId_` — used for SWITCHING/SWITCHED (default -1)

### 2.3 OsAccountSubProfileSubscribeRecord

At `os_account_sub_profile_subscribe_manager.h:30`:
- `eventListener_` — `sp<OsAccountSubProfileSubscribeCallback>` (IPC remote)
- `types_` — `std::set<OsAccountSubProfileEventType>` (subscribed events)
- `localId_` — calling OS account ID (derived from `callingUid / UID_TRANSFORM_DIVISOR`)
- `isNotifyAllUsers_` — `true` when `localId == 0` (system caller)

---

## 3. Thread Safety

| Lock | Type | Protects |
|------|------|----------|
| `recordMutex_` | `std::shared_mutex` | `subscribeRecords_` (the subscriber registry) |

- **Subscribe/Unsubscribe**: acquire `recordMutex_` in exclusive mode.
- **Publish → GetSubscribersToNotify**: acquires `recordMutex_` in shared mode to iterate, copies matching records out, then releases before async dispatch.
- **Async dispatch**: runs on a detached thread named `"subProfileEvent"`; no lock held during IPC calls.

---

## 4. Interaction Flows

### 4.1 Subscribe flow

1. Service stub (`os_account_subspace_manager_service.cpp`) validates each
   `typeInt` via `IsValidOsAccountSubProfileEventType`, converts to enum set.
2. `SubscribeOsAccountSubProfileEvents(types, eventListener)` — derives
   `localId` from calling UID; sets `isNotifyAllUsers = (localId == 0)`;
   attaches death recipient; merges types if listener already exists.

### 4.2 Publish flow

1. Publisher calls `Publish(eventType, localId, subProfileId, previousSubProfileId=-1)`.
2. `GetSubscribersToNotify` filters records: a subscriber matches if
   `isNotifyAllUsers` OR `localId` matches, AND the event type is in `types_`.
3. Each notification dispatched via `ExecuteSubProfileEventNotifyAsync` on a
   detached thread — calls `SendSubProfileEventNotify` with `MAX_RETRY_TIMES`
   retry on IPC errors.

### 4.3 Death cleanup

`OsAccountSubProfileSubscribeDeathRecipient::OnRemoteDied` promotes the weak
ref and calls `UnsubscribeOsAccountSubProfileEvents(object)` to remove all
subscriptions for the dead subscriber.

---

## 5. Publishers (call sites)

Publishers call `OsAccountSubProfileSubscribeManager::GetInstance().Publish(...)`:

| Publisher | Location | Events |
|-----------|----------|--------|
| OS account create finalization | `inner_os_account_manager.cpp:905,913,917,920` | CREATED, SWITCHING, SWITCHED |
| Public create subprofile | `ohos_account_manager.cpp:674` | CREATED |
| Public delete subprofile | `ohos_account_manager.cpp:713` | DELETED |
| Public switch subprofile | `ohos_account_manager.cpp:739,749` | SWITCHING, SWITCHED |

---

## 6. Error Codes

SubProfile-specific error codes are in `interfaces/innerkits/common/include/account_error_no.h`:

**Internal** (`ERR_OS_ACCOUNT_SUBPROFILE_*`, lines 102–107):
`LIMIT`, `NOT_FOUND`, `RESTRICTED`, `IS_FOREGROUND`, `HAS_ACTIVE_SESSION`,
`DISTRIBUTE_ACC_ALREADY_BOUND`.

**JS/NAPI** (`ERR_JS_OS_ACCOUNT_SUBPROFILE_*`, lines 407–412, range `12300401`–`12300406`).

---

## 7. Build & Test

```bash
# Build (from OpenHarmony root)
./build.sh --product-name rk3568 --build-target accountmgr

# Tests
cd {OpenHarmonyRootFolder}/test/testfwk/developer_test
./start.sh run -p rk3568 -t UT MST -tp os_account
```
