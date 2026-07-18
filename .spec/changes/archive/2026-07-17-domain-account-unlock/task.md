# Task Specification

> Self-contained task cards for 12 tasks. An AI Agent uses these to independently complete the coding implementation.

## TASK-1: C-ABI + Struct Definitions

| Field | Content |
|------|------|
| Task ID | TASK-1 |
| Title | C-ABI Interface + InnerAPI Struct Extension |
| Related Feature | F1 |
| Target Repository | os_account |
| Target Module | domain_account (C-ABI + InnerAPI) |
| Priority | P0 |
| Complexity | Medium |
| Execution Mode | Independently executable |

### What to Do

1. In `domain_plugin.h`, add the `PluginAuthResultInfo.secret` field, the `PluginUnlockDeviceConfigResult` struct, the `UnlockDeviceMode` enum, the `AuthWithUnlockIntentFunc`/`GetUnlockDeviceConfigResultFunc` function pointer types, and new `PluginMethodEnum` enum values
2. In `domain_account_common.h`, add the `DomainAuthResult.secret` field and the `DomainAccountUnlockOptions` struct
3. In `domain_account_common.cpp`, extend the `DomainAuthResult` serialization and implement the `DomainAccountUnlockOptions` serialization

### What Not to Do

- Do not implement DomainPluginAdapter logic
- Do not implement the mock plugin
- Do not implement business logic

### AC Mapping

| AC | Source | Verification Method |
|----|------|----------|
| AC-F1-1.1 | F1 spec | Compile + header file check |
| AC-F1-3.1~3.2 | F1 spec | Unit test (serialization/deserialization) |
| AC-F1-4.1 | F1 spec | Compile + enum check |

### Affected Files

| Operation | File Path | Description |
|------|----------|------|
| Modify | `interfaces/innerkits/domain_account/native/include/domain_plugin.h` | Add secret/structs/enums/function pointers/PluginMethodEnum |
| Modify | `interfaces/innerkits/domain_account/native/include/domain_account_common.h` | DomainAuthResult +secret; add DomainAccountUnlockOptions |
| Modify | `frameworks/domain_account/src/domain_account_common.cpp` | Serialization extension |

### AC

- **AC-1:** WHEN the header file is compiled THEN no compile errors
- **AC-2:** WHEN viewing PluginAuthResultInfo THEN it contains the secret field
- **AC-3:** WHEN viewing PluginMethodEnum THEN it contains AUTH_WITH_UNLOCK_INTENT and GET_UNLOCK_DEVICE_CONFIG
- **AC-4:** WHEN DomainAccountUnlockOptions is serialized and then deserialized THEN the challenge and authIntent values are consistent

### Verification Checklist

- [ ] All ACs have corresponding test coverage
- [ ] Compilation passes
- [ ] No modifications outside the file scope

---

## TASK-2: DomainPluginAdapter Adaptation

| Field | Content |
|------|------|
| Task ID | TASK-2 |
| Title | DomainPluginAdapter METHOD_NAME_MAP + LoadPlugin + Extraction Logic |
| Related Feature | F1 |
| Priority | P0 |
| Complexity | Medium |
| Execution Mode | Independently executable (depends on TASK-1) |

### What to Do

1. Add to `METHOD_NAME_MAP`: `AUTH_WITH_UNLOCK_INTENT` → `"AuthWithUnlockIntent"` and `GET_UNLOCK_DEVICE_CONFIG` → `"GetUnlockDeviceConfigResult"`
2. Extend `GetAndCleanPluginAuthResultInfo`: extract `secret` → `DomainAuthResult.secret`
3. Add `GetAndCleanPluginUnlockDeviceConfigResult`: extract `enableUnlockDevice`/`unlockDeviceMode` + `free`

### AC Mapping

| AC | Source |
|----|------|
| AC-F1-1.2 | F1 spec |
| AC-F1-2.1~2.2 | F1 spec |
| AC-F1-4.2~4.3 | F1 spec |

### Affected Files

| Operation | File Path |
|------|----------|
| Modify | `services/accountmgr/src/domain_account/domain_plugin_adapter.cpp` |
| Modify | `services/accountmgr/include/domain_account/domain_plugin_adapter.h` |

### Prerequisites

| Type | ID | Reason |
|------|------|------|
| Task | TASK-1 | Struct definitions must be completed first |

### Verification Checklist

- [ ] Compilation passes
- [ ] GetAndCleanPluginAuthResultInfo extracts secret
- [ ] GetAndCleanPluginUnlockDeviceConfigResult converts and releases

---

## TASK-3: DomainAuthCallbackAdapter Extension

| Field | Content |
|------|------|
| Task ID | TASK-3 |
| Title | DomainAuthCallbackAdapter::OnResult adds ATTR_NEXT_FAIL_LOCKOUT_DURATION |
| Related Feature | F1 |
| Priority | P0 |
| Complexity | Low |
| Execution Mode | Independently executable (depends on TASK-1) |

### What to Do

1. In `DomainAuthCallbackAdapter::OnResult`, set `ATTR_NEXT_FAIL_LOCKOUT_DURATION` from `authResult->authStatusInfo.nextPhaseFreezingTime`
2. Do not set `ATTR_ROOT_SECRET` (the secret is not transmitted to the client via IPC — security isolation)

### AC Mapping

| AC | Source |
|----|------|
| AC-F1-1.3 | F1 spec |

### Affected Files

| Operation | File Path |
|------|----------|
| Modify | `frameworks/account_iam/src/account_iam_callback_service.cpp` |

---

## TASK-4: Mock Plugin Update

| Field | Content |
|------|------|
| Task ID | TASK-4 |
| Title | mock_domain_so_plugin adds AuthWithUnlockIntent + GetUnlockDeviceConfigResult |
| Related Feature | F1 |
| Priority | P0 |
| Complexity | Medium |
| Execution Mode | Independently executable (depends on TASK-1 + TASK-2) |

### What to Do

1. Implement the `AuthWithUnlockIntent` mock: asynchronous callback returning a `PluginAuthResultInfo` containing `accountToken` + `secret`
2. Implement the `GetUnlockDeviceConfigResult` mock: synchronously returns `PluginUnlockDeviceConfigResult`
3. Add 2 new mappings to `PLUGIN_METHOD_MAP`

### Affected Files

| Operation | File Path |
|------|----------|
| Modify | `frameworks/domain_account/test/moduletest/src/mock_domain_so_plugin.cpp` |
| Modify | `frameworks/domain_account/test/moduletest/include/mock_domain_so_plugin.h` |

---

## TASK-5: SetDomainAuthUnlockEnabled API + IDL + Stub

| Field | Content |
|------|------|
| Task ID | TASK-5 |
| Title | SetDomainAuthUnlockEnabled InnerKit API + IDL + Service Stub |
| Related Feature | F2 |
| Priority | P0 |
| Complexity | Medium |
| Execution Mode | Independently executable (depends on TASK-1) |

### What to Do

1. Add the `SetDomainAuthUnlockEnabled` method to `IAccountIAM.idl`
2. Add API declaration and implementation to `account_iam_client.h/.cpp` (get proxy → IPC)
3. Add stub to `account_iam_service.cpp` (uid 7058 + MANAGE_USER_IDM permission check → delegate)

### AC Mapping

| AC | Source |
|----|------|
| AC-F2-1.1~1.5 | F2 spec |

### Affected Files

| Operation | File Path |
|------|----------|
| Modify | `frameworks/account_iam/IAccountIAM.idl` |
| Modify | `interfaces/innerkits/account_iam/native/include/account_iam_client.h` |
| Modify | `frameworks/account_iam/src/account_iam_client.cpp` |
| Modify | `services/accountmgr/src/account_iam/account_iam_service.cpp` |

---

## TASK-6: SetDomainAuthUnlockEnabled Business Logic

| Field | Content |
|------|------|
| Task ID | TASK-6 |
| Title | InnerAccountIAMManager SetDomainAuthUnlockEnabled Business Logic |
| Related Feature | F2 |
| Priority | P0 |
| Complexity | High |
| Execution Mode | Independently executable (depends on TASK-5) |

### What to Do

1. uid 7058 check + MANAGE_USER_IDM permission check
2. localId existence + domain account binding check
3. token validity check (VerifyAuthToken)
4. libHandle_ check (nullptr → not supported)
5. Enable flow: query existing key → if present, return directly → if absent, UpdateStorageUserAuth to add
6. Disable flow: query existing key → if present, only update state → if absent, UpdateStorageUserAuth to delete

### AC Mapping

| AC | Source |
|----|------|
| AC-F2-1.1~1.9 | F2 spec |

### Affected Files

| Operation | File Path |
|------|----------|
| Modify | `services/accountmgr/src/account_iam/inner_account_iam_manager.cpp` |
| Modify | `services/accountmgr/include/account_iam/inner_account_iam_manager.h` |

---

## TASK-7: GetUnlockDeviceConfig Internal Query

| Field | Content |
|------|------|
| Task ID | TASK-7 |
| Title | InnerDomainAccountManager::GetUnlockDeviceConfig Internal Method |
| Related Feature | F2 |
| Priority | P0 |
| Complexity | Medium |
| Execution Mode | Independently executable (depends on TASK-2) |

### What to Do

1. libHandle_ check (nullptr → enableUnlockDevice=false)
2. Get domain account info
3. Look up the GET_UNLOCK_DEVICE_CONFIG function pointer via methodMap_
4. Call the plugin + GetAndCleanPluginUnlockDeviceConfigResult conversion

### AC Mapping

| AC | Source |
|----|------|
| AC-F2-2.1~2.2 | F2 spec |

### Affected Files

| Operation | File Path |
|------|----------|
| Modify | `services/accountmgr/src/domain_account/inner_domain_account_manager.cpp` |
| Modify | `services/accountmgr/include/domain_account/inner_domain_account_manager.h` |

---

## TASK-8: PIN Add Flow Adaptation

| Field | Content |
|------|------|
| Task ID | TASK-8 |
| Title | AddCredCallback::OnResult PIN Add Flow Adaptation |
| Related Feature | F2 |
| Priority | P0 |
| Complexity | Medium |
| Execution Mode | Independently executable (depends on TASK-7) |

### What to Do

1. When AddCredCallback::OnResult succeeds and the credential is a PIN, call GetUnlockDeviceConfig
2. Check enableUnlockDevice && ONLINE_OFFLINE_AUTH_UNLOCK_DEVICE
3. When the condition is met, skip UpdateStorageUserAuth + UpdateStorageKeyContext

### AC Mapping

| AC | Source |
|----|------|
| AC-F2-3.1~3.3 | F2 spec |

### Affected Files

| Operation | File Path |
|------|----------|
| Modify | `services/accountmgr/src/account_iam/account_iam_callback.cpp` |

---

## TASK-9: PIN Delete Flow Adaptation

| Field | Content |
|------|------|
| Task ID | TASK-9 |
| Title | VerifyTokenCallbackWrapper::InnerOnResult PIN Delete Flow Adaptation |
| Related Feature | F2 |
| Priority | P0 |
| Complexity | Medium |
| Execution Mode | Independently executable (depends on TASK-7 + TASK-8; both modify account_iam_callback.cpp and must be executed serially with TASK-8) |

### What to Do

1. Call GetUnlockDeviceConfig in VerifyTokenCallbackWrapper::InnerOnResult
2. Check the condition (same as TASK-8)
3. When the condition is met, skip UpdateStorageUserAuth

### AC Mapping

| AC | Source |
|----|------|
| AC-F2-4.1~4.2 | F2 spec |

### Affected Files

| Operation | File Path |
|------|----------|
| Modify | `services/accountmgr/src/account_iam/account_iam_callback.cpp` |

---

## TASK-10: AuthUser Signature Modification + AuthUserWithUnlockOptions IDL

| Field | Content |
|------|------|
| Task ID | TASK-10 |
| Title | AuthUser hook-based signature modification + AuthUserWithUnlockOptions IDL + Client/Service framework |
| Related Feature | F3 |
| Priority | P0 |
| Complexity | High |
| Execution Mode | Independently executable (depends on TASK-1 + TASK-5) |

### What to Do

1. Add sequenceable DomainAccountUnlockOptions + AuthUserWithUnlockOptions method to IDomainAccount.idl
2. Modify the DomainAccountClient::AuthUser hook-based signature (add DomainAccountUnlockOptions parameter)
3. Modify the AuthUser implementation to internally call proxy->AuthUserWithUnlockOptions
4. No separate client function; AccountIAMClient::AuthUser calls StartDomainAuth for all DOMAIN auth (passing DomainAccountUnlockOptions); authIntent routing is server-side in DomainAccountManagerService::AuthUserWithUnlockOptions
5. Add authIntent==UNLOCK routing judgment to the AuthUser DOMAIN branch
6. Add AuthUserWithUnlockOptions stub to DomainAccountManagerService
7. Update existing test call-site signatures

### AC Mapping

| AC | Source |
|----|------|
| AC-F3-1.1, AC-F3-1.11 | F3 spec |

### Affected Files

| Operation | File Path |
|------|----------|
| Modify | `frameworks/domain_account/IDomainAccount.idl` |
| Modify | `interfaces/innerkits/domain_account/native/include/domain_account_client.h` |
| Modify | `frameworks/domain_account/src/domain_account_client.cpp` |
| Modify | `frameworks/account_iam/src/account_iam_client.cpp` |
| Modify | `services/accountmgr/src/domain_account/domain_account_manager_service.cpp` |

---

## TASK-11: AuthUserWithUnlockOptions Business Implementation + Unlock Logic

| Field | Content |
|------|------|
| Task ID | TASK-11 |
| Title | InnerDomainAccountManager AuthUserWithUnlockOptions + InnerDomainAuthCallback Unlock Logic |
| Related Feature | F3 |
| Priority | P0 |
| Complexity | High |
| Execution Mode | Independently executable (depends on TASK-2 + TASK-7 + TASK-10) |

### What to Do

1. InnerDomainAccountManager::AuthUserWithUnlockOptions: libHandle_ check → binding check → unlock check → construct InnerDomainAuthCallback (authIntent_=UNLOCK) → call plugin AuthWithUnlockIntent
2. Add authIntent parameter to the InnerDomainAuthCallback constructor
3. Insert unlock logic in InnerDomainAuthCallback::OnResult before line 232:
   - Check authIntent_==UNLOCK && errCode==ERR_OK
   - Check the account is not deactivated/locked
   - ActivateUserKey (EL2) → GetLockScreenStatus → UnlockUserScreen (EL3/EL4)
   - SetOsAccountIsVerified
   - memset_s to zero out token/secret
4. Ensure the existing Auth/AuthUser IDL path does not set authIntent_ (DEFAULT) and does not unlock

### AC Mapping

| AC | Source |
|----|------|
| AC-F3-1.1~1.11, AC-F3-2.1~2.2 | F3 spec |

### Affected Files

| Operation | File Path |
|------|----------|
| Modify | `services/accountmgr/src/domain_account/inner_domain_account_manager.cpp` |
| Modify | `services/accountmgr/include/domain_account/inner_domain_account_manager.h` |

### Key Design References

| Design Element | Reference Location | Key Conclusion |
|---------|----------|---------|
| ADR-1 | design.md §ADR-1 | A-1: OnResult directly calls the unlock API |
| ADR-6 | design.md §ADR-6 | Only authIntent_==UNLOCK triggers unlock |
| token zeroing timing | design.md §Requirements Baseline | Unlock logic is before line 232 |

---

## TASK-12: Unit Tests + Integration Tests

| Field | Content |
|------|------|
| Task ID | TASK-12 |
| Title | 60 test case implementation |
| Related Feature | F1 + F2 + F3 |
| Priority | P0 |
| Complexity | High |
| Execution Mode | Independently executable (depends on TASK-4~TASK-11 all completed) |

### What to Do

1. Implement 17 test cases for F1 (see `specs/plugin-interface-extension/test-design.md`)
2. Implement 21 test cases for F2 (see `specs/unlock-capability-switch/test-design.md`)
3. Implement 22 test cases for F3 (see `specs/domain-account-unlock-flow/test-design.md`)
4. Run tests and record results

### AC Mapping

Full set of ACs (39 items)

### Affected Files

| Operation | File Path |
|------|----------|
| Modify | `services/accountmgr/test/unittest/domain_account/domain_plugin_adapter_test.cpp` |
| Modify | `frameworks/domain_account/test/moduletest/src/domain_account_common_test.cpp` |
| Modify | `frameworks/account_iam/test/unittest/src/account_iam_callback_service_test.cpp` |
| Modify | `services/accountmgr/test/unittest/account_iam/account_iam_service_test.cpp` |
| Modify | `services/accountmgr/test/unittest/account_iam/account_iam_manager_test.cpp` |
| Modify | `services/accountmgr/test/unittest/domain_account/domain_account_manager_inner_service_test.cpp` |
| Modify | `services/accountmgr/test/unittest/account_iam/account_iam_callback_test.cpp` |
| Modify | `frameworks/account_iam/test/unittest/src/account_iam_client_test.cpp` |
| Modify | `frameworks/domain_account/test/moduletest/src/domain_account_client_mock_plugin_so_module_test.cpp` |

### Verification Checklist

- [ ] All 60 test cases implemented
- [ ] Tests pass (RED-GREEN-REFACTOR)
- [ ] Build passes
- [ ] Static analysis passes
- [ ] Completion evidence recorded

**Completion Evidence:**

| Evidence | Command/Path | Result |
|------|-----------|------|
| Test | `./start.sh run -p rk3568 -t UT MST -tp os_account` | PASS/FAIL |
| Build | `hb build os_account -t` | PASS/FAIL |
