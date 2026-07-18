# F3 Domain Account Unlock Flow — Test Case Design

> Test cases designed based on spec.md ACs. Follows existing test patterns: HWTEST_F + Mock+Wrapper + mock_domain_so_plugin + condition_variable synchronization.

## Test Files and Targets

| Test file | Test target | BUILD.gn target |
|----------|----------|---------------|
| `frameworks/account_iam/test/unittest/src/account_iam_client_test.cpp` | DOMAIN authentication routing via `StartDomainAuth` | `ohos_unittest("account_iam_client_test")` |
| `frameworks/domain_account/test/moduletest/src/domain_account_client_mock_plugin_so_module_test.cpp` | AuthUser signature change, AuthUserWithUnlockOptions IDL | `ohos_moduletest("domain_account_client_mock_plugin_so_module_test")` |
| `services/accountmgr/test/unittest/domain_account/domain_account_manager_inner_service_test.cpp` | AuthUserWithUnlockOptions business logic, InnerDomainAuthCallback unlock logic | `ohos_unittest("domain_account_manager_inner_service_test")` |
| `services/accountmgr/test/unittest/account_iam/account_iam_callback_test.cpp` | InnerDomainAuthCallback::OnResultWithUnlock unlock + zeroing | `ohos_unittest("account_iam_callback_test")` |

## Test Constants

```cpp
const std::vector<uint8_t> TEST_TOKEN = {1, 2, 3, 4, 5};
const std::vector<uint8_t> TEST_SECRET = {10, 20, 30, 40, 50};
const std::vector<uint8_t> TEST_CHALLENGE = {1, 2, 3, 4, 5, 6, 7, 8};
const int32_t TEST_AUTH_INTENT_UNLOCK = 1;
const int32_t WAIT_TIME = 5;  // Async wait seconds
```

## Test Cases

### AC-F3-1.1: DOMAIN+UNLOCK routes to AuthWithUnlockIntent

| Case ID | Test name | Test steps | Expected result | Level |
|---------|--------|----------|----------|------|
| F3-1.1 | `DomainAccountUnlock_001` | 1. Bind a domain account + enable unlock 2. Call `DomainAccountClient::AuthUser(userId, getPassword, callback, options{authIntent=UNLOCK_INTENT, challenge={1,2,3}}, contextId)` 3. Mock plugin `AuthWithUnlockIntent` returns success 4. Verify plugin receives `challengeValue`; verify `OnAcquireInfo` is received (module==DOMAIN) | Returns `ERR_OK`; plugin `AuthWithUnlockIntent` invoked; `challengeValue` matches input; `OnAcquireInfo` callback received (module==DOMAIN) | Level3 |
| F3-1.1 | `DomainAccountUnlock_002` | 1. Bind a domain account 2. Call `AuthUser` with `authIntent=DEFAULT` (not UNLOCK) 3. Verify routing goes through the existing `AuthUser` path | Returns `ERR_OK`; plugin `Auth` invoked (not `AuthWithUnlockIntent`); `OnAcquireInfo` is NOT called | Level3 |

### AC-F3-1.2: Unbound domain account returns error

| Case ID | Test name | Test steps | Expected result | Level |
|---------|--------|----------|----------|------|
| F3-1.2 | `DomainAccountUnlock_005` | 1. Use a userId (e.g. 9999) not bound to a domain account 2. Call unlock authentication 3. Wait for callback | Returns an error (not `ERR_OK`); plugin is not invoked | Level3 |

### AC-F3-1.3: Unlock not enabled returns error

| Case ID | Test name | Test steps | Expected result | Level |
|---------|--------|----------|----------|------|
| F3-1.3 | `DomainAccountUnlock_004` | 1. Bind a domain account 2. Mock `enableUnlockDevice=false` 3. Call unlock authentication 4. Wait for callback | Returns `ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE`; plugin `AuthWithUnlockIntent` is not invoked | Level3 |

### AC-F3-1.7: Authentication failure does not perform unlock

| Case ID | Test name | Test steps | Expected result | Level |
|---------|--------|----------|----------|------|
| F3-1.7 | `DomainAccountUnlock_006` | 1. Bind a domain account + enable unlock 2. Mock plugin `AuthWithUnlockIntent` returns error (`SetAuthWithUnlockIntentError(true)`) 3. Call unlock authentication 4. Wait for callback | Returns an error (not `ERR_OK`); no storage unlock is performed; `OnAcquireInfo` is NOT called | Level3 |

### AC-F3-1.8: Account deactivating/locking does not perform unlock

| Case ID | Test name | Test steps | Expected result | Level |
|---------|--------|----------|----------|------|
| F3-1.8 | `DomainAccountUnlock_Deactivating_001` | 1. Bind a domain account + enable unlock 2. Mark account deactivating (`deactivatingAccounts_`) 3. Call unlock authentication (`authIntent=UNLOCK_INTENT`) | Returns `ERR_IAM_BUSY`; plugin `AuthWithUnlockIntent` is NOT invoked; authentication does not start | Level3 |
| F3-1.8 | `DomainAccountUnlock_Locking_001` | 1. Bind a domain account + enable unlock 2. Mark account locking (`lockingAccounts_`, `SUPPORT_LOCK_OS_ACCOUNT`) 3. Call unlock authentication | Returns `ERR_IAM_BUSY`; plugin `AuthWithUnlockIntent` is NOT invoked | Level3 |
| F3-1.8 | `DomainAccountUnlock_HandleUnlock_Deactivating_001` | 1. Bind a domain account + enable unlock 2. Start unlock authentication (mock plugin fires success callback after ~1s) 3. Mark the account deactivating in the callback window 4. Verify `HandleUnlockResult` short-circuits before `UnlockUserStorage` | Authentication succeeds (`ERR_OK`); `OnAcquireInfo` is called; no storage unlock is performed; `IsOsAccountVerified` stays false | Level3 |

### AC-F3-1.9: No plugin returns not supported

| Case ID | Test name | Test steps | Expected result | Level |
|---------|--------|----------|----------|------|
| F3-1.9 | `DomainAccountUnlock_003` | 1. Bind a domain account 2. `UnloadPluginMethods()` (`libHandle_=nullptr`) 3. Call unlock authentication (`authIntent=UNLOCK_INTENT`) 4. Wait for callback | Returns `ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE` | Level3 |

### AC-F3-2.1: DomainAccountClient direct entry does not unlock

| Case ID | Test name | Test steps | Expected result | Level |
|---------|--------|----------|----------|------|
| F3-2.1 | `DomainAccountUnlock_007` | 1. Bind a domain account 2. Call password-based `DomainAccountClient::AuthUser(userId, password, callback, contextId)` (direct-password overload, not the hook-based unlock overload) 3. Verify no storage unlock is performed | Authentication only; no storage unlock is performed | Level3 |

### Coverage notes

- All cases above are implemented in `domain_account_client_mock_plugin_so_module_test.cpp` as `HWTEST_F` with `TestSize.Level3`, using `mock_domain_so_plugin` + `condition_variable` synchronization.
- AC-F3-1.11 (challenge passthrough) and AC-F3-3.1 (`OnAcquireInfo`) are covered together by `DomainAccountUnlock_001`.
- AC-F3-2.2 (AccountIAMClient entry performs unlock): the unlock path that `AccountIAMClient::AuthUser` reaches via `StartDomainAuth` is exercised by `DomainAccountUnlock_001`; the explicit `AccountIAMClient`-side routing is covered by `account_iam_client_test.cpp`.
- AC-F3-1.4 / 1.5 / 1.6 (EL2/EL3/IsVerified on success) are implicitly exercised by the success path of `DomainAccountUnlock_001`; explicit mock-assertion of `UnlockUserStorage`/`UnlockEnhancedStorage`/`SetOsAccountIsVerified` is deferred to `domain_account_manager_inner_service_test.cpp`.
- AC-F3-1.10 (token/secret zeroing) is verified via code review + security scan (per spec.md NFR table), not a dedicated unit case.
- EX-F3-6 (storage unlock failure / 20×100ms retry): no explicit implemented case yet; deferred to `domain_account_manager_inner_service_test.cpp`.

## SetUp/TearDown Key Points

```cpp
// Use mock_domain_so_plugin pattern + Mock+Wrapper callback synchronization
void SetUp() {
    LoadPluginMethods();  // Inject mock containing AuthWithUnlockIntent + GetUnlockDeviceConfigResult

    // Register domainInputer (provides password)
    auto inputer = std::make_shared<MockDomainInputer>();
    AccountIAMClient::GetInstance().RegisterDomainInputer(inputer);

    // Storage-related mocks
    // Mock GetLockScreenStatus → returns locked
    // Mock ActivateUserKey → returns success
    // Mock UnlockUserScreen → returns success

    setuid(ROOT_UID);
}

void TearDown() {
    AccountIAMClient::GetInstance().UnregisterDomainInputer();
    UnloadPluginMethods();
}
```

## Async Callback Synchronization Pattern

```cpp
// UnlockAuthCallback (DomainAccountCallback subclass) waits for async result
auto callback = std::make_shared<UnlockAuthCallback>();

DomainAccountUnlockOptions options;
options.authIntent = UNLOCK_INTENT;
options.challenge = {1, 2, 3};
uint64_t contextId = 0;

// Trigger async unlock authentication (modified hook-based AuthUser overload)
ErrCode ret = DomainAccountClient::GetInstance().AuthUser(
    userId, []() { return std::vector<uint8_t>{49, 50, 51}; },
    callback, options, contextId);
EXPECT_EQ(ret, ERR_OK);

// Wait for callback
std::unique_lock<std::mutex> lock(callback->mutex);
callback->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME),
    [callback]() { return callback->isReady; });
ASSERT_TRUE(callback->isReady);
EXPECT_EQ(callback->resultErrCode, ERR_OK);
EXPECT_TRUE(callback->acquireInfoCalled);
```

## Cross-Feature Dependencies

```
F3 test dependencies:
├── F1: mock_domain_so_plugin has been extended with AuthWithUnlockIntent + GetUnlockDeviceConfigResult
└── F2: InnerDomainAccountManager::GetUnlockDeviceConfig internal method has been implemented
```

## BUILD.gn Changes

```
# domain_account_client_mock_plugin_so_module_test.cpp:
#   - mock_domain_so_plugin.cpp adds AuthWithUnlockIntent + GetUnlockDeviceConfigResult
#   - PLUGIN_METHOD_MAP adds 2 new mappings
#   - Tests the new call path after AuthUser signature change

# domain_account_manager_inner_service_test.cpp:
#   - Adds AuthUserWithUnlockOptions business logic tests
#   - Adds InnerDomainAuthCallback unlock logic tests

# account_iam_callback_test.cpp:
#   - Adds InnerDomainAuthCallback::OnResultWithUnlock unlock + zeroing tests

# account_iam_client_test.cpp:
#   - Adds DOMAIN+UNLOCK routing tests
```
