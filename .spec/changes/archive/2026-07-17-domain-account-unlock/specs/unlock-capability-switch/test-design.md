# F2 Domain Account Unlock Capability Switch — Test Case Design

> Test cases designed based on spec.md ACs. Follows existing test patterns: HWTEST_F + Mock+Wrapper + mock_domain_so_plugin.

## Test Files and Targets

| Test file | Test target | BUILD.gn target |
|----------|----------|---------------|
| `services/accountmgr/test/unittest/account_iam/account_iam_service_test.cpp` | SetDomainAuthUnlockEnabled permission check | `ohos_unittest("account_iam_service_test")` |
| `services/accountmgr/test/unittest/account_iam/account_iam_manager_test.cpp` | SetDomainAuthUnlockEnabled business logic | `ohos_unittest("account_iam_manager_test")` |
| `services/accountmgr/test/unittest/domain_account/domain_account_manager_inner_service_test.cpp` | GetUnlockDeviceConfig internal query | `ohos_unittest("domain_account_manager_inner_service_test")` |
| `services/accountmgr/test/unittest/account_iam/account_iam_callback_test.cpp` | PIN add/delete flow adaptation | `ohos_unittest("account_iam_callback_test")` |

## Test Constants

```cpp
const int32_t DOMAIN_AUTH_SERVICE_UID = 7058;
const int32_t NON_AUTH_SERVICE_UID = 3058;
const std::vector<uint8_t> TEST_TOKEN = {1, 2, 3, 4, 5};
const std::vector<uint8_t> TEST_SECRET = {10, 20, 30, 40, 50};
const int32_t TEST_UNLOCK_MODE_OFFLINE = 1;
const int32_t TEST_UNLOCK_MODE_ONLINE_OFFLINE = 2;
```

## Test Cases

### AC-F2-1.1: Enable domain account unlock (normal flow)

| Case ID | Test name | Test steps | Expected result | Level |
|---------|--------|----------|----------|------|
| F2-1.1-001 | `SetDomainAuthUnlockEnabled_Enable_001` | 1. `setuid(7058)` + grant `MANAGE_USER_IDM` 2. Create and bind a domain account user 3. Mock `VerifyAuthToken` returns success 4. Mock storage has no existing key 5. Call `SetDomainAuthUnlockEnabled(localId, token, secret, true)` | Returns `ERR_OK`; `UpdateStorageUserAuth` is invoked | Level0 |
| F2-1.1-002 | `SetDomainAuthUnlockEnabled_Enable_002` | 1. Same as above 2. Mock storage has an existing key 3. Call enable | Returns `ERR_OK`; `UpdateStorageUserAuth` is not invoked (key already exists) | Level1 |

### AC-F2-1.2: uid not 7058 is rejected

| Case ID | Test name | Test steps | Expected result | Level |
|---------|--------|----------|----------|------|
| F2-1.2-001 | `SetDomainAuthUnlockEnabled_UidCheck_001` | 1. `setuid(3058)` 2. Call `SetDomainAuthUnlockEnabled` | Returns permission error | Level0 |
| F2-1.2-002 | `SetDomainAuthUnlockEnabled_UidCheck_002` | 1. `setuid(0)` (root) 2. Call | Returns permission error (root is not 7058) | Level1 |

### AC-F2-1.3: Missing MANAGE_USER_IDM permission is rejected

| Case ID | Test name | Test steps | Expected result | Level |
|---------|--------|----------|----------|------|
| F2-1.3-001 | `SetDomainAuthUnlockEnabled_PermissionCheck_001` | 1. `setuid(7058)` 2. Do not grant `MANAGE_USER_IDM` 3. Call | Returns permission error | Level0 |

### AC-F2-1.4: localId does not exist or is not bound to a domain account

| Case ID | Test name | Test steps | Expected result | Level |
|---------|--------|----------|----------|------|
| F2-1.4-001 | `SetDomainAuthUnlockEnabled_LocalIdCheck_001` | 1. `setuid(7058)` + permission 2. Pass in a non-existent localId 3. Call | Returns `ERR_DOMAIN_ACCOUNT_SERVICE_NOT_DOMAIN_ACCOUNT` | Level0 |
| F2-1.4-002 | `SetDomainAuthUnlockEnabled_LocalIdCheck_002` | 1. Pass in an existing localId that is not bound to a domain account 2. Call | Returns `ERR_DOMAIN_ACCOUNT_SERVICE_NOT_DOMAIN_ACCOUNT` | Level0 |

### AC-F2-1.5: Invalid token

| Case ID | Test name | Test steps | Expected result | Level |
|---------|--------|----------|----------|------|
| F2-1.5-001 | `SetDomainAuthUnlockEnabled_TokenCheck_001` | 1. Normal uid + permission + bound domain account 2. Mock `VerifyAuthToken` returns failure 3. Call | Returns authentication token error | Level0 |
| F2-1.5-002 | `SetDomainAuthUnlockEnabled_TokenCheck_002` | 1. Pass in an empty token 2. Call | Returns error | Level1 |

### AC-F2-1.6~1.8: Disable flow

| Case ID | Test name | Test steps | Expected result | Level |
|---------|--------|----------|----------|------|
| F2-1.7-001 | `SetDomainAuthUnlockEnabled_Disable_001` | 1. Normal uid + permission + bound domain account 2. Mock a PIN credential exists 3. Call `SetDomainAuthUnlockEnabled(localId, token, secret, false)` | Returns `ERR_OK`; `UpdateStorageUserAuth` is not invoked (the PIN-managed key is not interfered with) | Level0 |
| F2-1.8-001 | `SetDomainAuthUnlockEnabled_Disable_002` | 1. Normal uid + permission + bound domain account 2. Mock no PIN credential exists 3. Call `SetDomainAuthUnlockEnabled(localId, token, secret, false)` | Returns `ERR_ACCOUNT_IAM_NO_CREDENTIAL` (intercepted; disabling with no PIN is meaningless) | Level1 |

### AC-F2-1.9: No plugin returns not supported

| Case ID | Test name | Test steps | Expected result | Level |
|---------|--------|----------|----------|------|
| F2-1.9-001 | `SetDomainAuthUnlockEnabled_NoPlugin_001` | 1. `UnloadPluginMethods()` (`libHandle_=nullptr`) 2. Normal uid + permission 3. Call | Returns `ERR_DOMAIN_ACCOUNT_NOT_SUPPORT` | Level0 |

### AC-F2-2.1~2.2: GetUnlockDeviceConfig internal query

| Case ID | Test name | Test steps | Expected result | Level |
|---------|--------|----------|----------|------|
| F2-2.1-001 | `GetUnlockDeviceConfig_WithPlugin_001` | 1. `LoadPluginMethods()` 2. Mock plugin `GetUnlockDeviceConfigResult` returns `enable=1, mode=2` 3. Call `InnerDomainAccountManager::GetUnlockDeviceConfig(userId)` | Returns `ERR_OK`; `enableUnlockDevice=true`, `unlockDeviceMode=2` | Level0 |
| F2-2.1-002 | `GetUnlockDeviceConfig_WithPlugin_002` | 1. Mock returns `enable=0, mode=1` 2. Call | Returns `ERR_OK`; `enableUnlockDevice=false`, `unlockDeviceMode=1` | Level1 |
| F2-2.2-001 | `GetUnlockDeviceConfig_NoPlugin_001` | 1. `UnloadPluginMethods()` 2. Call `GetUnlockDeviceConfig` | Returns `ERR_OK`; `enableUnlockDevice=false` (default) | Level0 |

### AC-F2-3.1~3.3: PIN add flow adaptation

| Case ID | Test name | Test steps | Expected result | Level |
|---------|--------|----------|----------|------|
| F2-3.1-001 | `AddCredCallback_DomainUnlockEnabled_001` | 1. `LoadPluginMethods()` 2. Mock `GetUnlockDeviceConfigResult` returns `enable=1, mode=2` 3. Construct `AddCredCallback` (PIN type) 4. Call `OnResult(ERR_OK, extraInfo)` containing credentialId/secureUid/newSecret/token 5. Verify `UpdateStorageUserAuth` is not invoked | Storage key addition is skipped | Level0 |
| F2-3.2-001 | `AddCredCallback_DomainUnlockDisabled_001` | 1. Mock returns `enable=0, mode=1` 2. Same as above 3. Verify `UpdateStorageUserAuth` is invoked | Storage key addition proceeds normally | Level0 |
| F2-3.2-002 | `AddCredCallback_OfflineMode_001` | 1. Mock returns `enable=1, mode=1` (OFFLINE) 2. Verify `UpdateStorageUserAuth` is invoked | Storage key addition proceeds normally (OFFLINE mode is not skipped) | Level1 |
| F2-3.3-001 | `AddCredCallback_NoPlugin_001` | 1. `UnloadPluginMethods()` 2. Construct `AddCredCallback` (PIN) 3. Call `OnResult(ERR_OK, ...)` 4. Verify `UpdateStorageUserAuth` is invoked | Proceeds with normal storage key management | Level0 |

### AC-F2-4.1~4.2: PIN delete flow adaptation

| Case ID | Test name | Test steps | Expected result | Level |
|---------|--------|----------|----------|------|
| F2-4.1-001 | `DelCred_DomainUnlockEnabled_001` | 1. `LoadPluginMethods()` 2. Mock returns `enable=1, mode=2` 3. Construct `VerifyTokenCallbackWrapper` 4. `VerifyAuthToken` succeeds 5. Call `InnerOnResult(ERR_OK, extraInfo)` containing secureUid/rootSecret 6. Verify `UpdateStorageUserAuth` is not invoked | Storage key deletion is skipped | Level0 |
| F2-4.2-001 | `DelCred_DomainUnlockDisabled_001` | 1. Mock returns `enable=0` 2. Same as above 3. Verify `UpdateStorageUserAuth` is invoked | Storage key deletion proceeds normally | Level0 |

## SetUp/TearDown Key Points

```cpp
void SetUp() {
    // Set accountmgr token
    g_accountMgrTokenID = GetTokenIdFromProcess("accountmgr");
    SetSelfTokenID(g_accountMgrTokenID);

    // Inject mock plugin
    LoadPluginMethods();
    setuid(ROOT_UID);
}

void TearDown() {
    UnloadPluginMethods();
    // Clean up test accounts
}
```

## Permission Setup Pattern

```cpp
// Grant MANAGE_USER_IDM permission
AccessTokenID tokenID = AllocPermission({"ohos.permission.MANAGE_USER_IDM"}, 7058);
SetSelfTokenID(tokenID);
setuid(7058);
```
