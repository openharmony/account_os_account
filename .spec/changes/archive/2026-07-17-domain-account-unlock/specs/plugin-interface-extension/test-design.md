# F1 Plugin Interface Extension — Test Case Design

> Test cases designed based on spec.md ACs. Follows existing test patterns: HWTEST_F + Mock+Wrapper + mock_domain_so_plugin.

## Test Files and Targets

| Test file | Test target | BUILD.gn target |
|----------|----------|---------------|
| `services/accountmgr/test/unittest/domain_account/domain_plugin_adapter_test.cpp` | LoadPlugin, GetAndCleanPluginAuthResultInfo, GetAndCleanPluginUnlockDeviceConfigResult | `ohos_unittest("domain_plugin_adapter_test")` |
| `frameworks/domain_account/test/moduletest/src/domain_account_common_test.cpp` | DomainAccountUnlockOptions serialization, DomainAuthResult.secret | `ohos_moduletest("domain_account_frameworks_module_mock_test")` |
| `frameworks/account_iam/test/unittest/src/account_iam_callback_service_test.cpp` | DomainAuthCallbackAdapter ATTR_ROOT_SECRET (assert NOT set) | `ohos_unittest("account_iam_callback_service_test")` |
| `frameworks/domain_account/test/moduletest/src/mock_domain_so_plugin.cpp` | AuthWithUnlockIntent, GetUnlockDeviceConfigResult mock | Dependency target |

## Test Constants

```cpp
const std::vector<uint8_t> TEST_SECRET = {10, 20, 30, 40, 50};
const std::vector<uint8_t> TEST_CHALLENGE = {1, 2, 3, 4, 5, 6, 7, 8};
const int32_t TEST_AUTH_INTENT_UNLOCK = 1;  // AuthIntent::UNLOCK
const int32_t TEST_UNLOCK_MODE_OFFLINE = 1;  // OFFLINE_AUTH_UNLOCK_DEVICE
const int32_t TEST_UNLOCK_MODE_ONLINE_OFFLINE = 2;  // ONLINE_OFFLINE_AUTH_UNLOCK_DEVICE
```

## Test Cases

### AC-F1-1.1: PluginAuthResultInfo contains accountToken and secret

| Case ID | Test name | Test steps | Expected result | Level |
|---------|--------|----------|----------|------|
| F1-1.1-001 | `PluginAuthResultInfo_SecretField_001` | 1. Construct `PluginAuthResultInfo` and set `accountToken` and `secret` 2. Verify both fields are readable/writable | `accountToken` and `secret` values are correct | Level0 |
| F1-1.1-002 | `PluginAuthResultInfo_SecretField_002` | 1. Mock plugin `AuthWithUnlockIntent` returns `PluginAuthResultInfo` containing `secret` 2. Verify via callback | `authResultInfo->secret` received by callback is non-empty and correct | Level0 |

### AC-F1-1.2: GetAndCleanPluginAuthResultInfo extracts secret

| Case ID | Test name | Test steps | Expected result | Level |
|---------|--------|----------|----------|------|
| F1-1.2-001 | `GetAndCleanPluginAuthResultInfo_Secret_001` | 1. Construct `PluginAuthResultInfo` (with `accountToken` + `secret`) 2. Call `GetAndCleanPluginAuthResultInfo` 3. Verify `DomainAuthResult.token` and `DomainAuthResult.secret` | `token` is populated from `accountToken`; `secret` is populated from `secret`; values are correct | Level0 |
| F1-1.2-002 | `GetAndCleanPluginAuthResultInfo_Secret_002` | 1. Construct `PluginAuthResultInfo` (`secret` is empty) 2. Call `GetAndCleanPluginAuthResultInfo` 3. Verify `DomainAuthResult.secret` | `secret` is an empty vector; no crash | Level1 |
| F1-1.2-003 | `GetAndCleanPluginAuthResultInfo_Free_001` | 1. Call `GetAndCleanPluginAuthResultInfo` 2. Verify `PluginAuthResultInfo` is `free`d | No memory leak | Level2 |

### AC-F1-1.3: DomainAuthCallbackAdapter does NOT set ATTR_ROOT_SECRET

| Case ID | Test name | Test steps | Expected result | Level |
|---------|--------|----------|----------|------|
| F1-1.3-001 | `DomainAuthCallbackAdapter_AttrRootSecret_001` | 1. Construct `DomainAuthResult` (with `secret`) 2. Call `DomainAuthCallbackAdapter::OnResult` 3. Verify `IDMCallback::OnResult` receives `Attributes` that does NOT contain `ATTR_ROOT_SECRET` | `ATTR_ROOT_SECRET` is NOT set; `secret` is only used at the service layer for unlock storage | Level0 |
| F1-1.3-002 | `DomainAuthCallbackAdapter_AttrRootSecret_002` | 1. Construct `DomainAuthResult` (`secret` is empty) 2. Call `OnResult` 3. Verify `ATTR_ROOT_SECRET` is NOT set | `ATTR_ROOT_SECRET` is NOT set; no crash | Level1 |

### AC-F1-2.1: GetUnlockDeviceConfigResult returns config

| Case ID | Test name | Test steps | Expected result | Level |
|---------|--------|----------|----------|------|
| F1-2.1-001 | `MockPlugin_GetUnlockDeviceConfig_001` | 1. Set mock plugin `GetUnlockDeviceConfigResult` to return `enableUnlockDevice=1, unlockDeviceMode=2` 2. Inject via `LoadPluginMethods` 3. Call query | Return values are correct | Level0 |
| F1-2.1-002 | `MockPlugin_GetUnlockDeviceConfig_002` | 1. Set mock to return `enableUnlockDevice=0, unlockDeviceMode=0` 2. Call query | Return values are correct | Level1 |

### AC-F1-2.2: GetAndCleanPluginUnlockDeviceConfigResult converts and frees

| Case ID | Test name | Test steps | Expected result | Level |
|---------|--------|----------|----------|------|
| F1-2.2-001 | `GetAndCleanPluginUnlockDeviceConfigResult_001` | 1. Construct `PluginUnlockDeviceConfigResult` 2. Call `GetAndCleanPluginUnlockDeviceConfigResult` 3. Verify `enableUnlockDevice` and `unlockDeviceMode` are converted correctly | Values are correct | Level0 |
| F1-2.2-002 | `GetAndCleanPluginUnlockDeviceConfigResult_Free` | 1. Call `GetAndCleanPluginUnlockDeviceConfigResult` 2. Verify `PluginUnlockDeviceConfigResult` is `free`d | No memory leak | Level2 |

### AC-F1-3.1~3.2: DomainAccountUnlockOptions IDL conversion

| Case ID | Test name | Test steps | Expected result | Level |
|---------|--------|----------|----------|------|
| F1-3.1-001 | `DomainAccountUnlockOptions_IdlConversion_001` | 1. Construct `DomainAccountUnlockOptions` (`challenge=TEST_CHALLENGE, authIntent=1`) 2. Convert to `DomainAccountUnlockOptionsIdl` 3. Convert back 4. Verify field values | `challenge` and `authIntent` are consistent | Level0 |
| F1-3.1-002 | `DomainAccountUnlockOptions_IdlConversion_002` | 1. Construct `DomainAccountUnlockOptions` (`challenge` is empty) 2. Convert to/from `DomainAccountUnlockOptionsIdl` 3. Verify | `challenge` is empty; no crash | Level1 |
| F1-3.2-001 | `DomainAccountUnlockOptions_IdlRoundTrip_001` | 1. Construct `DomainAccountUnlockOptionsIdl` with specific data 2. Convert to `DomainAccountUnlockOptions` 3. Verify fields | Field values are correct | Level1 |

### AC-F1-4.1~4.3: LoadPlugin loads new symbols

| Case ID | Test name | Test steps | Expected result | Level |
|---------|--------|----------|----------|------|
| F1-4.1-001 | `PluginMethodEnum_NewValues_001` | 1. Check that `PluginMethodEnum` contains `AUTH_WITH_UNLOCK_INTENT` and `GET_UNLOCK_DEVICE_CONFIG` | Enum values exist | Level0 |
| F1-4.2-001 | `LoadPlugin_NewSymbols_001` | 1. Mock plugin exports `AuthWithUnlockIntent` and `GetUnlockDeviceConfigResult` 2. Inject via `LoadPluginMethods` 3. Verify `methodMap_` contains the new enums | `methodMap_` contains `AUTH_WITH_UNLOCK_INTENT` and `GET_UNLOCK_DEVICE_CONFIG` | Level0 |
| F1-4.3-001 | `LoadPlugin_MissingSymbols_001` | 1. Mock plugin does not export the new symbols 2. Call `LoadPlugin` (using mock_musl) 3. Verify load failure | `libHandle_` is nullptr; load fails | Level0 |

## SetUp/TearDown Key Points

```cpp
// Use mock_domain_so_plugin pattern
void SetUp() {
    LoadPluginMethods();  // Inject mock method map (including new functions)
    setuid(ROOT_UID);
}

void TearDown() {
    UnloadPluginMethods();  // Clean up libHandle_ and methodMap_
}
```

## BUILD.gn Changes

```
# domain_plugin_adapter_test.cpp adds test cases, no new source files needed
# mock_domain_so_plugin.cpp adds AuthWithUnlockIntent + GetUnlockDeviceConfigResult mock functions
# PLUGIN_METHOD_MAP adds 2 new mappings
# domain_account_common_test.cpp adds DomainAccountUnlockOptions IDL conversion tests
```
