/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "createosaccount_fuzzer.h"

#include <cstdint>
#include <string>
#include <vector>
#include "os_account_manager.h"
#include "account_log_wrapper.h"
#include "fuzz_data.h"
#include "os_account_constants.h"
#include "securec.h"

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
constexpr uint32_t MAX_ACCOUNT_TYPE_COUNT = 5;
constexpr uint32_t MAX_HAP_LIST_SIZE = 1002;
constexpr uint32_t MAX_HAP_NAME_LENGTH = 1000;
constexpr int32_t DEFAULT_TEST_USER_ID = 100;
constexpr int32_t TEST_USER_ID_1001 = 1001;
constexpr int32_t TEST_USER_ID_1002 = 1002;
constexpr int64_t TEST_TIMESTAMP_2022 = 1640995200;

OsAccountType GetAccountType(FuzzData& fuzzData, bool useValid)
{
    if (useValid) {
        return OsAccountType::NORMAL;
    }
    return static_cast<OsAccountType>(fuzzData.GetData<uint32_t>() % MAX_ACCOUNT_TYPE_COUNT);
}

std::string GetAccountName(FuzzData& fuzzData, bool useValid, const std::string& defaultName = "TestUser")
{
    return useValid ? defaultName : fuzzData.GenerateString();
}

int32_t GetUserId(FuzzData& fuzzData, bool useValid, int32_t defaultId = DEFAULT_TEST_USER_ID)
{
    return useValid ? defaultId : fuzzData.GetData<int32_t>();
}

int64_t GetTimestamp(FuzzData& fuzzData, bool useValid, int64_t defaultTime = TEST_TIMESTAMP_2022)
{
    return useValid ? defaultTime : fuzzData.GetData<int64_t>();
}

bool CreateOsAccountWithShortNameFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzData fuzzData(data, size);
    
    bool useValidParams = fuzzData.GetData<bool>();
    
    OsAccountInfo osAccountInfoOne;
    OsAccountType testType = GetAccountType(fuzzData, useValidParams);
    std::string accountName = GetAccountName(fuzzData, useValidParams, "TestUser");
    std::string shortName = GetAccountName(fuzzData, useValidParams, "Test");
    
    int32_t result = OsAccountManager::CreateOsAccount(accountName, shortName, testType, osAccountInfoOne);
    if (result == ERR_OK) {
        ACCOUNT_LOGI("CreateOsAccountWithShortNameFuzzTest RemoveOsAccount");
        OsAccountManager::RemoveOsAccount(osAccountInfoOne.GetLocalId());
    }
    
    CreateOsAccountOptions options;
    if (useValidParams) {
        options.disallowedHapList.push_back("com.example.test");
        options.disallowedHapList.push_back("com.example.demo");
    } else {
        uint32_t listSize = fuzzData.GetData<uint32_t>() % MAX_HAP_LIST_SIZE;
        for (uint32_t i = 0; i < listSize; i++) {
            uint32_t hapNameSize = fuzzData.GetData<uint32_t>() % MAX_HAP_NAME_LENGTH;
            std::string hapName = fuzzData.GetStringFromData(0, hapNameSize);
            options.disallowedHapList.push_back(hapName);
        }
    }
    
    result = OsAccountManager::CreateOsAccount(accountName, shortName, testType, options, osAccountInfoOne);
    if (result == ERR_OK) {
        ACCOUNT_LOGI("CreateOsAccountWithShortNameFuzzTest with options RemoveOsAccount");
        OsAccountManager::RemoveOsAccount(osAccountInfoOne.GetLocalId());
    }
    
    return result == ERR_OK;
}

bool CreateOsAccountFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzData fuzzData(data, size);
    bool useValidParams = fuzzData.GetData<bool>();
    
    OsAccountInfo osAccountInfoOne;
    OsAccountType testType = GetAccountType(fuzzData, useValidParams);
    std::string accountName = GetAccountName(fuzzData, useValidParams, "NormalFuzzTestUser");
    
    int32_t result = OsAccountManager::CreateOsAccount(accountName, testType, osAccountInfoOne);
    if (result == ERR_OK) {
        ACCOUNT_LOGI("CreateOsAccountFuzzTest RemoveOsAccount");
        OsAccountManager::RemoveOsAccount(osAccountInfoOne.GetLocalId());
    }
    
    return result == ERR_OK;
}

bool CreateOsAccountForDomainFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzData fuzzData(data, size);
    bool useValidParams = fuzzData.GetData<bool>();
    
    std::string accountName = useValidParams ? "domain.user" : fuzzData.GenerateString();
    std::string domain = useValidParams ? "example.com" : fuzzData.GenerateString();
    DomainAccountInfo domainInfo(accountName, domain);
    OsAccountType testType = GetAccountType(fuzzData, useValidParams);
    OsAccountInfo osAccountInfo;
    
    int32_t result = OsAccountManager::CreateOsAccountForDomain(testType, domainInfo, nullptr);
    if (result == ERR_OK) {
        ACCOUNT_LOGI("CreateOsAccountForDomainFuzzTest RemoveOsAccount");
        OsAccountManager::RemoveOsAccount(osAccountInfo.GetLocalId());
    }
    
    return result == ERR_OK;
}

bool UpdateOsAccountWithFullInfoFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzData fuzzData(data, size);
    bool useValidParams = fuzzData.GetData<bool>();
    
    OsAccountInfo osAccountInfo;
    osAccountInfo.SetLocalName(GetAccountName(fuzzData, useValidParams, "UpdateTestUser"));
    osAccountInfo.SetLocalId(GetUserId(fuzzData, useValidParams, TEST_USER_ID_1001));
    osAccountInfo.SetSerialNumber(GetUserId(fuzzData, useValidParams, TEST_USER_ID_1001));
    osAccountInfo.SetCreateTime(GetTimestamp(fuzzData, useValidParams));
    osAccountInfo.SetLastLoginTime(GetTimestamp(fuzzData, useValidParams));
    
    int32_t result = OsAccountManager::UpdateOsAccountWithFullInfo(osAccountInfo);
    if (result == ERR_OK) {
        ACCOUNT_LOGI("UpdateOsAccountWithFullInfoFuzzTest RemoveOsAccount");
        OsAccountManager::RemoveOsAccount(osAccountInfo.GetLocalId());
    }
    
    return result == ERR_OK;
}

bool CreateOsAccountWithFullInfoFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzData fuzzData(data, size);
    bool useValidParams = fuzzData.GetData<bool>();
    
    OsAccountInfo osAccountInfo;
    osAccountInfo.SetLocalName(GetAccountName(fuzzData, useValidParams, "FullInfoTestUser"));
    osAccountInfo.SetLocalId(GetUserId(fuzzData, useValidParams, TEST_USER_ID_1002));
    osAccountInfo.SetSerialNumber(GetUserId(fuzzData, useValidParams, TEST_USER_ID_1002));
    osAccountInfo.SetCreateTime(GetTimestamp(fuzzData, useValidParams));
    osAccountInfo.SetLastLoginTime(GetTimestamp(fuzzData, useValidParams));
    
    int32_t result = OsAccountManager::CreateOsAccountWithFullInfo(osAccountInfo);
    if (result == ERR_OK) {
        ACCOUNT_LOGI("CreateOsAccountWithFullInfoFuzzTest RemoveOsAccount");
        OsAccountManager::RemoveOsAccount(osAccountInfo.GetLocalId());
    }
    
    return result == ERR_OK;
}

bool CheckOsAccountConstraintEnabledFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzData fuzzData(data, size);
    bool useValidParams = fuzzData.GetData<bool>();
    
    int32_t userId = GetUserId(fuzzData, useValidParams, DEFAULT_TEST_USER_ID);
    std::string constraintStr = useValidParams ? "constraint.print" : fuzzData.GenerateString();
    bool isEnabled = false;
    
    int32_t result = OsAccountManager::CheckOsAccountConstraintEnabled(userId, constraintStr, isEnabled);
    
    return result == ERR_OK;
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::CreateOsAccountWithShortNameFuzzTest(data, size);
    OHOS::CreateOsAccountFuzzTest(data, size);
    OHOS::CreateOsAccountForDomainFuzzTest(data, size);
    OHOS::UpdateOsAccountWithFullInfoFuzzTest(data, size);
    OHOS::CreateOsAccountWithFullInfoFuzzTest(data, size);
    OHOS::CheckOsAccountConstraintEnabledFuzzTest(data, size);
    return 0;
}