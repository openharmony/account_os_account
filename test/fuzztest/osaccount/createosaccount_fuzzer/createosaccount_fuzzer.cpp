/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#undef private
#include "os_account_constants.h"
#include "securec.h"

using namespace std;
using namespace OHOS::AccountSA;
namespace OHOS {
const int CONSTANTS_NUMBER_FIVE = 5;
const int LIST_NUMBER_LIMIT = 1002;
const int HAP_NAME_LENGTH_LIMIT = 1000;
const uint8_t *g_baseFuzzData = nullptr;
size_t g_baseFuzzSize = 0;
size_t g_baseFuzzPos;

template <class T> T GetData()
{
    T object{};
    size_t objectSize = sizeof(object);
    if (g_baseFuzzData == nullptr || objectSize > g_baseFuzzSize - g_baseFuzzPos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, g_baseFuzzData + g_baseFuzzPos, objectSize);
    if (ret != EOK) {
        return {};
    }
    g_baseFuzzPos += objectSize;
    return object;
}

bool CreateOsAccountWithShortNameFuzzTest(const uint8_t* data, size_t size)
{
    bool result = false;
    if ((data != nullptr) && (size != 0)) {
        FuzzData fuzzData(data, size);
        OsAccountInfo osAccountInfoOne;
        OsAccountType testType = static_cast<OsAccountType>(fuzzData.GetData<uint32_t>() % CONSTANTS_NUMBER_FIVE);
        std::string accountName(fuzzData.GenerateString());
        std::string shortName(fuzzData.GenerateString());
        result = OsAccountManager::CreateOsAccount(accountName, shortName, testType, osAccountInfoOne);
        if (result == ERR_OK) {
            ACCOUNT_LOGI("CreateOsAccountWithShortNameFuzzTest RemoveOsAccount");
            OsAccountManager::RemoveOsAccount(osAccountInfoOne.GetLocalId());
        }
        uint32_t listSize = fuzzData.GetData<uint32_t>();
        CreateOsAccountOptions options;
        for (uint32_t i = 0; i < listSize % LIST_NUMBER_LIMIT; i++) {
            uint32_t hapNameSize = fuzzData.GetData<uint32_t>();
            std::string hapName(fuzzData.GetStringFromData(0, hapNameSize % HAP_NAME_LENGTH_LIMIT));
            options.disallowedHapList.push_back(hapName);
        }
        result = OsAccountManager::CreateOsAccount(accountName, shortName, testType, options, osAccountInfoOne);
        if (result == ERR_OK) {
            ACCOUNT_LOGI("CreateOsAccountWithShortNameFuzzTest RemoveOsAccount");
            OsAccountManager::RemoveOsAccount(osAccountInfoOne.GetLocalId());
        }
    }
    return result;
}

bool CreateOsAccountFuzzTest(const uint8_t* data, size_t size)
{
    bool result = false;
    if ((data != nullptr) && (size != 0)) {
        FuzzData fuzzData(data, size);
        OsAccountInfo osAccountInfoOne;
        OsAccountType testType = static_cast<OsAccountType>(fuzzData.GetData<uint32_t>() % CONSTANTS_NUMBER_FIVE);
        std::string accountName(fuzzData.GenerateString());
        result = OsAccountManager::CreateOsAccount(accountName, testType, osAccountInfoOne);
        if (result == ERR_OK) {
            ACCOUNT_LOGI("CreateOsAccountFuzzTest RemoveOsAccount");
            OsAccountManager::RemoveOsAccount(osAccountInfoOne.GetLocalId());
        }
    }
    return result;
}

bool CreateOsAccountForDomainFuzzTest(const uint8_t* data, size_t size)
{
    bool result = false;
    if ((data != nullptr) && (size != 0)) {
        FuzzData fuzzData(data, size);
        std::string accountName(fuzzData.GenerateString());
        std::string domain(fuzzData.GenerateString());
        DomainAccountInfo domainInfo(accountName, domain);
        OsAccountType testType = static_cast<OsAccountType>(fuzzData.GetData<uint32_t>() % CONSTANTS_NUMBER_FIVE);
        OsAccountInfo osAccountInfo;
        result = OsAccountManager::CreateOsAccountForDomain(testType, domainInfo, nullptr);
        if (result == ERR_OK) {
            ACCOUNT_LOGI("CreateOsAccountForDomainFuzzTest RemoveOsAccount");
            OsAccountManager::RemoveOsAccount(osAccountInfo.GetLocalId());
        }
    }
    return result;
}

bool UpdateOsAccountWithFullInfoFuzzTest(const uint8_t* data, size_t size)
{
    bool result = false;
    if ((data != nullptr) && (size != 0)) {
        FuzzData fuzzData(data, size);
        OsAccountInfo osAccountInfo;
        osAccountInfo.SetLocalName(fuzzData.GenerateString());
        osAccountInfo.SetLocalId(fuzzData.GetData<int64_t>());
        osAccountInfo.SetSerialNumber(fuzzData.GetData<int64_t>());
        osAccountInfo.SetCreateTime(fuzzData.GetData<int64_t>());
        osAccountInfo.SetLastLoginTime(fuzzData.GetData<int64_t>());
        result = OsAccountManager::UpdateOsAccountWithFullInfo(osAccountInfo);
        if (result == ERR_OK) {
            ACCOUNT_LOGI("CreateOsAccountFuzzTest RemoveOsAccount");
            OsAccountManager::RemoveOsAccount(osAccountInfo.GetLocalId());
        }
    }
    return result;
}

bool CreateOsAccountWithFullInfoFuzzTest(const uint8_t* data, size_t size)
{
    bool result = false;
    if ((data != nullptr) && (size != 0)) {
        FuzzData fuzzData(data, size);
        OsAccountInfo osAccountInfo;
        osAccountInfo.SetLocalName(fuzzData.GenerateString());
        osAccountInfo.SetLocalId(fuzzData.GetData<int64_t>());
        osAccountInfo.SetSerialNumber(fuzzData.GetData<int64_t>());
        osAccountInfo.SetCreateTime(fuzzData.GetData<int64_t>());
        osAccountInfo.SetLastLoginTime(fuzzData.GetData<int64_t>());
        result = OsAccountManager::CreateOsAccountWithFullInfo(osAccountInfo);
        if (result == ERR_OK) {
            ACCOUNT_LOGI("CreateOsAccountFuzzTest RemoveOsAccount");
            OsAccountManager::RemoveOsAccount(osAccountInfo.GetLocalId());
        }
    }
    return result;
}

bool CheckOsAccountConstraintEnabledFuzzTest(const uint8_t* data, size_t size)
{
    bool result = false;
    if ((data != nullptr) && (size != 0)) {
        FuzzData fuzzData(data, size);
        int32_t userId = fuzzData.GetData<int32_t>();
        std::string constraintStr(fuzzData.GenerateString());
        bool isEnabled = false;
        result = OsAccountManager::CheckOsAccountConstraintEnabled(userId, constraintStr, isEnabled);
    }
    return result;
}
} // namespace

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::CreateOsAccountWithShortNameFuzzTest(data, size);
    OHOS::CreateOsAccountFuzzTest(data, size);
    OHOS::CreateOsAccountForDomainFuzzTest(data, size);
    OHOS::UpdateOsAccountWithFullInfoFuzzTest(data, size);
    OHOS::CreateOsAccountWithFullInfoFuzzTest(data, size);
    OHOS::CheckOsAccountConstraintEnabledFuzzTest(data, size);
    return 0;
}

