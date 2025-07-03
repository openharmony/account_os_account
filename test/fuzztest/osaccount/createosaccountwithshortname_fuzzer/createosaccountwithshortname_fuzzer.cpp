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

#include "createosaccountwithshortname_fuzzer.h"

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

OsAccountType GetAccountType(FuzzData& fuzzData, bool useValid)
{
    if (useValid) {
        return OsAccountType::NORMAL;
    }
    return static_cast<OsAccountType>(fuzzData.GetData<uint32_t>() % MAX_ACCOUNT_TYPE_COUNT);
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
    std::string accountName = fuzzData.GenerateString();
    std::string shortName = fuzzData.GenerateString();

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

}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::CreateOsAccountWithShortNameFuzzTest(data, size);
    return 0;
}
