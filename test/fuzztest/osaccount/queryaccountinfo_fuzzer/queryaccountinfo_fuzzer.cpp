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

#include "queryaccountinfo_fuzzer.h"

#include "os_account_manager.h"
#include "account_log_wrapper.h"
#include "os_account_constants.h"
#include <cstdint>
#include <string>
#include <vector>

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
bool QueryActiveOsAccountIdsFuzzTest(const uint8_t* data, size_t size)
{
    int32_t result = ERR_OK;
    std::vector<int32_t> testIds;
    result = OsAccountManager::QueryActiveOsAccountIds(testIds);
    return result == ERR_OK;
}

bool QueryOsAccountConstraintSourceTypesFuzzTest(const uint8_t* data, size_t size)
{
    int32_t result = ERR_OK;
    if (size > 0) {
        std::vector<ConstraintSourceTypeInfo> testConstraintSourceTypeInfos;
        int testId = static_cast<int>(size);
        std::string testConstraint(reinterpret_cast<const char*>(data), size);
        result = OsAccountManager::QueryOsAccountConstraintSourceTypes(
            testId, testConstraint, testConstraintSourceTypeInfos);
    }
    return result == ERR_OK;
}

bool QueryOsAccountByIdFuzzTest(const uint8_t* data, size_t size)
{
    int32_t result = ERR_OK;
    if (size > 0) {
        int testId = static_cast<int>(size);
        OsAccountInfo osAccountInfo;
        result = OsAccountManager::QueryOsAccountById(testId, osAccountInfo);
    }
    return result == ERR_OK;
}

bool QueryMaxOsAccountNumberFuzzTest(const uint8_t* data, size_t size)
{
    int32_t result = ERR_OK;
    uint32_t testMaxOsAccountNumber;
    result = OsAccountManager::QueryMaxOsAccountNumber(testMaxOsAccountNumber);
    return result == ERR_OK;
}

bool QueryMaxLoggedInOsAccountNumberFuzzTest(const uint8_t* data, size_t size)
{
    uint32_t maxNum;
    ErrCode result = OsAccountManager::QueryMaxLoggedInOsAccountNumber(maxNum);
    return result == ERR_OK;
}

bool QueryCurrentOsAccountFuzzTest(const uint8_t* data, size_t size)
{
    int32_t result = ERR_OK;
    if (size > 0) {
        std::string testName(reinterpret_cast<const char*>(data), size);
        OsAccountInfo osAccountInfo;
        osAccountInfo.SetLocalName(testName);
        result = OsAccountManager::QueryCurrentOsAccount(osAccountInfo);
    }
    return result == ERR_OK;
}

bool QueryAllCreatedOsAccountsFuzzTest(const uint8_t* data, size_t size)
{
    int32_t result = ERR_OK;
    std::vector<OsAccountInfo> osAccountInfos;
    result = OsAccountManager::QueryAllCreatedOsAccounts(osAccountInfos);
    return result == ERR_OK;
}
} // namespace

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::QueryActiveOsAccountIdsFuzzTest(data, size);
    OHOS::QueryOsAccountConstraintSourceTypesFuzzTest(data, size);
    OHOS::QueryOsAccountByIdFuzzTest(data, size);
    OHOS::QueryMaxOsAccountNumberFuzzTest(data, size);
    OHOS::QueryMaxLoggedInOsAccountNumberFuzzTest(data, size);
    OHOS::QueryCurrentOsAccountFuzzTest(data, size);
    OHOS::QueryAllCreatedOsAccountsFuzzTest(data, size);
    return 0;
}

