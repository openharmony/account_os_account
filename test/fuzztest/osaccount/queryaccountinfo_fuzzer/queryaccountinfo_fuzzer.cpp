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
#include "fuzz_data.h"
#include "os_account_constants.h"
#include <cstdint>
#include <string>
#include <vector>

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
bool QueryOsAccountConstraintSourceTypesFuzzTest(const uint8_t* data, size_t size)
{
    int32_t result = ERR_OK;
    if ((data != nullptr) && (size != 0)) {
        FuzzData fuzzData(data, size);
        std::vector<ConstraintSourceTypeInfo> testConstraintSourceTypeInfos;
        int32_t testId = fuzzData.GetData<int32_t>();
        std::string testConstraint(fuzzData.GenerateString());
        result = OsAccountManager::QueryOsAccountConstraintSourceTypes(
            testId, testConstraint, testConstraintSourceTypeInfos);
    }
    return result == ERR_OK;
}

bool QueryOsAccountByIdFuzzTest(const uint8_t* data, size_t size)
{
    int32_t result = ERR_OK;
    if ((data != nullptr) && (size != 0)) {
        FuzzData fuzzData(data, size);
        int32_t testId = fuzzData.GetData<int32_t>();
        OsAccountInfo osAccountInfo;
        result = OsAccountManager::QueryOsAccountById(testId, osAccountInfo);
    }
    return result == ERR_OK;
}

bool QueryCurrentOsAccountFuzzTest(const uint8_t* data, size_t size)
{
    int32_t result = ERR_OK;
    if ((data != nullptr) && (size != 0)) {
        FuzzData fuzzData(data, size);
        std::string testName(fuzzData.GenerateString());
        OsAccountInfo osAccountInfo;
        osAccountInfo.SetLocalName(testName);
        result = OsAccountManager::QueryCurrentOsAccount(osAccountInfo);
    }
    return result == ERR_OK;
}
} // namespace

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::QueryOsAccountConstraintSourceTypesFuzzTest(data, size);
    OHOS::QueryOsAccountByIdFuzzTest(data, size);
    OHOS::QueryCurrentOsAccountFuzzTest(data, size);
    return 0;
}

