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

#include "updateosaccountwithfullinfo_fuzzer.h"

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
constexpr int32_t TEST_USER_ID_1001 = 1001;
constexpr int64_t TEST_TIMESTAMP_2022 = 1640995200;

int32_t GetUserId(FuzzData& fuzzData, bool useValid, int32_t defaultId)
{
    return useValid ? defaultId : fuzzData.GetData<int32_t>();
}

int64_t GetTimestamp(FuzzData& fuzzData, bool useValid, int64_t defaultTime = TEST_TIMESTAMP_2022)
{
    return useValid ? defaultTime : fuzzData.GetData<int64_t>();
}

bool UpdateOsAccountWithFullInfoFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzData fuzzData(data, size);
    bool useValidParams = fuzzData.GetData<bool>();
    
    OsAccountInfo osAccountInfo;
    osAccountInfo.SetLocalName(fuzzData.GenerateString());
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

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::UpdateOsAccountWithFullInfoFuzzTest(data, size);
    return 0;
}
