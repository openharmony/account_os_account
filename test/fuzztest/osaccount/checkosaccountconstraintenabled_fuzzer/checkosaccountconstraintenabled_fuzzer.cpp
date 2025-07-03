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

#include "checkosaccountconstraintenabled_fuzzer.h"

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
constexpr int32_t DEFAULT_TEST_USER_ID = 100;

int32_t GetUserId(FuzzData& fuzzData, bool useValid, int32_t defaultId = DEFAULT_TEST_USER_ID)
{
    return useValid ? defaultId : fuzzData.GetData<int32_t>();
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
    OHOS::CheckOsAccountConstraintEnabledFuzzTest(data, size);
    return 0;
}
