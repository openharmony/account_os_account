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

#include "isosaccountdeactivating_fuzzer.h"

#include "os_account_manager.h"
#include "account_log_wrapper.h"
#include "fuzz_data.h"
#include "os_account_constants.h"
#include <string>
#include <vector>

using namespace std;
using namespace OHOS::AccountSA;

const int32_t MAX_TEST_ID = 10738; // Maximum test ID for fuzzing

namespace OHOS {
    bool IsOsAccountDeactivatingFuzzTest(const uint8_t* data, size_t size)
    {
        bool result = true;
        if (data != nullptr && size >= sizeof(int32_t)) {
            FuzzData fuzzData(data, size);
            int32_t testId = fuzzData.GetData<bool>() ?
                (fuzzData.GetData<int32_t>() % MAX_TEST_ID) : fuzzData.GetData<int32_t>();
            bool isDeactivating = false;
            ErrCode errCode = OsAccountManager::IsOsAccountDeactivating(testId, isDeactivating);
            result = errCode == ERR_OK;
        }
        return result;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::IsOsAccountDeactivatingFuzzTest(data, size);
    return 0;
}