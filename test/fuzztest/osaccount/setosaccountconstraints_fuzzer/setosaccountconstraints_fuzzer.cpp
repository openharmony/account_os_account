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

#include "setosaccountconstraints_fuzzer.h"

#include <string>
#include <vector>
#include "os_account_manager.h"
#include "account_log_wrapper.h"
#include "fuzz_data.h"
#undef private
#include "os_account_constants.h"

using namespace std;
using namespace OHOS::AccountSA;
const int LOCAL_ID = 100;
const int CONSTANTS_NUMBER_TWO = 2;
const int CONSTANTS_NUMBER_THREE = 3;

namespace OHOS {
    bool SetOsAccountConstraintsFuzzTest(const uint8_t* data, size_t size)
    {
        bool result = false;
        if ((data != nullptr) && (size != 0)) {
            FuzzData fuzzData(data, size);
            std::vector<std::string> CONSTANTS_VECTOR {
                "constraint.print",
                "constraint.screen.timeout.set",
                "constraint.share.into.profile"
            };
            int32_t temp = fuzzData.GetData<int32_t>() % CONSTANTS_NUMBER_THREE;
            std::string testConstraint(fuzzData.GenerateString());
            if (!temp) {
                CONSTANTS_VECTOR.push_back(testConstraint);
            }
            bool enable = ((fuzzData.GetData<int32_t>() % CONSTANTS_NUMBER_TWO) == 0);
            result = OsAccountManager::SetOsAccountConstraints(LOCAL_ID, CONSTANTS_VECTOR, enable);
        }
        return result;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SetOsAccountConstraintsFuzzTest(data, size);
    return 0;
}
