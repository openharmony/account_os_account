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

#include "setspecificosaccountconstraints_fuzzer.h"

#include <string>
#include <vector>
#include "os_account_manager.h"
#include "account_log_wrapper.h"
#undef private
#include "os_account_constants.h"

using namespace std;
using namespace OHOS::AccountSA;
const int32_t ENFORCER_ID = 100;
const int32_t TARGET_ID = 50;
const int CONSTANTS_NUMBER_TWO = 2;
const int CONSTANTS_NUMBER_THREE = 3;
namespace OHOS {
    bool SetSpecificOsAccountConstraintsFuzzTest(const uint8_t* data, size_t size)
    {
        bool result = false;
        if (size > 0) {
            std::vector<std::string> CONSTANTS_VECTOR {
                "constraint.print",
                "constraint.screen.timeout.set",
                "constraint.share.into.profile"
            };
            bool enable = ((size % CONSTANTS_NUMBER_TWO) == 0);
            bool isDeviceOwner = ((size % CONSTANTS_NUMBER_THREE) == 0);
            result = OsAccountManager::SetSpecificOsAccountConstraints(
                CONSTANTS_VECTOR, enable, TARGET_ID, ENFORCER_ID, isDeviceOwner);
        }
        return result;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SetSpecificOsAccountConstraintsFuzzTest(data, size);
    return 0;
}
