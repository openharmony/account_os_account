/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "getauthenticatorinfo_fuzzer.h"

#include <string>
#include <vector>
#include "account_log_wrapper.h"
#include "app_account_common.h"
#include "app_account_manager.h"
#include "fuzz_data.h"

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
    bool GetAuthenticatorInfoFuzzTest(const uint8_t* data, size_t size)
    {
        bool result = false;
        if (size > 0) {
            FuzzData fuzzData(data, size);
            std::string testOwner(fuzzData.GenerateString());
            AuthenticatorInfo testInfo;
            testInfo.owner = testOwner;
            result = AppAccountManager::GetAuthenticatorInfo(testOwner, testInfo);
        }
        return result;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetAuthenticatorInfoFuzzTest(data, size);
    return 0;
}

