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

#include "createaccount_fuzzer.h"

#include "account_log_wrapper.h"
#include "app_account_manager.h"
#include "app_account_common.h"
#include <string>
#include <vector>

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
    bool CreateAccountFuzzTest(const uint8_t* data, size_t size)
    {
        bool result = false;
        if (size > 0) {
            std::string testName(reinterpret_cast<const char*>(data), size);
            std::string testKey(reinterpret_cast<const char*>(data), size);
            std::string testValue(reinterpret_cast<const char*>(data), size);
            CreateAccountOptions options;
            options.customData[testKey] = testValue;
            result = AppAccountManager::CreateAccount(testName, options);
        }
        return result;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::CreateAccountFuzzTest(data, size);
    return 0;
}

