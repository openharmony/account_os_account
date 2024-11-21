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

#include "getallaccessibleaccounts_fuzzer.h"

#include <string>
#include <vector>
#define private public
#include "account_log_wrapper.h"
#include "app_account_info.h"
#include "app_account_manager.h"
#undef private
#include "fuzz_data.h"

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
    bool GetAllAccessibleAccountsFuzzTest(const uint8_t* data, size_t size)
    {
        bool result = false;
        if (size > 0) {
            FuzzData fuzzData(data, size);
            std::string testOwner(fuzzData.GenerateString());
            std::vector<AppAccountInfo> appAccounts;
            AppAccountInfo appAccount;
            appAccount.owner_ = testOwner;
            appAccounts.emplace_back(appAccount);
            result = AppAccountManager::GetAllAccessibleAccounts(appAccounts);
        }
        return result;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetAllAccessibleAccountsFuzzTest(data, size);
    return 0;
}

