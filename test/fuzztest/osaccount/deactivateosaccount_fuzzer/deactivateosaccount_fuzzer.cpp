/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "deactivateosaccount_fuzzer.h"

#include "os_account_manager.h"
#include "account_log_wrapper.h"
#include "fuzz_data.h"
#include "os_account_constants.h"
#include <string>
#include <vector>

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
    bool DeactivateOsAccountFuzzTest(const uint8_t* data, size_t size)
    {
        int32_t result = ERR_OK;
        if ((data != nullptr) && (size != 0)) {
            FuzzData fuzzData(data, size);
            int32_t testId = fuzzData.GetData<int32_t>();
            result = OsAccountManager::DeactivateOsAccount(testId);
            OsAccountManager::DeactivateAllOsAccounts();
        }
        return result == ERR_OK;
    }

    void CreateTestOsAccount()
    {
        OsAccountInfo osAccountInfoOne;
        OsAccountType testType = OsAccountType::NORMAL;
        std::string accountName = "deactivate_test_account";

        int32_t result = OsAccountManager::CreateOsAccount(accountName, testType, osAccountInfoOne);
        if (result == ERR_OK) {
            ACCOUNT_LOGI("Delete deactivate_test_account.");
            OsAccountManager::RemoveOsAccount(osAccountInfoOne.GetLocalId());
        }
    }
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::CreateTestOsAccount();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DeactivateOsAccountFuzzTest(data, size);
    return 0;
}

