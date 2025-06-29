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

#include "getcreatedosaccountnumfromdatabase_fuzzer.h"

#include <string>
#include <vector>
#include "os_account_manager.h"
#include "account_log_wrapper.h"
#include "fuzz_data.h"
#undef private
#include "os_account_constants.h"

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
    const std::vector<std::string> VALID_ACCOUNT_TYPES = {
        "normal",
        "admin",
        "guest",
        "",
        "nonexistent_type"
    };

    bool GetCreatedOsAccountNumFromDatabaseFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        FuzzData fuzzData(data, size);
        int createdOsAccountNum = -1;
        
        std::string testName = fuzzData.GetData<bool>() ?
                              VALID_ACCOUNT_TYPES[fuzzData.GetData<uint8_t>() % VALID_ACCOUNT_TYPES.size()] :
                              fuzzData.GenerateString();
        
        OsAccountManager::GetCreatedOsAccountNumFromDatabase(testName, createdOsAccountNum);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetCreatedOsAccountNumFromDatabaseFuzzTest(data, size);
    return 0;
}

