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

#include "setosaccountname_fuzzer.h"

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

namespace OHOS {
    bool SetOsAccountNameFuzzTest(const uint8_t* data, size_t size)
    {
        bool result = false;
        if ((data != nullptr) && (size != 0)) {
            FuzzData fuzzData(data, size);
            std::string testName(fuzzData.GenerateString());
            result = OsAccountManager::SetOsAccountName(LOCAL_ID, testName);
        }
        return result;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SetOsAccountNameFuzzTest(data, size);
    return 0;
}

