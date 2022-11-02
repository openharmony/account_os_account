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

#include "queryohosaccountinfobyuserid_fuzzer.h"

#include "account_proxy.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "ohos_account_kits.h"
#include <string>
#include <vector>

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
    bool QueryOhosAccountInfoByUserIdFuzzTest(const uint8_t* data, size_t size)
    {
        std::pair<bool, OhosAccountInfo> result;
        if (size > 0) {
            result.first = false;
            int testId = static_cast<int>(size);
            result = OhosAccountKits::GetInstance().QueryOhosAccountInfoByUserId(testId);
        }
        return result.first;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::QueryOhosAccountInfoByUserIdFuzzTest(data, size);
    return 0;
}

