/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "setohosaccountinfobyuserid_fuzzer.h"

#include "account_proxy.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "fuzz_data.h"
#include "ohos_account_kits.h"
#include <string>
#include <vector>

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
namespace {
static constexpr uint32_t OHOS_ACCOUNT_STATE_NUM = 5;
}
bool SetOhosAccountInfoByUserIdFuzzTest(const uint8_t* data, size_t size)
{
    int32_t result = ERR_OK;
    if ((data != nullptr) && (size != 0)) {
        FuzzData fuzzData(data, size);
        int32_t testId = fuzzData.GetData<int32_t>();
        OhosAccountInfo testOhosAccountInfo(
            fuzzData.GenerateString(),
            fuzzData.GenerateString(),
            fuzzData.GetData<int32_t>() % OHOS_ACCOUNT_STATE_NUM - 1
        );
        std::string testEventStr(fuzzData.GenerateString());
        result = OhosAccountKits::GetInstance().SetOhosAccountInfoByUserId(testId, testOhosAccountInfo, testEventStr);
    }
    return result == ERR_OK;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SetOhosAccountInfoByUserIdFuzzTest(data, size);
    return 0;
}

