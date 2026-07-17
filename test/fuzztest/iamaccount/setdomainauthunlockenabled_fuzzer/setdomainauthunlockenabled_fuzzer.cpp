/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "setdomainauthunlockenabled_fuzzer.h"

#include <string>
#include <vector>
#include "account_iam_client.h"
#include "fuzz_data.h"

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
bool SetDomainAuthUnlockEnabledFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    FuzzData fuzzData(data, size);
    int32_t localId = fuzzData.GetData<int32_t>();
    std::vector<uint8_t> token = {fuzzData.GetData<uint8_t>(), fuzzData.GetData<uint8_t>(),
        fuzzData.GetData<uint8_t>(), fuzzData.GetData<uint8_t>()};
    std::vector<uint8_t> secret = {fuzzData.GetData<uint8_t>(), fuzzData.GetData<uint8_t>(),
        fuzzData.GetData<uint8_t>(), fuzzData.GetData<uint8_t>()};
    bool enabled = fuzzData.GetData<bool>();
    ErrCode result = AccountIAMClient::GetInstance().SetDomainAuthUnlockEnabled(
        localId, token, secret, enabled);
    std::fill(token.begin(), token.end(), 0);
    std::fill(secret.begin(), secret.end(), 0);
    return result == ERR_OK;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::SetDomainAuthUnlockEnabledFuzzTest(data, size);
    return 0;
}
