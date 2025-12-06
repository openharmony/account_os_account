/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "prepareremoteauth_fuzzer.h"

#include <string>
#include <vector>
#define private public
#include "account_iam_client.h"
#include "account_i_a_m_proxy.h"
#undef private
#include "fuzz_data.h"

using namespace std;
using namespace OHOS::AccountSA;

class MockPreRemoteAuthCallback : public OHOS::AccountSA::PreRemoteAuthCallback {
public:
    void OnResult(int32_t result)
    {
        return;
    }
    virtual ~MockPreRemoteAuthCallback() {}
};

namespace OHOS {
bool PrepareRemoteAuthFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    FuzzData fuzzData(data, size);
    std::string remoteNetworkId(fuzzData.GenerateString());
    std::shared_ptr<PreRemoteAuthCallback> callback = nullptr;
    bool isInitCallback = fuzzData.GetData<bool>();
    if (isInitCallback) {
        callback = make_shared<MockPreRemoteAuthCallback>();
    }
    int32_t result = AccountIAMClient::GetInstance().PrepareRemoteAuth(remoteNetworkId, callback);
    return result == ERR_OK;
}

}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::PrepareRemoteAuthFuzzTest(data, size);
    return 0;
}
