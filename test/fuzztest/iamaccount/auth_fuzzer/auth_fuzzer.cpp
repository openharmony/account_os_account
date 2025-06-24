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

#include "auth_fuzzer.h"

#include <string>
#include <vector>
#include "account_iam_client.h"
#include "fuzz_data.h"
#include "os_account_constants.h"

using namespace std;
using namespace OHOS::AccountSA;

class MockIDMCallback : public OHOS::AccountSA::IDMCallback {
public:
    virtual ~MockIDMCallback() {}
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) override
    {
        return;
    }
    void OnResult(int32_t result, const Attributes &extraInfo) override
    {
        return;
    }
};

namespace OHOS {
    void GenRemoteAuthOptions(FuzzData &fuzzData, RemoteAuthOptions &remoteAuthOptions)
    {
        remoteAuthOptions.hasVerifierNetworkId = fuzzData.GetData<bool>();
        if (remoteAuthOptions.hasVerifierNetworkId) {
            remoteAuthOptions.verifierNetworkId = fuzzData.GenerateString();
        }
        remoteAuthOptions.hasCollectorNetworkId = fuzzData.GetData<bool>();
        if (remoteAuthOptions.hasCollectorNetworkId) {
            remoteAuthOptions.collectorNetworkId = fuzzData.GenerateString();
        }
        remoteAuthOptions.hasCollectorTokenId = fuzzData.GetData<bool>();
        if (remoteAuthOptions.hasCollectorTokenId) {
            remoteAuthOptions.collectorTokenId = fuzzData.GetData<uint32_t>();
        }
    }

    bool AuthFuzzTest(const uint8_t *data, size_t size)
    {
        FuzzData fuzzData(data, size);
        std::vector<uint8_t> challenge = {fuzzData.GetData<uint8_t>()};
        AuthType authType = fuzzData.GenerateEnmu(UserIam::UserAuth::RECOVERY_KEY);
        AuthTrustLevel authTrustLevel = fuzzData.GenerateEnmu(UserIam::UserAuth::ATL4);
        std::shared_ptr<IDMCallback> callback = make_shared<MockIDMCallback>();
        AuthOptions authOptions;
        authOptions.hasAccountId = fuzzData.GetData<bool>();
        if (authOptions.hasAccountId) {
            authOptions.accountId = fuzzData.GetData<bool>() ? fuzzData.GetData<int32_t>() % Constants::MAX_USER_ID
                                                            : fuzzData.GetData<int32_t>();
        }
        authOptions.hasRemoteAuthOptions = fuzzData.GetData<bool>();
        if (authOptions.hasRemoteAuthOptions) {
            GenRemoteAuthOptions(fuzzData, authOptions.remoteAuthOptions);
        }
        authOptions.authIntent = fuzzData.GenerateEnmu(AuthIntent::ABANDONED_PIN_AUTH);
        uint64_t result = AccountIAMClient::GetInstance().Auth(
            authOptions, challenge, authType, authTrustLevel, callback);
        return result == ERR_OK;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AuthFuzzTest(data, size);
    return 0;
}

