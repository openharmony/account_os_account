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

#include "addcredential_fuzzer.h"

#include <string>
#include <vector>

#include "account_iam_client.h"
#include "fuzz_data.h"


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
    bool AddCredentialFuzzTest(const uint8_t* data, size_t size)
    {
        FuzzData fuzzData(data, size);
        int32_t userId = fuzzData.GetData<int32_t>();
        AuthType authType = fuzzData.GenerateEnmu(UserIam::UserAuth::RECOVERY_KEY);
        std::optional<PinSubType> pinType = {fuzzData.GenerateEnmu(UserIam::UserAuth::PIN_MAX)};
        std::vector<uint8_t> token = {fuzzData.GetData<uint8_t>()};
        CredentialParameters credInfo = {
            .authType = authType,
            .pinType = pinType,
            .token = token,
        };
        std::shared_ptr<IDMCallback> callback = make_shared<MockIDMCallback>();
        AccountIAMClient::GetInstance().AddCredential(userId, credInfo, callback);
        return false;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AddCredentialFuzzTest(data, size);
    return 0;
}

