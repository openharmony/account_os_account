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

#include "getpropertybycredentialId_fuzzer.h"

#include <string>
#include <vector>
#include "account_iam_client.h"
#include "fuzz_data.h"


using namespace std;
using namespace OHOS::AccountSA;

class MockGetSetPropCallback : public OHOS::AccountSA::GetSetPropCallback {
public:
    virtual ~MockGetSetPropCallback() {}
    void OnResult(int32_t result, const Attributes &extraInfo) override
    {
        return;
    }
};

namespace OHOS {
    bool GetPropertyByCredentialIdFuzzTest(const uint8_t* data, size_t size)
    {
        FuzzData fuzzData(data, size);
        uint64_t credentialId = fuzzData.GetData<uint64_t>();
        std::vector<Attributes::AttributeKey> keys = {
            fuzzData.GenerateEnmu(UserIam::UserAuth::Attributes::ATTR_AUTH_INTENTION)};
        std::shared_ptr<GetSetPropCallback> callback = nullptr;
        bool isInitCallback = fuzzData.GetData<bool>();
        if (isInitCallback) {
            callback = make_shared<MockGetSetPropCallback>();
        }
        AccountIAMClient::GetInstance().GetPropertyByCredentialId(credentialId, keys, callback);
        return false;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetPropertyByCredentialIdFuzzTest(data, size);
    return 0;
}

