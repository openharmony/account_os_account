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
#include "acquireauthorization_fuzzer.h"
#include <cstddef>
#include <string>
#include <vector>
#include "account_log_wrapper.h"
#include "authorization_callback.h"
#include "authorization_callback_stub.h"
#include "authorization_client.h"
#include "authorization_common.h"
#include "fuzz_data.h"

using namespace std;
using namespace OHOS::AccountSA;

class MockAuthorizationCallback : public OHOS::AccountSA::AuthorizationCallback {
public:
    MockAuthorizationCallback() = default;
    virtual ~MockAuthorizationCallback() = default;
    OHOS::ErrCode OnResult(int32_t resultCode, const OHOS::AccountSA::AuthorizationResult& result) override
    {
        return OHOS::ERR_OK;
    }

    OHOS::ErrCode OnConnectAbility(const OHOS::AccountSA::ConnectAbilityInfo &info,
        const OHOS::sptr<OHOS::IRemoteObject> &callback) override
    {
        return OHOS::ERR_OK;
    }
};

namespace OHOS {
bool AcquireAuthorizationFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    FuzzData fuzzData(data, size);
    std::string privilege = fuzzData.GenerateString();

    // Create AcquireAuthorizationOptions with fuzz data
    AcquireAuthorizationOptions options;
    options.hasContext = fuzzData.GenerateBool();
    options.isReuseNeeded = fuzzData.GenerateBool();
    options.isInteractionAllowed = fuzzData.GenerateBool();

    // Generate challenge data
    uint32_t challengeSize = fuzzData.GetData<uint32_t>() % 128;
    for (uint32_t i = 0; i < challengeSize; i++) {
        options.challenge.push_back(fuzzData.GetData<uint8_t>());
    }
    // Create callback with different strategies
    uint32_t callbackType = fuzzData.GetData<uint32_t>() % 2;
    if (callbackType == 1) {
        auto callback = std::make_shared<MockAuthorizationCallback>();
        AuthorizationClient::GetInstance().AcquireAuthorization(privilege, options, callback);
    } else {
        // nullptr case - test error handling
        AuthorizationClient::GetInstance().AcquireAuthorization(privilege, options, nullptr);
    }
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AcquireAuthorizationFuzzTest(data, size);
    return 0;
}
