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

#include "verifycredential_fuzzer.h"

#include <string>
#include <vector>
#include "account_log_wrapper.h"
#include "app_account_authenticator_callback_stub.h"
#include "app_account_common.h"
#include "app_account_manager.h"
#include "fuzz_data.h"

using namespace std;
using namespace OHOS::AccountSA;
const int CONSTANTS_NUMBER_ONE = 1;
const int CONSTANTS_NUMBER_TWO = 2;
const int CONSTANTS_NUMBER_THREE = 3;

class MockAuthenticatorCallback : public OHOS::AccountSA::IAppAccountAuthenticatorCallback {
public:
    OHOS::ErrCode OnResult(int32_t resultCode, const OHOS::AAFwk::Want& result) override
    {
        return OHOS::ERR_OK;
    }
    OHOS::ErrCode OnRequestRedirected(const OHOS::AAFwk::Want& request) override
    {
        return OHOS::ERR_OK;
    }
    OHOS::ErrCode OnRequestContinued() override
    {
        return OHOS::ERR_OK;
    }
    OHOS::sptr<OHOS::IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};

class MockAuthenticatorCallbackStub final : public AppAccountAuthenticatorCallbackStub {
public:
    OHOS::ErrCode OnResult(int32_t resultCode, const OHOS::AAFwk::Want &result)
    {
        return OHOS::ERR_OK;
    }

    OHOS::ErrCode OnRequestRedirected(const OHOS::AAFwk::Want &request)
    {
        return OHOS::ERR_OK;
    }

    OHOS::ErrCode OnRequestContinued()
    {
        return OHOS::ERR_OK;
    }
    OHOS::ErrCode CallbackEnter([[maybe_unused]] uint32_t code)
    {
        return OHOS::ERR_OK;
    }
    OHOS::ErrCode CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
    {
        return OHOS::ERR_OK;
    }
};
namespace OHOS {
    bool VerifyCredentialFuzzTest(const uint8_t* data, size_t size)
    {
        bool result = false;
        if (size > 0) {
            FuzzData fuzzData(data, size);
            std::string testName(fuzzData.GenerateString());
            std::string testOwner(fuzzData.GenerateString());
            std::string testValue(fuzzData.GenerateString());
            VerifyCredentialOptions options;
            options.credentialType = testValue;
            options.credential = testValue;
            sptr<IAppAccountAuthenticatorCallback> callback = nullptr;
            uint32_t number = fuzzData.GetData<uint32_t>() % CONSTANTS_NUMBER_THREE;
            if (number == CONSTANTS_NUMBER_ONE) {
                callback = new (std::nothrow) MockAuthenticatorCallback();
            } else if (number == CONSTANTS_NUMBER_TWO) {
                callback = new (std::nothrow) MockAuthenticatorCallbackStub();
            }
            result = AppAccountManager::VerifyCredential(testName, testOwner, options, callback);
        }
        return result;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::VerifyCredentialFuzzTest(data, size);
    return 0;
}

