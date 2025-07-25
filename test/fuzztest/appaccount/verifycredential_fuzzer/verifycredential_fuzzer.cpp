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
#include "app_account_common.h"
#include "app_account_manager.h"
#include "fuzz_data.h"

using namespace std;
using namespace OHOS::AccountSA;

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
            sptr<MockAuthenticatorCallback> callback = new (std::nothrow) MockAuthenticatorCallback();
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

