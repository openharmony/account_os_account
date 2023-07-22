/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "verifycredentialstub_fuzzer.h"
#include <string>
#include <vector>

#include "account_log_wrapper.h"
#include "app_account_authenticator_callback_stub.h"
#include "app_account_manager_service.h"
#include "iapp_account.h"

using namespace std;
using namespace OHOS::AccountSA;

class MockAuthenticatorCallback final : public AppAccountAuthenticatorCallbackStub {
public:
    void OnResult(int32_t resultCode, const OHOS::AAFwk::Want &result) {}
    void OnRequestRedirected(OHOS::AAFwk::Want &request) {}
    void OnRequestContinued() {}
};

namespace OHOS {
const std::u16string APPACCOUNT_TOKEN = u"ohos.accountfwk.IAppAccount";
bool VerifyCredentialStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    std::string testName(reinterpret_cast<const char*>(data), size);
    std::string testOwner(reinterpret_cast<const char*>(data), size);
    std::string testValue(reinterpret_cast<const char*>(data), size);
    VerifyCredentialOptions options;
    options.credentialType = testValue;
    options.credential = testValue;
    sptr<MockAuthenticatorCallback> callback = new (std::nothrow) MockAuthenticatorCallback();

    if (callback == nullptr) {
        ACCOUNT_LOGI("AppAccountStub VerifyCredential callback is null");
        return false;
    }
    
    MessageParcel dataTemp;
    if (!dataTemp.WriteInterfaceToken(APPACCOUNT_TOKEN)) {
        return false;
    }

    if (!dataTemp.WriteString(testName)) {
        return false;
    }
    if (!dataTemp.WriteString(testOwner)) {
        return false;
    }
    
    if (!dataTemp.WriteParcelable(&options)) {
        return false;
    }
    
    if (!dataTemp.WriteRemoteObject(callback->AsObject())) {
        return false;
    }
    
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(AppAccountInterfaceCode::VERIFY_CREDENTIAL);
    auto appAccountManagerService = std::make_shared<AppAccountManagerService>();
    appAccountManagerService->OnRemoteRequest(code, dataTemp, reply, option);
    
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::VerifyCredentialStubFuzzTest(data, size);
    return 0;
}

