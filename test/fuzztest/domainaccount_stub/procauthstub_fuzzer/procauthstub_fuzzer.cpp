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

#include "procauthstub_fuzzer.h"

#include <string>
#include <vector>

#include "domain_account_manager_service.h"
#include "domain_auth_callback.h"
#include "domain_auth_callback_service.h"
#include "idomain_account.h"

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
namespace {
const std::u16string ACCOUNT_TOKEN = u"ohos.accountfwk.IDomainAccount";
const int32_t PASSWORD_LEN = 8;

class TestDomainAuthCallback : public OHOS::AccountSA::DomainAuthCallback {
public:
    TestDomainAuthCallback() = default;
    virtual ~TestDomainAuthCallback() = default;
    void OnResult(int32_t resultCode, const OHOS::AccountSA::DomainAuthResult &result) override
    {}
};
}

    bool ProcAuthStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        std::string accountName(reinterpret_cast<const char*>(data), size);
        std::string domain(reinterpret_cast<const char*>(data), size);
        std::vector<uint8_t> password;

        for (int32_t i = 0; i < PASSWORD_LEN; i++) {
            uint8_t bit = static_cast<uint8_t>(size);
            password.emplace_back(bit);
        }

        auto callbackPtr = std::make_shared<TestDomainAuthCallback>();
        sptr<IDomainAuthCallback> callback = new (std::nothrow) DomainAuthCallbackService(callbackPtr);

        MessageParcel dataTemp;

        if (!dataTemp.WriteInterfaceToken(ACCOUNT_TOKEN)) {
            return false;
        }
        if (!dataTemp.WriteString(accountName)) {
            return false;
        }
        if (!dataTemp.WriteString(domain)) {
            return false;
        }
        if (!dataTemp.WriteUInt8Vector(password)) {
            return false;
        }
        if (!dataTemp.WriteRemoteObject(callback->AsObject())) {
            return false;
        }

        MessageParcel reply;
        MessageOption option;

        uint32_t code = static_cast<uint32_t>(IDomainAccount::Message::DOMAIN_AUTH);
        auto domainAccountService = std::make_shared<DomainAccountManagerService>();
        domainAccountService->OnRemoteRequest(code, dataTemp, reply, option);

        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::ProcAuthStubFuzzTest(data, size);
    return 0;
}
