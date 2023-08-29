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

#include "procauthwithpopupstub_fuzzer.h"

#include <string>
#include <vector>

#include "domain_account_manager_service.h"
#include "domain_account_callback.h"
#include "domain_account_callback_service.h"
#include "idomain_account.h"

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
namespace {
const std::u16string ACCOUNT_TOKEN = u"ohos.accountfwk.IDomainAccount";

class TestDomainAuthCallback : public OHOS::AccountSA::DomainAccountCallback {
public:
    TestDomainAuthCallback() = default;
    virtual ~TestDomainAuthCallback() = default;
    void OnResult(const int32_t errCode, Parcel &parcel) override
    {}
};
}

    bool ProcAuthWithPopupStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        int32_t userId = static_cast<int32_t>(size);

        auto callbackPtr = std::make_shared<TestDomainAuthCallback>();
        sptr<IDomainAccountCallback> callback = new (std::nothrow) DomainAccountCallbackService(callbackPtr);

        MessageParcel dataTemp;

        if (!dataTemp.WriteInterfaceToken(ACCOUNT_TOKEN)) {
            return false;
        }
        if (!dataTemp.WriteInt32(userId)) {
            return false;
        }
        if (!dataTemp.WriteRemoteObject(callback->AsObject())) {
            return false;
        }

        MessageParcel reply;
        MessageOption option;

        uint32_t code = static_cast<uint32_t>(DomainAccountInterfaceCode::DOMAIN_AUTH_WITH_POPUP);
        auto domainAccountService = std::make_shared<DomainAccountManagerService>();
        domainAccountService->OnRemoteRequest(code, dataTemp, reply, option);

        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::ProcAuthWithPopupStubFuzzTest(data, size);
    return 0;
}

