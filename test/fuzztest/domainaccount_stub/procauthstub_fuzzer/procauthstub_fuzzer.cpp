/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "domain_account_callback.h"
#include "domain_account_callback_service.h"
#include "domain_account_manager_service.h"
#include "fuzz_data.h"
#include "idomain_account.h"

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
namespace {
const int32_t PASSWORD_LEN = 8;
const int ENUM_MAX = 4;
const uint32_t TEST_VECTOR_MAX_SIZE = 102402;

class TestDomainAuthCallback : public OHOS::AccountSA::DomainAccountCallback {
public:
    TestDomainAuthCallback() = default;
    virtual ~TestDomainAuthCallback() = default;
    void OnResult(const int32_t errCode, Parcel &parcel) override
    {}
};
}

    bool ProcAuthStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        FuzzData fuzzData(data, size);

        auto callbackPtr = std::make_shared<TestDomainAuthCallback>();
        sptr<IDomainAccountCallback> callback = new (std::nothrow) DomainAccountCallbackService(callbackPtr);

        MessageParcel dataTemp;

        DomainAccountInfo info;
        info.domain_ = fuzzData.GenerateString();
        info.accountName_ = fuzzData.GenerateString();
        info.accountId_ = fuzzData.GenerateString();
        info.isAuthenticated = fuzzData.GenerateBool();
        info.serverConfigId_ = fuzzData.GenerateString();
        int typeNumber = fuzzData.GetData<int>() % ENUM_MAX;
        info.status_ = static_cast<DomainAccountStatus>(typeNumber);

        if (!dataTemp.WriteInterfaceToken(DomainAccountStub::GetDescriptor())) {
            return false;
        }
        if (fuzzData.GetData<bool>()) {
            if (!dataTemp.WriteParcelable(&info)) {
                return false;
            }
        }
        uint32_t passwordSize = fuzzData.GetData<bool>() ? TEST_VECTOR_MAX_SIZE : PASSWORD_LEN;
        if (!dataTemp.WriteInt32(passwordSize)) {
            return false;
        }
        for (uint32_t i = 0; i < PASSWORD_LEN; i++) {
            if (!dataTemp.WriteUint8(fuzzData.GetData<uint8_t>())) {
                return false;
            }
        }
        if (fuzzData.GetData<bool>()) {
            if (!dataTemp.WriteRemoteObject(callback->AsObject())) {
                return false;
            }
        }

        MessageParcel reply;
        MessageOption option;

        uint32_t code = static_cast<uint32_t>(IDomainAccountIpcCode::COMMAND_AUTH);
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

