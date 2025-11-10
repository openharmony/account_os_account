/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "procgetdomainaccesstokenstub_fuzzer.h"

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
const int ENUM_MAX = 4;

class TestGetDomainAccountInfoCallback : public DomainAccountCallbackStub {
public:
    TestGetDomainAccountInfoCallback(){};
    virtual ~TestGetDomainAccountInfoCallback();
    ErrCode OnResult(int32_t errCode, const DomainAccountParcel &parcel) override;
};

TestGetDomainAccountInfoCallback::~TestGetDomainAccountInfoCallback() {}

ErrCode TestGetDomainAccountInfoCallback::OnResult(int32_t errCode, const DomainAccountParcel &parcel)
{
    return ERR_OK;
}
}

bool ProcGetDomainAccessTokenStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MessageParcel dataTemp;
    if (!dataTemp.WriteInterfaceToken(DomainAccountStub::GetDescriptor())) {
        return false;
    }

    DomainAccountInfo info;
    FuzzData fuzzData(data, size);
    info.domain_ = fuzzData.GenerateString();
    info.accountName_ = fuzzData.GenerateString();
    info.accountId_ = fuzzData.GenerateString();
    info.isAuthenticated = fuzzData.GenerateBool();
    info.serverConfigId_ = fuzzData.GenerateString();
    int typeNumber = fuzzData.GetData<int>() % ENUM_MAX;
    info.status_ = static_cast<DomainAccountStatus>(typeNumber);
    if (fuzzData.GetData<bool>()) {
        if (!dataTemp.WriteParcelable(&info)) {
            return false;
        }
    }

    AAFwk::WantParams workParams;
    if (fuzzData.GetData<bool>()) {
        if (!dataTemp.WriteParcelable(&workParams)) {
            return false;
        }
    }

    auto testCallback = new TestGetDomainAccountInfoCallback();

    if (testCallback == nullptr) {
        return false;
    }
    if (fuzzData.GetData<bool>()) {
        if (!dataTemp.WriteRemoteObject(testCallback->AsObject())) {
            return false;
        }
    }

    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(IDomainAccountIpcCode::COMMAND_GET_ACCESS_TOKEN);
    auto domainAccountService = std::make_shared<DomainAccountManagerService>();
    domainAccountService->OnRemoteRequest(code, dataTemp, reply, option);

    return true;
}

}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::ProcGetDomainAccessTokenStubFuzzTest(data, size);
    return 0;
}

