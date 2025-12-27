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

#include "procgetdomainaccountinfostub_fuzzer.h"

#include <memory>
#include <string>
#include <vector>
#include "account_log_wrapper.h"
#include "domain_account_callback_stub.h"
#include "domain_account_common.h"
#include "domain_account_manager_service.h"
#include "fuzz_data.h"
#include "idomain_account.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::AccountSA;
const int32_t WAIT_TIME = 3;
class TestGetDomainAccountInfoCallback : public DomainAccountCallbackStub {
public:
    TestGetDomainAccountInfoCallback() {};
    virtual ~TestGetDomainAccountInfoCallback();
    ErrCode OnResult(int32_t errCode, const DomainAccountParcel &parcel) override;
    void WaitForCallbackResult();
private:
    std::mutex mutex_;
    bool isCalled_ = false;
    std::condition_variable cv_;
};

TestGetDomainAccountInfoCallback::~TestGetDomainAccountInfoCallback()
{}

ErrCode TestGetDomainAccountInfoCallback::OnResult(int32_t errCode, const DomainAccountParcel &parcel)
{
    std::unique_lock<std::mutex> lock(mutex_);
    if (isCalled_) {
        ACCOUNT_LOGE("Callback is called.");
        return 0;
    }
    isCalled_ = true;
    cv_.notify_one();
    return 0;
}

void TestGetDomainAccountInfoCallback::WaitForCallbackResult()
{
    std::unique_lock<std::mutex> lock(mutex_);
    ACCOUNT_LOGI("WaitForCallbackResult.");
    cv_.wait_for(lock, std::chrono::seconds(WAIT_TIME), [this] { return isCalled_; });
}

namespace OHOS {
bool ProcGetDomainAccountInfoStubFuzzTest(const uint8_t* data, size_t size)
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
    if (fuzzData.GetData<bool>()) {
        if (!dataTemp.WriteParcelable(&info)) {
            return false;
        }
    }

    auto testCallback = new TestGetDomainAccountInfoCallback();

    if (testCallback == nullptr) {
        ACCOUNT_LOGI("AppAccountStub ProcHasDomainAccount testCallback is null");
        return false;
    }
    if (fuzzData.GetData<bool>()) {
        if (!dataTemp.WriteRemoteObject(testCallback->AsObject())) {
            return false;
        }
    }
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(IDomainAccountIpcCode::COMMAND_GET_DOMAIN_ACCOUNT_INFO);
    auto domainAccountService = std::make_shared<DomainAccountManagerService>();
    domainAccountService->OnRemoteRequest(code, dataTemp, reply, option);
    testCallback->WaitForCallbackResult();
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::ProcGetDomainAccountInfoStubFuzzTest(data, size);
    return 0;
}

