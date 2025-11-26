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

#include "binddomainaccountstub_fuzzer.h"
#include <string>
#include <thread>
#include <vector>

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "domain_account_callback_service.h"
#include "fuzz_data.h"
#include "ios_account.h"
#include "os_account_manager_service.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS::AccountSA;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
const std::u16string IOS_ACCOUNT_DESCRIPTOR = u"ohos.accountfwk.IOsAccount";

class TestCallback final : public DomainAccountCallback {
public:
    TestCallback() = default;
    ~TestCallback() = default;
    void OnResult(const int32_t errCode, Parcel &parcel) override
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (isCalled_) {
            ACCOUNT_LOGE("Callback is called.");
            return;
        }
        isCalled_ = true;
        cv_.notify_one();
    }

    void WaitForCallbackResult()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        ACCOUNT_LOGI("WaitForCallbackResult.");
        cv_.wait(lock, [this] { return isCalled_; });
    }

private:
    std::mutex mutex_;
    bool isCalled_ = false;
    std::condition_variable cv_;
};

bool BindDomainAccountStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzData fuzzData(data, size);
    MessageParcel datas;
    datas.WriteInterfaceToken(IOS_ACCOUNT_DESCRIPTOR);
    int32_t localId = static_cast<int32_t>(fuzzData.GetData<size_t>() % Constants::MAX_USER_ID);
    if (!datas.WriteInt32(localId)) {
        return false;
    }
    auto useDomainAccountInfo = fuzzData.GenerateBool();
    if (useDomainAccountInfo) {
        DomainAccountInfo domainInfo(fuzzData.GenerateString(), fuzzData.GenerateString());
        if (!datas.WriteParcelable(&domainInfo)) {
            return false;
        }
    }
    auto useDomainAccountCallbackService = fuzzData.GenerateBool();
    std::shared_ptr<TestCallback> callbackPtr = nullptr;
    if (useDomainAccountCallbackService) {
        callbackPtr = std::make_shared<TestCallback>();
        sptr<DomainAccountCallbackService> callbackService =
            new (std::nothrow) DomainAccountCallbackService(callbackPtr);
        if ((callbackService == nullptr) || (!datas.WriteRemoteObject(callbackService->AsObject()))) {
            return false;
        }
    }

    MessageParcel reply;
    MessageOption option;

    auto osAccountManagerService_ = std::make_shared<OsAccountManagerService>();

    auto ret = osAccountManagerService_->OnRemoteRequest(
        static_cast<int32_t>(IOsAccountIpcCode::COMMAND_BIND_DOMAIN_ACCOUNT), datas, reply, option);
    if (ret != ERR_OK) {
        return true;
    }
    ErrCode errCode = reply.ReadInt32();
    if (errCode != ERR_OK) {
        return true;
    }
    if (callbackPtr != nullptr) {
        callbackPtr->WaitForCallbackResult();
    }
    return true;
}
} // namespace OHOS

void NativeTokenGet()
{
    uint64_t tokenId;
    const char **perms = new const char *[1];
    perms[0] = "ohos.permission.MANAGE_LOCAL_ACCOUNTS";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 1,
        .aclsNum = 0,
        .perms = perms,
        .acls = nullptr,
        .aplStr = "system_core",
    };
    infoInstance.processName = "BIND_DOMAIN_ACCOUNT";
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    AccessTokenKit::ReloadNativeTokenInfo();
    delete[] perms;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    NativeTokenGet();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::BindDomainAccountStubFuzzTest(data, size);
    return 0;
}
