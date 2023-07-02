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

#include "unsubscribeappaccountstub_fuzzer.h"
#include <string>
#include <vector>

#include "account_log_wrapper.h"
#include "app_account_event_listener.h"
#include "app_account_manager_service.h"
#include "app_account_subscribe_info.h"
#include "app_account_subscriber.h"
#include "iapp_account.h"

using namespace std;
using namespace OHOS::AccountSA;
class AppAccountSubscriberTest : public AppAccountSubscriber {
public:
    explicit AppAccountSubscriberTest(const AppAccountSubscribeInfo &subscribeInfo)
        : AppAccountSubscriber(subscribeInfo)
    {
        ACCOUNT_LOGI("enter");
    }

    ~AppAccountSubscriberTest()
    {}

    virtual void OnAccountsChanged(const std::vector<AppAccountInfo> &accounts)
    {
        ACCOUNT_LOGI("enter");
    }
};
namespace OHOS {
const std::u16string APPACCOUNT_TOKEN = u"ohos.accountfwk.IAppAccount";
bool UnSubscribeAppAccountStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    MessageParcel dataTemp;
    if (!dataTemp.WriteInterfaceToken(APPACCOUNT_TOKEN)) {
        return false;
    }

    AppAccountSubscribeInfo subscribeInfo;
    std::shared_ptr<AppAccountSubscriberTest> appAccountSubscriberPtr =
        std::make_shared<AppAccountSubscriberTest>(subscribeInfo);
    auto appAccountEventListenerSptr = new (std::nothrow) AppAccountEventListener(appAccountSubscriberPtr);
    
    if (!dataTemp.WriteRemoteObject(appAccountEventListenerSptr->AsObject())) {
        return false;
    }
    
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(AppAccountInterfaceCode::UNSUBSCRIBE_ACCOUNT);
    auto appAccountManagerService = std::make_shared<AppAccountManagerService>();
    appAccountManagerService->OnRemoteRequest(code, dataTemp, reply, option);
    
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::UnSubscribeAppAccountStubFuzzTest(data, size);
    return 0;
}

