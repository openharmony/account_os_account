/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "subscribeappaccount_fuzzer.h"

#include "app_account_manager.h"
#include "app_account_subscribe_info.h"
#include "account_log_wrapper.h"
#include <string>
#include <vector>

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
    bool SubscribeAppAccountFuzzTest(const uint8_t* data, size_t size)
    {
        bool result = false;
        if (size > 0) {
            std::string testOwner(reinterpret_cast<const char*>(data), size);
            std::vector<std::string> owners;
            owners.emplace_back(testOwner);
            AppAccountSubscribeInfo subscribeInfo(owners);
            auto subscriberTestPtr = std::make_shared<AppAccountSubscriberTest>(subscribeInfo);
            result = AppAccountManager::SubscribeAppAccount(subscriberTestPtr);
        }
        return result;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SubscribeAppAccountFuzzTest(data, size);
    return 0;
}

