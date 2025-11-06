/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ACCOUNT_TAIHE_ACCOUNT_INFO_H
#define ACCOUNT_TAIHE_ACCOUNT_INFO_H

#include "account_iam_client.h"
#include "account_iam_info.h"
#include "os_account_manager.h"
#include "os_account_subscriber.h"
#include "os_account_subscribe_info.h"
#include "taihe_common.h"

using active_callback = taihe::callback<void(int32_t)>;
using switch_callback = taihe::callback<void(ohos::account::osAccount::OsAccountSwitchEventData const&)>;

namespace OHOS {
namespace AccountSA {
class TaiheSubscriberPtr : public AccountSA::OsAccountSubscriber {
public:
    explicit TaiheSubscriberPtr(const AccountSA::OsAccountSubscribeInfo &subscribeInfo);
    ~TaiheSubscriberPtr() override;

    void OnStateChanged(const OsAccountStateData &data) override;
    std::shared_ptr<active_callback> activeRef_ = nullptr;
    std::shared_ptr<switch_callback> switchRef_ = nullptr;
private:
    void OnAccountsChanged(const int &id);
    void OnAccountsSwitch(const int &newId, const int &oldId, std::optional<uint64_t> displayId);
};

struct TaiheUnsubscribeCBInfo   {
    AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE osSubscribeType = AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE::INVALID_TYPE;
    std::string name;
    std::shared_ptr<active_callback> activeCallbackRef = nullptr;
    std::shared_ptr<switch_callback> switchCallbackRef = nullptr;;
};

struct SubscribeCBInfo  {
    bool IsSameCallBack(AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE type, std::shared_ptr<active_callback> activeCallback,
        std::shared_ptr<switch_callback> switchCallback);
    AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE osSubscribeType = AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE::INVALID_TYPE;
    std::string name;
    AccountSA::OsAccountManager *osManager = nullptr;
    std::shared_ptr<active_callback> activeCallbackRef = nullptr;
    std::shared_ptr<switch_callback> switchCallbackRef = nullptr;
    std::shared_ptr<TaiheSubscriberPtr> subscriber = nullptr;
};

}
}
#endif // ACCOUNT_TAIHE_ACCOUNT_INFO_H