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

#include "taihe_account_info.h"
#include "account_log_wrapper.h"
namespace OHOS {
namespace AccountSA {
TaiheSubscriberPtr::TaiheSubscriberPtr(const AccountSA::OsAccountSubscribeInfo &subscribeInfo)
    :OsAccountSubscriber(subscribeInfo)
{}

TaiheSubscriberPtr::~TaiheSubscriberPtr()
{}

void TaiheSubscriberPtr::OnAccountsChanged(const int &id)
{
    ACCOUNT_LOGE("OnAccountsChanged enter");
    active_callback call = *ref_;
    call(static_cast<double>(id));
}

void TaiheSubscriberPtr::OnAccountsSwitch(const int &newId, const int &oldId)
{
    ACCOUNT_LOGE("OnAccountsSwitchenter");
    TaiheOsAccountSwitchEventData data = {static_cast<double>(oldId), static_cast<double>(newId)};
}

bool SubscribeCBInfo::IsSameCallBack(AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE type,
    std::shared_ptr<active_callback> activeCallback, std::shared_ptr<switch_callback> switchCallback)
{
    if (type != osSubscribeType) {
        ACCOUNT_LOGE("Type is different!");
        return false;
    }
    if (osSubscribeType == AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATED ||
        osSubscribeType == AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATING) {
        if (activeCallbackRef.get() == activeCallback.get()) {
            return true;
        } else {
            ACCOUNT_LOGE("ActiveCallback is different!");
            return false;
        }
    } else {
        if (switchCallbackRef.get() == switchCallback.get()) {
            return true;
            ACCOUNT_LOGE("SwitchCallback is different!");
        } else {
            return false;
        }
    }
}
}
}