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
    if (activeRef_) {
        active_callback call = *activeRef_;
        call(id);
    } else {
        ACCOUNT_LOGE("activeRef_ is nullptr!");
    }
}

void TaiheSubscriberPtr::OnAccountsSwitch(const int &newId, const int &oldId)
{
    if (switchRef_) {
        TaiheOsAccountSwitchEventData data = {oldId, newId};
        switch_callback call = *switchRef_;
        call(data);
    } else {
        ACCOUNT_LOGE("switchRef_ is nullptr!");
    }
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
        if (*activeCallbackRef == *activeCallback) {
            return true;
        } else {
            ACCOUNT_LOGE("ActiveCallback is different!");
            return false;
        }
    } else {
        if (*switchCallbackRef == *switchCallback) {
            return true;
        } else {
            ACCOUNT_LOGE("SwitchCallback is different!");
            return false;
        }
    }
}
}
}