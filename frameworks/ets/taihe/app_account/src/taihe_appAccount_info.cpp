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

#include "taihe_appAccount_info.h"

namespace OHOS {
namespace AccountSA {
SubscriberPtr::SubscriberPtr(const AccountSA::AppAccountSubscribeInfo &subscribeInfo,
    subscribe_callback callback):AccountSA::AppAccountSubscriber(subscribeInfo), callback_(callback)
{}

SubscriberPtr::~SubscriberPtr()
{}

void SubscriberPtr::OnAccountsChanged(const std::vector<AccountSA::AppAccountInfo> &accounts)
{
    std::lock_guard<std::mutex> lock(g_thLockForAppAccountSubscribers);
    SubscriberPtr *subscriber = this;
    bool isFound = false;
    for (const auto& objectInfoTmp : AccountSA::g_ThAppAccountSubscribers) {
        for (const auto& item : objectInfoTmp.second) {
            if (item->subscriber.get() == subscriber) {
                isFound = true;
                break;
            }
        }
        if (isFound) break;
    }

    if (!isFound) {
        return;
    }

    std::vector<AccountSA::AppAccountInfo> tempAccountsInfos = accounts;
    std::vector<ohos::account::appAccount::AppAccountInfo> tempInfo;
    for (auto& accountInfo : tempAccountsInfos) {
        ohos::account::appAccount::AppAccountInfo tempAccountInfo{
            .owner = taihe::string(accountInfo.GetOwner().c_str()),
            .name = taihe::string(accountInfo.GetName().c_str()),
        };
        tempInfo.push_back(tempAccountInfo);
    }
    subscribe_callback call = callback_;
    call(tempInfo);
}
THauthenticatorAsyncCallback::THauthenticatorAsyncCallback()
{}

THauthenticatorAsyncCallback::~THauthenticatorAsyncCallback()
{}

ErrCode THauthenticatorAsyncCallback::OnResult(int32_t resultCode, const AAFwk::Want &result)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (isDone_) {
        return ERR_OK;
    }
    isDone_ = true;
    param_ = std::make_shared<AuthenticatorCallbackParam>();
    param_->resultCode = resultCode;
    param_->result = result;
    cv_.notify_one();
    return ERR_OK;
}

ErrCode THauthenticatorAsyncCallback::OnRequestRedirected(const AAFwk::Want &request)
{
    return ERR_OK;
};

ErrCode THauthenticatorAsyncCallback::OnRequestContinued()
{
    return ERR_OK;
};
}
}