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
THauthenticatorAsyncCallback::THauthenticatorAsyncCallback()
{}

THauthenticatorAsyncCallback::~THauthenticatorAsyncCallback()
{}

void THauthenticatorAsyncCallback::OnResult(int32_t resultCode, const AAFwk::Want &result)
{
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (isDone) {
            return;
        }
        isDone = true;
    }
    cv.notify_one();

    param = std::make_shared<AuthenticatorCallbackParam>();
    param->resultCode = resultCode;
    param->result = result;
}

void THauthenticatorAsyncCallback::OnRequestRedirected(AAFwk::Want &request)
{};

void THauthenticatorAsyncCallback::OnRequestContinued()
{};

SubscriberPtr::SubscriberPtr(const AccountSA::AppAccountSubscribeInfo &subscribeInfo,
    taihe::callback_view<void(taihe::array_view<ohos::account::appAccount::AppAccountInfo>)> callback):
    AccountSA::AppAccountSubscriber(subscribeInfo), callback_(callback)
{}

SubscriberPtr::~SubscriberPtr()
{}

void SubscriberPtr::OnAccountsChanged(const std::vector<AccountSA::AppAccountInfo> &accounts)
{
    std::vector<AccountSA::AppAccountInfo> tempAccountsInfos = accounts;
    std::vector<ohos::account::appAccount::AppAccountInfo> tempInfo;
    for (auto& accountInfo : tempAccountsInfos){
        ohos::account::appAccount::AppAccountInfo tempAccountInfo{
            .owner = taihe::string(accountInfo.GetOwner().c_str()),
            .name = taihe::string(accountInfo.GetName().c_str()),
        };
        tempInfo.push_back(tempAccountInfo);
    }
    active_callback call = callback_;
    call(tempInfo);
}

AppAccountManagerCallback::AppAccountManagerCallback(ohos::account::appAccount::AuthCallback callback) :
    callback_(callback)
{}

AppAccountManagerCallback::~AppAccountManagerCallback()
{};

void AppAccountManagerCallback::OnResult(int32_t resultCode, const AAFwk::Want &result)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (isDone) {
        return;
    }
    isDone = true;

    ACCOUNT_LOGI("Post task finish");
    do {
        ani_env *env = taihe::get_env();
        auto scalableData = AppExecFwk::WrapWantParams(env, result.GetParams());
        if (scalableData == nullptr) {
            ACCOUNT_LOGE("WrapWantParams get nullptr");
            break;
        }
        ohos::account::appAccount::AuthResult* authResult =
            reinterpret_cast<ohos::account::appAccount::AuthResult*>(scalableData);
        taihe::optional_view<ohos::account::appAccount::AuthResult> authResults(authResult);
        callback_.onResult(resultCode,authResults);
    } while (0);
    cv.notify_one();
}

void AppAccountManagerCallback::OnRequestRedirected(AAFwk::Want &request)
{
    do {
        ani_env *env = taihe::get_env();
        auto scalableData = AppExecFwk::WrapWantParams(env, request.GetParams());
        if (scalableData == nullptr) {
            ACCOUNT_LOGE("WrapWantParams get nullptr");
            break;
        }
        callback_.onRequestRedirected(reinterpret_cast<uintptr_t>(scalableData));
    } while (0);
}

void AppAccountManagerCallback::OnRequestContinued()
{};
}
}