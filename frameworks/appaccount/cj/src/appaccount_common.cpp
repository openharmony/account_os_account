/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include "appaccount_common.h"

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "app_account_constants.h"
#include "app_account_manager.h"

namespace OHOS::AccountSA {
AuthenticatorAsyncCallback::AuthenticatorAsyncCallback(
    std::function<void(RetDataBool)> cRef,
    std::function<void(ErrCArrAppAccountInfo)> sRef)
    : checkAccountLabelsCallbackRef(cRef), selectAccountsCallbackRef(sRef) {}

AuthenticatorAsyncCallback::~AuthenticatorAsyncCallback() {}

ErrCode AuthenticatorAsyncCallback::OnResult(int32_t resultCode, const AAFwk::Want &result)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (isDone) {
            return ERR_OK;
        }
        isDone = true;
    }
    
    this->errCode = resultCode;
    this->onResultRetBool = result.GetBoolParam(Constants::KEY_BOOLEAN_RESULT, false);
    this->onResultRetNames = result.GetStringArrayParam(Constants::KEY_ACCOUNT_NAMES);
    this->onResultRetOwners = result.GetStringArrayParam(Constants::KEY_ACCOUNT_OWNERS);
    return ERR_OK;
}

ErrCode AuthenticatorAsyncCallback::OnRequestRedirected(const AAFwk::Want &request)
{
    return ERR_OK;
}

ErrCode AuthenticatorAsyncCallback::OnRequestContinued()
{
    return ERR_OK;
}

AppAccountManagerCallback::AppAccountManagerCallback(JSAuthCallback callback): callback_(callback) {}

AppAccountManagerCallback::~AppAccountManagerCallback() {}

ErrCode AppAccountManagerCallback::OnResult(int32_t resultCode, const AAFwk::Want &result)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (isDone) {
            return ERR_OK;
        }
        isDone = true;
    }
    
    this->errCode = resultCode;
    // account: AppAccountInfo
    this->nameResult = result.GetStringParam(Constants::KEY_ACCOUNT_NAMES);
    this->ownerResult = result.GetStringParam(Constants::KEY_ACCOUNT_OWNERS);
    //tokenInfo: AuthTokenInfo
    this->authTypeResult = result.GetStringParam(Constants::KEY_AUTH_TYPE);
    this->tokenResult = result.GetStringParam(Constants::KEY_TOKEN);
    return ERR_OK;
}

ErrCode AppAccountManagerCallback::OnRequestRedirected(const AAFwk::Want &request)
{
    return ERR_OK;
}

ErrCode AppAccountManagerCallback::OnRequestContinued()
{
    return ERR_OK;
}

SubscribePtr::SubscribePtr(const AppAccountSubscribeInfo &subscribeInfo) : AppAccountSubscriber(subscribeInfo) {}

void SubscribePtr::OnAccountsChanged(const std::vector<AppAccountInfo>  &accounts) {}
void SubscribePtr::SetCallbackRef(std::function<void(CArrAppAccountInfo)> callbackRef)
{
    ref_ = callbackRef;
}
} // namespace::OHOS::AccountSA