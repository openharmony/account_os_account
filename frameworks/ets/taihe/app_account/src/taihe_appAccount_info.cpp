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
}

ErrCode THauthenticatorAsyncCallback::OnRequestContinued()
{
    return ERR_OK;
}

ErrCode THauthenticatorAsyncCallback::CallbackEnter([[maybe_unused]] uint32_t code)
{
    return ERR_OK;
}

ErrCode THauthenticatorAsyncCallback::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    switch (code) {
        case static_cast<uint32_t>(IAppAccountAuthenticatorCallbackIpcCode::COMMAND_ON_RESULT): {
            if (result == ERR_INVALID_DATA) {
                AAFwk::Want resultWant;
                OnResult(ERR_JS_ACCOUNT_AUTHENTICATOR_SERVICE_EXCEPTION, resultWant);
                return ERR_APPACCOUNT_SERVICE_OAUTH_INVALID_RESPONSE;
            }
            break;
        }
        case static_cast<uint32_t>(IAppAccountAuthenticatorCallbackIpcCode::COMMAND_ON_REQUEST_REDIRECTED): {
            if (result == ERR_INVALID_DATA) {
                AAFwk::Want request;
                OnRequestRedirected(request);
                return ERR_APPACCOUNT_SERVICE_OAUTH_INVALID_RESPONSE;
            }
            break;
        }
        default:
            return ERR_NONE;
    }
    return ERR_NONE;
}
}
}