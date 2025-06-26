/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "app_account_check_labels_callback.h"

#include "app_account_authenticator_session_manager.h"
#include "account_log_wrapper.h"
#include "app_account_constants.h"

namespace OHOS {
namespace AccountSA {
AppAccountCheckLabelsCallback::AppAccountCheckLabelsCallback(std::vector<AppAccountInfo> accounts,
    const AuthenticatorSessionRequest &request, const std::string &sessionId)
    : accounts_(accounts), request_(request), sessionId_(sessionId)
{}

AppAccountCheckLabelsCallback::~AppAccountCheckLabelsCallback()
{}

void AppAccountCheckLabelsCallback::SendResult(int32_t resultCode)
{
    AAFwk::Want result;
    if (resultCode == ERR_JS_SUCCESS) {
        std::vector<std::string> names;
        std::vector<std::string> owners;
        for (auto account : accountsWithLabels_) {
            names.push_back(account.GetName());
            owners.push_back(account.GetOwner());
        }
        result.SetParam(Constants::KEY_ACCOUNT_NAMES, names);
        result.SetParam(Constants::KEY_ACCOUNT_OWNERS, owners);
    }
    AppAccountAuthenticatorSessionManager::GetInstance().OnSessionResult(sessionId_, resultCode, result);
}

ErrCode AppAccountCheckLabelsCallback::CheckLabels()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto &sessionManager = AppAccountAuthenticatorSessionManager::GetInstance();
    while (index_ < accounts_.size()) {
        AppAccountInfo account = accounts_[index_];
        AuthenticatorSessionRequest newRequest = request_;
        account.GetOwner(newRequest.owner);
        account.GetName(newRequest.name);
        newRequest.callback = this;
        isRequesting_ = true;
        if (sessionManager.CheckAccountLabels(newRequest) == ERR_OK) {
            break;
        }
        isRequesting_ = false;
        index_++;
    }
    if (index_ >= accounts_.size()) {
        SendResult(ERR_JS_SUCCESS);
        sessionManager.CloseSession(sessionId_);
        return ERR_OK;
    }
    return ERR_OK;
}

ErrCode AppAccountCheckLabelsCallback::OnResult(int32_t resultCode, const AAFwk::Want &result)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!isRequesting_) {
        ACCOUNT_LOGE("Invalid request");
        return ERR_OK;
    }
    isRequesting_ = false;
    if (result.GetBoolParam(Constants::KEY_BOOLEAN_RESULT, false) && (index_ < accounts_.size())) {
        accountsWithLabels_.push_back(accounts_[index_]);
    }
    index_++;
    CheckLabels();
    return ERR_OK;
}

ErrCode AppAccountCheckLabelsCallback::OnRequestRedirected(const AAFwk::Want &request)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!isRequesting_) {
        ACCOUNT_LOGE("Invalid request");
        return ERR_OK;
    }
    isRequesting_ = false;
    index_++;
    CheckLabels();
    return ERR_OK;
}

ErrCode AppAccountCheckLabelsCallback::OnRequestContinued()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!isRequesting_) {
        ACCOUNT_LOGE("Invalid request");
        return ERR_OK;
    }
    isRequesting_ = false;
    index_++;
    CheckLabels();
    return ERR_OK;
}

ErrCode AppAccountCheckLabelsCallback::CallbackEnter([[maybe_unused]] uint32_t code)
{
    return ERR_OK;
}

ErrCode AppAccountCheckLabelsCallback::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
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
}  // namespace AccountSA
}  // namespace OHOS
