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

#include "app_account_check_labels_callback.h"

#include "app_account_authenticator_session_manager.h"
#include "account_log_wrapper.h"
#include "app_account_constants.h"

namespace OHOS {
namespace AccountSA {
AppAccountCheckLabelsCallback::AppAccountCheckLabelsCallback(std::vector<AppAccountInfo> accounts,
    const AuthenticatorSessionRequest &request, const std::string &sessionId)
    : accounts_(accounts), request_(request), sessionId_(sessionId)
{
    ACCOUNT_LOGD("enter");
}

AppAccountCheckLabelsCallback::~AppAccountCheckLabelsCallback()
{
    ACCOUNT_LOGD("enter");
}

void AppAccountCheckLabelsCallback::SendResult(int32_t resultCode)
{
    ACCOUNT_LOGD("enter");
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
    request_.callback->OnResult(resultCode, result);
}

ErrCode AppAccountCheckLabelsCallback::CheckLabels()
{
    ACCOUNT_LOGD("enter");
    auto sessionManager = AppAccountAuthenticatorSessionManager::GetInstance();
    if (sessionManager == nullptr) {
        return ERR_APPACCOUNT_SERVICE_OAUTH_SERVICE_EXCEPTION;
    }
    if (index_ >= accounts_.size()) {
        SendResult(ERR_JS_SUCCESS);
        sessionManager->CloseSession(sessionId_);
        return ERR_OK;
    }
    AppAccountInfo account = accounts_[index_];
    AuthenticatorSessionRequest newRequest = request_;
    account.GetOwner(newRequest.owner);
    account.GetName(newRequest.name);
    newRequest.callback = this;
    ErrCode result = sessionManager->CheckAccountLabels(newRequest);
    if (result != ERR_OK) {
        SendResult(ERR_JS_OAUTH_SERVICE_EXCEPTION);
        sessionManager->CloseSession(sessionId_);
    }
    return ERR_OK;
}

void AppAccountCheckLabelsCallback::OnResult(int32_t resultCode, const AAFwk::Want &result)
{
    ACCOUNT_LOGD("enter");
    if (result.GetBoolParam(Constants::KEY_BOOL_RESULT, false)) {
        accountsWithLabels_.push_back(accounts_[index_]);
    }
    index_++;
    CheckLabels();
}

void AppAccountCheckLabelsCallback::OnRequestRedirected(AAFwk::Want &request)
{
    index_++;
    CheckLabels();
}

void AppAccountCheckLabelsCallback::OnRequestContinued()
{
    index_++;
    CheckLabels();
}
}  // namespace AccountSA
}  // namespace OHOS
