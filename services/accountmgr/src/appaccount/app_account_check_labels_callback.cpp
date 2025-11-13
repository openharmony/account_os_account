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
namespace {
static const char* ACCOUNT_KEY = "account";
static const char* ACCOUNT_OWNER_KEY = "owner";
static const char* ACCOUNT_NAME_KEY = "name";
}

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
    if (result.HasParameter(Constants::KEY_BOOLEAN_RESULT)) {
        // in old callback (below API 9), would ignore resultCode
        OnResultAPI8(result);
    } else {
        // if KEY_BOOLEAN_RESULT not in result, it's new callback (API 9 and above) or
        // considered as new callback
        if (!OnResultAPI9(resultCode, result)) {
            ACCOUNT_LOGE("Authenticator failed, resultCode = %{public}d", resultCode);
            SendResult(ERR_JS_ACCOUNT_AUTHENTICATOR_SERVICE_EXCEPTION);
            AppAccountAuthenticatorSessionManager::GetInstance().CloseSession(sessionId_);
            return ERR_OK;
        }
    }
    index_++;
    CheckLabels();
    return ERR_OK;
}

void AppAccountCheckLabelsCallback::OnResultAPI8(const AAFwk::Want &result)
{
    if (result.GetBoolParam(Constants::KEY_BOOLEAN_RESULT, false) && (index_ < accounts_.size())) {
        accountsWithLabels_.push_back(accounts_[index_]);
    }
}

bool AppAccountCheckLabelsCallback::OnResultAPI9(int32_t resultCode, const AAFwk::Want &result)
{
    if ((resultCode == ERR_JS_ACCOUNT_NOT_FOUND) || (index_ >= accounts_.size())) {
        // Authenticator return account not found, consider not found.
        return true;
    }
    if (resultCode != ERR_OK) {
        // if resultCode is not ERR_JS_ACCOUNT_NOT_FOUND, considered as ERR_JS_ACCOUNT_AUTHENTICATOR_SERVICE_EXCEPTION
        return false;
    }
    NativeAppAuthResult authResult(result);
    if (!authResult.hasAuthResult || !authResult.account.has_value()) {
        // Do not have auth result, consider check failed
        ACCOUNT_LOGW("Do not have auth result or account info.");
        return true;
    }
    if ((authResult.account->name_ == accounts_[index_].name_) &&
        (authResult.account->owner_ == accounts_[index_].owner_)) {
        accountsWithLabels_.push_back(accounts_[index_]);
        return true;
    }
    ACCOUNT_LOGE("Check labels failed, name or owner not match");
    return true;
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

NativeAppAuthResult::NativeAppAuthResult(const AAFwk::Want &result)
{
    auto params = result.GetParams();
    if (params.IsEmpty()) {
        ACCOUNT_LOGE("Param in want is empty");
        return;
    }
    hasAuthResult = true;
    auto accountWant = params.GetWantParams(ACCOUNT_KEY);
    if (!accountWant.IsEmpty()) {
        auto accountName = accountWant.GetStringParam(ACCOUNT_NAME_KEY);
        auto accountOwner = accountWant.GetStringParam(ACCOUNT_OWNER_KEY);
        AppAccountInfo accountInfo(accountName, accountOwner);
        account = accountInfo;
    }
}

CheckLabelsCallbackHelper::CheckLabelsCallbackHelper(
    const std::string &name, const std::string &owner, const sptr<IAppAccountAuthenticatorCallback> &callback)
    : name_(name), owner_(owner), callback_(callback)
{}

ErrCode CheckLabelsCallbackHelper::OnRequestRedirected(const AAFwk::Want &request)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return callback_->OnRequestRedirected(request);
}

ErrCode CheckLabelsCallbackHelper::OnRequestContinued()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return callback_->OnRequestContinued();
}

ErrCode CheckLabelsCallbackHelper::OnResult(int32_t resultCode, const AAFwk::Want &result)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (result.HasParameter(Constants::KEY_BOOLEAN_RESULT)) {
        // in old callback (below API 9), would do nothing
        return callback_->OnResult(resultCode, result);
    } else {
        // if KEY_BOOLEAN_RESULT not in result, it's new callback (API 9 and above) or
        // considered as new callback
        return OnResultAPI9(resultCode, result);
    }
}

ErrCode CheckLabelsCallbackHelper::OnResultAPI9(int32_t resultCode, const AAFwk::Want &result)
{
    AAFwk::Want want;
    AAFwk::WantParams params;
    if (resultCode == ERR_JS_ACCOUNT_NOT_FOUND) {
        // Authenticator return account not found, should return ERR_JS_ACCOUNT_NOT_FOUND
        return callback_->OnResult(ERR_JS_ACCOUNT_NOT_FOUND, want);
    }
    if (resultCode != ERR_OK) {
        // if resultCode is other code, considered as ERR_JS_ACCOUNT_AUTHENTICATOR_SERVICE_EXCEPTION
        ACCOUNT_LOGE(
            "Authenticator failed during check labels, considered as authenticator error, resultCode = %{public}d",
            resultCode);
        return callback_->OnResult(ERR_JS_ACCOUNT_AUTHENTICATOR_SERVICE_EXCEPTION, want);
    }
    NativeAppAuthResult authResult(result);
    if (!authResult.hasAuthResult || !authResult.account.has_value()) {
        ACCOUNT_LOGE("Auth result or account is not found");
        // Do not have auth result, consider check failed
        want.SetParam(Constants::KEY_BOOLEAN_RESULT, false);
        return callback_->OnResult(resultCode, want);
    }
    if ((authResult.account->name_ == name_) && (authResult.account->owner_ == owner_)) {
        want.SetParam(Constants::KEY_BOOLEAN_RESULT, true);
        return callback_->OnResult(resultCode, want);
    }
    ACCOUNT_LOGE("Check labels failed, name or owner not match");
    want.SetParam(Constants::KEY_BOOLEAN_RESULT, false);
    return callback_->OnResult(resultCode, want);
}
}  // namespace AccountSA
}  // namespace OHOS
