/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "domain_account_plugin_service.h"

#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
DomainAccountPluginService::DomainAccountPluginService(const std::shared_ptr<DomainAccountPlugin> &plugin)
    : innerPlugin_(plugin)
{}

DomainAccountPluginService::~DomainAccountPluginService()
{}

ErrCode DomainAccountPluginService::CheckAndInitExecEnv(const sptr<IDomainAccountCallback> &callback,
    DomainAccountCallbackClient **callbackClient)
{
    if (innerPlugin_ == nullptr) {
        ACCOUNT_LOGE("innerPlugin_ is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    *callbackClient = new (std::nothrow) DomainAccountCallbackClient(callback);
    if (*callbackClient == nullptr) {
        ACCOUNT_LOGE("failed to create domain account callback client");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    return ERR_OK;
}

ErrCode DomainAccountPluginService::AuthCommonInterface(const DomainAccountInfo &info,
    const std::vector<uint8_t> &authData, const sptr<IDomainAccountCallback> &callback, AuthMode authMode)
{
    if (innerPlugin_ == nullptr) {
        ACCOUNT_LOGE("innerPlugin_ is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    auto callbackClient = std::make_shared<DomainAccountCallbackClient>(callback);
    if (callbackClient == nullptr) {
        ACCOUNT_LOGE("failed to create DomainAuthCallbackClient");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    switch (authMode) {
        case AUTH_WITH_CREDENTIAL_MODE: {
            innerPlugin_->Auth(info, authData, callbackClient);
            break;
        }
        case AUTH_WITH_POPUP_MODE: {
            innerPlugin_->AuthWithPopup(info, callbackClient);
            break;
        }
        case AUTH_WITH_TOKEN_MODE: {
            innerPlugin_->AuthWithToken(info, authData, callbackClient);
            break;
        }
        default: {
            ACCOUNT_LOGE("authMode is invalid");
            return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        }
    }
    return ERR_OK;
}

ErrCode DomainAccountPluginService::Auth(const DomainAccountInfo &info, const std::vector<uint8_t> &password,
    const sptr<IDomainAccountCallback> &callback)
{
    return AuthCommonInterface(info, password, callback, AUTH_WITH_CREDENTIAL_MODE);
}

ErrCode DomainAccountPluginService::AuthWithPopup(
    const DomainAccountInfo &info, const sptr<IDomainAccountCallback> &callback)
{
    return AuthCommonInterface(info, {}, callback, AUTH_WITH_POPUP_MODE);
}

ErrCode DomainAccountPluginService::AuthWithToken(
    const DomainAccountInfo &info, const std::vector<uint8_t> &token, const sptr<IDomainAccountCallback> &callback)
{
    return AuthCommonInterface(info, token, callback, AUTH_WITH_TOKEN_MODE);
}

ErrCode DomainAccountPluginService::IsAccountTokenValid(const AccountSA::DomainAccountInfo &info,
    const std::vector<uint8_t> &token, const sptr<IDomainAccountCallback> &callback)
{
    DomainAccountCallbackClient *callbackClient = nullptr;
    ErrCode errCode = CheckAndInitExecEnv(callback, &callbackClient);
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_ptr<DomainAccountCallbackClient> callbackPtr(callbackClient);
    innerPlugin_->IsAccountTokenValid(info, token, callbackPtr);
    return ERR_OK;
}

ErrCode DomainAccountPluginService::GetAccessToken(const DomainAccountInfo &domainInfo,
    const std::vector<uint8_t> &accountToken, const GetAccessTokenOptions &option,
    const sptr<IDomainAccountCallback> &callback)
{
    DomainAccountCallbackClient *callbackClient = nullptr;
    ErrCode errCode = CheckAndInitExecEnv(callback, &callbackClient);
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_ptr<DomainAccountCallbackClient> callbackPtr(callbackClient);
    innerPlugin_->GetAccessToken(domainInfo, accountToken, option, callbackPtr);
    return ERR_OK;
}

ErrCode DomainAccountPluginService::GetAuthStatusInfo(
    const DomainAccountInfo &accountInfo, const sptr<IDomainAccountCallback> &callback)
{
    if (innerPlugin_ == nullptr) {
        ACCOUNT_LOGE("innerPlugin_ is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    auto callbackClient = std::make_shared<DomainAccountCallbackClient>(callback);
    if (callbackClient == nullptr) {
        ACCOUNT_LOGE("failed to create DomainAccountCallbackClient");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    innerPlugin_->GetAuthStatusInfo(accountInfo, callbackClient);
    return ERR_OK;
}

ErrCode DomainAccountPluginService::GetDomainAccountInfo(
    const GetDomainAccountInfoOptions &options, const sptr<IDomainAccountCallback> &callback)
{
    DomainAccountCallbackClient *callbackClient = nullptr;
    ErrCode errCode = CheckAndInitExecEnv(callback, &callbackClient);
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_ptr<DomainAccountCallbackClient> callbackPtr(callbackClient);
    innerPlugin_->GetDomainAccountInfo(options, callbackPtr);
    return ERR_OK;
}

ErrCode DomainAccountPluginService::OnAccountBound(const DomainAccountInfo &info, const int32_t localId,
    const sptr<IDomainAccountCallback> &callback)
{
    DomainAccountCallbackClient *callbackClient = nullptr;
    ErrCode errCode = CheckAndInitExecEnv(callback, &callbackClient);
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_ptr<DomainAccountCallbackClient> callbackPtr(callbackClient);
    innerPlugin_->OnAccountBound(info, localId, callbackPtr);
    return ERR_OK;
}

ErrCode DomainAccountPluginService::OnAccountUnBound(const DomainAccountInfo &info,
    const sptr<IDomainAccountCallback> &callback)
{
    DomainAccountCallbackClient *callbackClient = nullptr;
    ErrCode errCode = CheckAndInitExecEnv(callback, &callbackClient);
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_ptr<DomainAccountCallbackClient> callbackPtr(callbackClient);
    innerPlugin_->OnAccountUnBound(info, callbackPtr);
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS