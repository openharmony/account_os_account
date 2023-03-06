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

#include "inner_domain_account_manager.h"
#include "account_log_wrapper.h"
#include "domain_account_plugin_death_recipient.h"
#include "domain_auth_callback_proxy.h"
#include "domain_account_callback_service.h"
#include "domain_has_domain_info_callback.h"
#include "idomain_account_callback.h"
#include "iinner_os_account_manager.h"

namespace OHOS {
namespace AccountSA {
InnerDomainAccountManager &InnerDomainAccountManager::GetInstance()
{
    static InnerDomainAccountManager instance;
    return instance;
}

InnerDomainAuthCallback::InnerDomainAuthCallback(int32_t userId, const sptr<IDomainAuthCallback> &callback)
    : userId_(userId), callback_(callback)
{}

InnerDomainAuthCallback::~InnerDomainAuthCallback()
{}

void InnerDomainAuthCallback::OnResult(int32_t resultCode, const DomainAuthResult &result)
{
    if ((resultCode == ERR_OK) && (userId_ != 0)) {
        InnerDomainAccountManager::GetInstance().InsertTokenToMap(userId_, result.token);
    }
    if (callback_ == nullptr) {
        ACCOUNT_LOGI("callback_ is nullptr");
        return;
    }
    return callback_->OnResult(resultCode, result);
}

ErrCode InnerDomainAccountManager::RegisterPlugin(const sptr<IDomainAccountPlugin> &plugin)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (plugin == nullptr) {
        ACCOUNT_LOGE("the registered plugin is nullptr");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMTER;
    }
    if (plugin_ != nullptr) {
        ACCOUNT_LOGE("plugin already exists");
        return ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_ALREADY_EXIST;
    }
    auto deathRecipient = GetDeathRecipient();
    if ((deathRecipient == nullptr) || (!plugin->AsObject()->AddDeathRecipient(deathRecipient))) {
        ACCOUNT_LOGE("failed to add death recipient for plugin");
        return ERR_ACCOUNT_COMMON_ADD_DEATH_RECIPIENT;
    }
    plugin_ = plugin;
    return ERR_OK;
}

void InnerDomainAccountManager::UnregisterPlugin()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if ((plugin_ != nullptr) && (plugin_->AsObject() != nullptr)) {
        plugin_->AsObject()->RemoveDeathRecipient(deathRecipient_);
    }
    plugin_ = nullptr;
    deathRecipient_ = nullptr;
}

ErrCode InnerDomainAccountManager::StartAuth(const sptr<IDomainAccountPlugin> &plugin, const DomainAccountInfo &info,
    const std::vector<uint8_t> &authData, const sptr<IDomainAuthCallback> &callback, AuthMode authMode)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("invalid callback, cannot return result to client");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMTER;
    }
    DomainAuthResult emptyResult = {};
    if (plugin == nullptr) {
        ACCOUNT_LOGE("plugin is not exixt");
        callback->OnResult(ConvertToJSErrCode(ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST), emptyResult);
        return ERR_ACCOUNT_COMMON_INVALID_PARAMTER;
    }
    ErrCode errCode = ERR_ACCOUNT_COMMON_INVALID_PARAMTER;
    switch (authMode) {
        case AUTH_WITH_CREDENTIAL_MODE:
            errCode = plugin->Auth(info, authData, callback);
            break;
        case AUTH_WITH_POPUP_MODE:
            errCode = plugin->AuthWithPopup(info, callback);
            break;
        case AUTH_WITH_TOKEN_MODE:
            errCode = plugin->AuthWithToken(info, authData, callback);
            break;
        default:
            break;
    }
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("failed to auth domain account, errCode: %{public}d", errCode);
        callback->OnResult(ConvertToJSErrCode(errCode), emptyResult);
        return errCode;
    }
    return ERR_OK;
}

ErrCode InnerDomainAccountManager::PostTask(AppExecFwk::InnerEvent::Callback &task)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto handler = GetEventHandler();
    if (handler == nullptr) {
        ACCOUNT_LOGE("failed to create EventHandler");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
        if (!handler->PostTask(task)) {
        ACCOUNT_LOGE("failed to post task");
        return ERR_ACCOUNT_COMMON_POST_TASK;
    }
    return ERR_OK;
}

ErrCode InnerDomainAccountManager::GetDomainAccountInfoByUserId(int32_t userId, DomainAccountInfo &domainInfo)
{
    OsAccountInfo accountInfo;
    ErrCode errCode = IInnerOsAccountManager::GetInstance()->QueryOsAccountById(userId, accountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("get os account info failed, errCode: %{public}d", errCode);
        return errCode;
    }
    accountInfo.GetDomainInfo(domainInfo);
    if (domainInfo.accountName_.empty()) {
        ACCOUNT_LOGE("the target user is not a domain account");
        return ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST;
    }
    return ERR_OK;
}

ErrCode InnerDomainAccountManager::Auth(const DomainAccountInfo &info, const std::vector<uint8_t> &password,
    const sptr<IDomainAuthCallback> &callback)
{
    int32_t userId = 0;
    sptr<IDomainAuthCallback> innerCallback = callback;
    IInnerOsAccountManager::GetInstance()->GetOsAccountLocalIdFromDomain(info, userId);
    if (userId != 0) {
        innerCallback = new (std::nothrow) InnerDomainAuthCallback(userId, callback);
        if (innerCallback == nullptr) {
            ACCOUNT_LOGE("failed to create innerCallback");
            innerCallback = callback;
        }
    }
    AppExecFwk::InnerEvent::Callback task = std::bind(&InnerDomainAccountManager::StartAuth,
        this, plugin_, info, password, innerCallback, AUTH_WITH_CREDENTIAL_MODE);
    return PostTask(task);
}

ErrCode InnerDomainAccountManager::InnerAuth(int32_t userId, const std::vector<uint8_t> &authData,
    const sptr<IDomainAuthCallback> &callback, AuthMode authMode)
{
    DomainAccountInfo domainInfo;
    ErrCode errCode = GetDomainAccountInfoByUserId(userId, domainInfo);
    if (errCode != ERR_OK) {
        return errCode;
    }
    sptr<InnerDomainAuthCallback> innerCallback = new (std::nothrow) InnerDomainAuthCallback(userId, callback);
    if (innerCallback == nullptr) {
        ACCOUNT_LOGE("failed to create innerCallback");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    AppExecFwk::InnerEvent::Callback task =
        std::bind(&InnerDomainAccountManager::StartAuth, this, plugin_, domainInfo, authData, innerCallback, authMode);
    return PostTask(task);
}

ErrCode InnerDomainAccountManager::AuthUser(int32_t userId, const std::vector<uint8_t> &password,
    const sptr<IDomainAuthCallback> &callback)
{
    return InnerAuth(userId, password, callback, AUTH_WITH_CREDENTIAL_MODE);
}

ErrCode InnerDomainAccountManager::AuthWithPopup(int32_t userId, const sptr<IDomainAuthCallback> &callback)
{
    if (userId == 0) {
        std::vector<int32_t> userIds;
        (void)IInnerOsAccountManager::GetInstance()->QueryActiveOsAccountIds(userIds);
        if (userIds.empty()) {
            ACCOUNT_LOGE("fail to get activated os account ids");
            return ERR_OSACCOUNT_SERVICE_INNER_CANNOT_FIND_OSACCOUNT_ERROR;
        }
        userId = userIds[0];
    }
    return InnerAuth(userId, {}, callback, AUTH_WITH_POPUP_MODE);
}

ErrCode InnerDomainAccountManager::AuthWithToken(int32_t userId, const std::vector<uint8_t> &token)
{
    return InnerAuth(userId, token, nullptr, AUTH_WITH_TOKEN_MODE);
}

void InnerDomainAccountManager::InsertTokenToMap(int32_t userId, const std::vector<uint8_t> &token)
{
    std::lock_guard<std::mutex> lock(mutex_);
    userTokenMap_[userId] = token;
    return;
}

std::vector<uint8_t> InnerDomainAccountManager::GetTokenFromMap(int32_t userId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    return userTokenMap_[userId];
}

void InnerDomainAccountManager::RemoveTokenFromMap(int32_t userId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    userTokenMap_.erase(userId);
    return;
}

ErrCode InnerDomainAccountManager::GetAuthStatusInfo(
    const DomainAccountInfo &info, const sptr<IDomainAccountCallback> &callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (plugin_ == nullptr) {
        ACCOUNT_LOGE("plugin not exists");
        return ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST;
    }
    return plugin_->GetAuthStatusInfo(info, callback);
}

std::shared_ptr<AppExecFwk::EventHandler> InnerDomainAccountManager::GetEventHandler()
{
    if (handler_ != nullptr) {
        return handler_;
    }
    handler_ = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::Create());
    return handler_;
}

sptr<IRemoteObject::DeathRecipient> InnerDomainAccountManager::GetDeathRecipient()
{
    if (deathRecipient_ != nullptr) {
        return deathRecipient_;
    }
    deathRecipient_ = new (std::nothrow) DomainAccountPluginDeathRecipient();
    return deathRecipient_;
}

bool InnerDomainAccountManager::IsPluginAvailable()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return plugin_ != nullptr;
}

static void ErrorOnResult(const ErrCode errCode, const sptr<IDomainAccountCallback> &callback)
{
    Parcel emptyParcel;
    emptyParcel.WriteBool(false);
    callback->OnResult(errCode, emptyParcel);
}

ErrCode InnerDomainAccountManager::StartHasDomainAccount(const sptr<IDomainAccountPlugin> &plugin,
    const DomainAccountInfo &info, const sptr<IDomainAccountCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("invalid callback");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMTER;
    }
    if (plugin == nullptr) {
        ACCOUNT_LOGE("plugin is nullptr");
        ErrorOnResult(ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST, callback);
        return ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST;
    }
    auto callbackWrapper = std::make_shared<DomainHasDomainInfoCallback>(callback, info.domain_, info.accountName_);
    if (callbackWrapper == nullptr) {
        ACCOUNT_LOGE("make shared DomainHasDomainInfoCallback failed");
        ErrorOnResult(ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR, callback);
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    sptr<DomainAccountCallbackService> callbackService =
        new (std::nothrow) DomainAccountCallbackService(callbackWrapper);
    if (callbackService == nullptr) {
        ACCOUNT_LOGE("make shared DomainAccountCallbackService failed");
        ErrorOnResult(ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR, callback);
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    ErrCode result = plugin->GetDomainAccountInfo(info.domain_, info.accountName_, callbackService);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get domain account, errCode: %{public}d", result);
        ErrorOnResult(result, callback);
        return result;
    }
    return ERR_OK;
}

ErrCode InnerDomainAccountManager::HasDomainAccount(
    const DomainAccountInfo &info, const sptr<IDomainAccountCallback> &callback)
{
    AppExecFwk::InnerEvent::Callback task =
        std::bind(&InnerDomainAccountManager::StartHasDomainAccount, this, plugin_, info, callback);
    return PostTask(task);
}

void InnerDomainAccountManager::StartOnAccountBound(const sptr<IDomainAccountPlugin> &plugin,
    const DomainAccountInfo &info, const int32_t localId, const sptr<IDomainAccountCallback> &callback)
{
    if (plugin_ == nullptr) {
        ACCOUNT_LOGE("plugin not exists");
        return ErrorOnResult(ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST, callback);
    }
    plugin->OnAccountBound(info, localId, callback);
}

ErrCode InnerDomainAccountManager::OnAccountBound(const DomainAccountInfo &info, const int32_t localId,
    const std::shared_ptr<DomainAccountCallback> &callback)
{
    sptr<DomainAccountCallbackService> callbackService = new (std::nothrow) DomainAccountCallbackService(callback);
    if (callbackService == nullptr) {
        ACCOUNT_LOGE("make shared DomainAccountCallbackService failed");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    AppExecFwk::InnerEvent::Callback task =
        std::bind(&InnerDomainAccountManager::StartOnAccountBound, this, plugin_, info, localId, callbackService);
    return PostTask(task);
}

void InnerDomainAccountManager::StartOnAccountUnBound(const sptr<IDomainAccountPlugin> &plugin,
    const DomainAccountInfo &info, const sptr<IDomainAccountCallback> &callback)
{
    if (plugin_ == nullptr) {
        ACCOUNT_LOGE("plugin not exists");
        return ErrorOnResult(ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST, callback);
    }
    plugin->OnAccountUnBound(info, callback);
}

ErrCode InnerDomainAccountManager::OnAccountUnBound(const DomainAccountInfo &info,
    const std::shared_ptr<DomainAccountCallback> &callback)
{
    sptr<DomainAccountCallbackService> callbackService = new (std::nothrow) DomainAccountCallbackService(callback);
    if (callbackService == nullptr) {
        ACCOUNT_LOGE("make shared DomainAccountCallbackService failed");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    AppExecFwk::InnerEvent::Callback task =
        std::bind(&InnerDomainAccountManager::StartOnAccountUnBound, this, plugin_, info, callbackService);
    return PostTask(task);
}

void InnerDomainAccountManager::StartGetDomainAccountInfo(const sptr<IDomainAccountPlugin> &plugin,
    const std::string &domain, const std::string &accountName, const sptr<IDomainAccountCallback> &callback)
{
    if (plugin_ == nullptr) {
        ACCOUNT_LOGE("plugin not exists");
        return ErrorOnResult(ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST, callback);
    }
    ErrCode errCode = plugin->GetDomainAccountInfo(domain, accountName, callback);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("failed to get domain account, errCode: %{public}d", errCode);
        ErrorOnResult(errCode, callback);
    }
}

ErrCode InnerDomainAccountManager::GetDomainAccountInfo(
    const std::string &domain, const std::string &accountName, const std::shared_ptr<DomainAccountCallback> &callback)
{
    sptr<DomainAccountCallbackService> callbackService = new (std::nothrow) DomainAccountCallbackService(callback);
    if (callbackService == nullptr) {
        ACCOUNT_LOGE("make shared DomainAccountCallbackService failed");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    AppExecFwk::InnerEvent::Callback task = std::bind(&InnerDomainAccountManager::StartGetDomainAccountInfo, this,
        plugin_, domain, accountName, callbackService);
    return PostTask(task);
}
}  // namespace AccountSA
}  // namespace OHOS
