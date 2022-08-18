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

#include "account_iam_client.h"

#include "account_error_no.h"
#include "account_iam_callback_service.h"
#include "account_log_wrapper.h"
#include "account_proxy.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AccountSA {
AccountIAMClient::AccountIAMClient()
{}

void AccountIAMClient::OpenSession(int32_t userId, std::vector<uint8_t> &challenge)
{
    if (GetAccountIAMProxy() != ERR_OK) {
        ACCOUNT_LOGD("fail to get account iam proxy");
        return;
    }
    proxy_->OpenSession(userId, challenge);
}

void AccountIAMClient::CloseSession(int32_t userId)
{
    if (GetAccountIAMProxy() != ERR_OK) {
        ACCOUNT_LOGD("fail to get account iam proxy");
        return;
    }
    proxy_->CloseSession(userId);
}

void AccountIAMClient::AddCredential(
    int32_t userId, const CredentialParameters& credInfo, const std::shared_ptr<IDMCallback> &callback)
{
    if (GetAccountIAMProxy() != ERR_OK) {
        ACCOUNT_LOGD("fail to get account iam proxy");
        return;
    }
    sptr<IIDMCallback> wrapper = new (std::nothrow) IDMCallbackService(callback);
    proxy_->AddCredential(userId, credInfo, wrapper);
}

void AccountIAMClient::UpdateCredential(
    int32_t userId, const CredentialParameters& credInfo, const std::shared_ptr<IDMCallback> &callback)
{
    if (GetAccountIAMProxy() != ERR_OK) {
        ACCOUNT_LOGD("fail to get account iam proxy");
        return;
    }
    sptr<IIDMCallback> wrapper = new (std::nothrow) IDMCallbackService(callback);
    proxy_->UpdateCredential(userId, credInfo, wrapper);
}

void AccountIAMClient::DelCred(int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken,
    const std::shared_ptr<IDMCallback>& callback)
{
    if (GetAccountIAMProxy() != ERR_OK) {
        ACCOUNT_LOGD("fail to get account iam proxy");
        return;
    }
    sptr<IIDMCallback> wrapper = new (std::nothrow) IDMCallbackService(callback);
    proxy_->DelCred(userId, credentialId, authToken, wrapper);
}

void AccountIAMClient::DelUser(
    int32_t userId, const std::vector<uint8_t> &authToken, const std::shared_ptr<IDMCallback> &callback)
{
    if (GetAccountIAMProxy() != ERR_OK) {
        ACCOUNT_LOGD("fail to get account iam proxy");
        return;
    }
    sptr<IIDMCallback> wrapper = new (std::nothrow) IDMCallbackService(callback);
    proxy_->DelUser(userId, authToken, wrapper);
}

void AccountIAMClient::GetCredentialInfo(
    int32_t userId, AuthType authType, const std::shared_ptr<GetCredInfoCallback> &callback)
{
    if (GetAccountIAMProxy() != ERR_OK) {
        ACCOUNT_LOGD("fail to get account iam proxy");
        return;
    }
    sptr<IGetCredInfoCallback> wrapper = new (std::nothrow) GetCredInfoCallbackService(callback);
    proxy_->GetCredentialInfo(userId, authType, wrapper);
}

int32_t AccountIAMClient::Cancel(int32_t userId, uint64_t challenge)
{
    if (GetAccountIAMProxy() != ERR_OK) {
        ACCOUNT_LOGD("fail to get account iam proxy");
        return ResultCode::FAIL;
    }
    return proxy_->Cancel(userId, challenge);
}

uint64_t AccountIAMClient::Auth(const std::vector<uint8_t> &challenge, AuthType authType,
    AuthTrustLevel authTrustLevel, const std::shared_ptr<IDMCallback> &callback)
{
    uint64_t contextId = 0;
    if (GetAccountIAMProxy() != ERR_OK) {
        ACCOUNT_LOGD("fail to get account iam proxy");
        return contextId;
    }
    sptr<IIDMCallback> wrapper = new (std::nothrow) IDMCallbackService(callback);
    return proxy_->AuthUser(0, challenge, authType, authTrustLevel, wrapper);
}

uint64_t AccountIAMClient::AuthUser(
    int32_t userId, const std::vector<uint8_t> &challenge, AuthType authType,
    AuthTrustLevel authTrustLevel, const std::shared_ptr<IDMCallback> &callback)
{
    uint64_t contextId = 0;
    if (GetAccountIAMProxy() != ERR_OK) {
        ACCOUNT_LOGD("fail to get account iam proxy");
        return contextId;
    }
    sptr<IIDMCallback> wrapper = new (std::nothrow) IDMCallbackService(callback);
    return proxy_->AuthUser(userId, challenge, authType, authTrustLevel, wrapper);
}

int32_t AccountIAMClient::CancelAuth(uint64_t contextId)
{
    if (GetAccountIAMProxy() != ERR_OK) {
        ACCOUNT_LOGD("fail to get account iam proxy");
        return ResultCode::FAIL;
    }
    return proxy_->CancelAuth(contextId);
}

int32_t AccountIAMClient::GetAvailableStatus(AuthType authType, AuthTrustLevel authTrustLevel)
{
    int32_t status = 0;
    if (GetAccountIAMProxy() != ERR_OK) {
        ACCOUNT_LOGD("fail to get account iam proxy");
        return status;
    }
    return proxy_->GetAvailableStatus(authType, authTrustLevel);
}

void AccountIAMClient::GetProperty(
    int32_t userId, const GetPropertyRequest &request, const std::shared_ptr<GetSetPropCallback> &callback)
{
    if (GetAccountIAMProxy() != ERR_OK) {
        ACCOUNT_LOGD("fail to get account iam proxy");
        return;
    }
    sptr<IGetSetPropCallback> wrapper = new (std::nothrow) GetSetPropCallbackService(callback);
    proxy_->GetProperty(userId, request, wrapper);
}

void AccountIAMClient::SetProperty(
    int32_t userId, const SetPropertyRequest &request, const std::shared_ptr<GetSetPropCallback> &callback)
{
    if (GetAccountIAMProxy() != ERR_OK) {
        ACCOUNT_LOGD("fail to get account iam proxy");
        return;
    }
    sptr<IGetSetPropCallback> wrapper = new (std::nothrow) GetSetPropCallbackService(callback);
    proxy_->SetProperty(userId, request, wrapper);
}

bool AccountIAMClient::RegisterInputer(const std::shared_ptr<GetDataCallback> &inputer)
{
    if (GetAccountIAMProxy() != ERR_OK) {
        ACCOUNT_LOGD("fail to get account iam proxy");
        return false;
    }
    sptr<IGetDataCallback> wrapper = new (std::nothrow) GetDataCallbackService(inputer);
    return proxy_->RegisterInputer(wrapper);
}

void AccountIAMClient::UnRegisterInputer()
{
    if (GetAccountIAMProxy() != ERR_OK) {
        ACCOUNT_LOGD("fail to get account iam proxy");
        return;
    }
    proxy_->UnRegisterInputer();
}

void AccountIAMClient::ResetAccountIAMProxy(const wptr<IRemoteObject>& remote)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy_ == nullptr) {
        ACCOUNT_LOGD("proxy is nullptr");
        return;
    }
    auto serviceRemote = proxy_->AsObject();
    if ((serviceRemote != nullptr) && (serviceRemote == remote.promote())) {
        serviceRemote->RemoveDeathRecipient(deathRecipient_);
        proxy_ = nullptr;
    }
}

void AccountIAMClient::AccountIAMDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    if (remote == nullptr) {
        ACCOUNT_LOGD("remote is nullptr");
        return;
    }
    AccountIAMClient::GetInstance().ResetAccountIAMProxy(remote);
}

ErrCode AccountIAMClient::GetAccountIAMProxy()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy_ != nullptr) {
        return ERR_OK;
    }
    sptr<ISystemAbilityManager> saMgr =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!saMgr) {
        ACCOUNT_LOGD("failed to get system ability manager");
        return ERR_APPACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER;
    }
    sptr<IRemoteObject> remoteObject = saMgr->GetSystemAbility(SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN);
    if (!remoteObject) {
        ACCOUNT_LOGD("failed to get account system ability");
        return ERR_APPACCOUNT_KIT_GET_ACCOUNT_SYSTEM_ABILITY;
    }
    sptr<IAccount> accountProxy = iface_cast<AccountProxy>(remoteObject);
    if (!accountProxy) {
        ACCOUNT_LOGD("failed to cast account proxy");
        return ERR_APPACCOUNT_KIT_CAST_ACCOUNT_PROXY;
    }
    sptr<IRemoteObject> accountIAMRemoteObject = accountProxy->GetAccountIAMService();
    if (!accountIAMRemoteObject) {
        ACCOUNT_LOGD("failed to get account iam service");
        return ERR_APPACCOUNT_KIT_GET_APP_ACCOUNT_SERVICE;
    }
    proxy_ = iface_cast<IAccountIAM>(accountIAMRemoteObject);
    if ((!proxy_) || (!proxy_->AsObject())) {
        ACCOUNT_LOGD("failed to cast account iam proxy");
        return ERR_APPACCOUNT_KIT_GET_APP_ACCOUNT_PROXY;
    }
    deathRecipient_ = new (std::nothrow) AccountIAMDeathRecipient();
    if (!deathRecipient_) {
        ACCOUNT_LOGD("failed to create account iam death recipient");
        return ERR_APPACCOUNT_KIT_CREATE_APP_ACCOUNT_DEATH_RECIPIENT;
    }
    proxy_->AsObject()->AddDeathRecipient(deathRecipient_);
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
