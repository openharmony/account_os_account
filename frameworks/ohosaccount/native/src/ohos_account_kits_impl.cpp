/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "ohos_account_kits_impl.h"
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_proxy.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AccountSA {
OhosAccountKitsImpl::OhosAccountKitsImpl() {}
OhosAccountKitsImpl::~OhosAccountKitsImpl() {}

void OhosAccountKitsImpl::ResetService(const wptr<IRemoteObject>& remote)
{
    ACCOUNT_LOGI("Remote is dead, reset service instance");

    std::lock_guard<std::mutex> lock(accountProxyLock_);
    if (accountProxy_ != nullptr) {
        sptr<IRemoteObject> object = accountProxy_->AsObject();
        if ((object != nullptr) && (remote == object)) {
            object->RemoveDeathRecipient(deathRecipient_);
            accountProxy_ = nullptr;
        }
    }
}

sptr<IAccount> OhosAccountKitsImpl::GetService()
{
    std::lock_guard<std::mutex> lock(accountProxyLock_);
    if (accountProxy_ != nullptr) {
        return accountProxy_;
    }

    sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        ACCOUNT_LOGE("Get samgr failed");
        return nullptr;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN);
    if (object == nullptr) {
        ACCOUNT_LOGE("Get account object from samgr failed");
        return nullptr;
    }

    if (deathRecipient_ == nullptr) {
        deathRecipient_ = new (std::nothrow) DeathRecipient();
        if (deathRecipient_ == nullptr) {
            ACCOUNT_LOGE("deathRecipient_ is nullptr.");
            return nullptr;
        }
    }

    if ((object->IsProxyObject()) && (!object->AddDeathRecipient(deathRecipient_))) {
        ACCOUNT_LOGE("Failed to add death recipient");
    }

    accountProxy_ = iface_cast<AccountProxy>(object);
    if (accountProxy_ == nullptr) {
        ACCOUNT_LOGE("account iface_cast failed");
    }
    return accountProxy_;
}

void OhosAccountKitsImpl::DeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    DelayedRefSingleton<OhosAccountKitsImpl>::GetInstance().ResetService(remote);
}

bool OhosAccountKitsImpl::UpdateOhosAccountInfo(const std::string& accountName, const std::string& uid,
    const std::string& eventStr)
{
    auto accountProxy = GetService();
    if (accountProxy == nullptr) {
        ACCOUNT_LOGE("Get proxy failed");
        return false;
    }
    return accountProxy->UpdateOhosAccountInfo(accountName, uid, eventStr);
}

std::int32_t OhosAccountKitsImpl::SetOhosAccountInfo(
    const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr)
{
    auto accountProxy = GetService();
    if (accountProxy == nullptr) {
        ACCOUNT_LOGE("Get proxy failed");
        return ERR_ACCOUNT_ZIDL_ACCOUNT_PROXY_ERROR;
    }
    if (!ohosAccountInfo.IsValid()) {
        ACCOUNT_LOGE("OhosAccountInfo check failed");
        return ERR_OHOSACCOUNT_KIT_INVALID_PARAMETER;
    }
    return accountProxy->SetOhosAccountInfo(ohosAccountInfo, eventStr);
}

std::pair<bool, OhosAccountInfo> OhosAccountKitsImpl::QueryOhosAccountInfo()
{
    auto accountProxy = GetService();
    if (accountProxy == nullptr) {
        ACCOUNT_LOGE("Get proxy failed");
        return std::make_pair(false, OhosAccountInfo());
    }

    return accountProxy->QueryOhosAccountInfo();
}

ErrCode OhosAccountKitsImpl::GetOhosAccountInfo(OhosAccountInfo &accountInfo)
{
    auto accountProxy = GetService();
    if (accountProxy == nullptr) {
        ACCOUNT_LOGE("Get proxy failed");
        return ERR_ACCOUNT_ZIDL_ACCOUNT_PROXY_ERROR;
    }

    return accountProxy->GetOhosAccountInfo(accountInfo);
}

ErrCode OhosAccountKitsImpl::GetOhosAccountInfoByUserId(int32_t userId, OhosAccountInfo &accountInfo)
{
    auto accountProxy = GetService();
    if (accountProxy == nullptr) {
        ACCOUNT_LOGE("Get proxy failed");
        return ERR_ACCOUNT_ZIDL_ACCOUNT_PROXY_ERROR;
    }

    return accountProxy->GetOhosAccountInfoByUserId(userId, accountInfo);
}

std::pair<bool, OhosAccountInfo> OhosAccountKitsImpl::QueryOhosAccountInfoByUserId(std::int32_t userId)
{
    auto accountProxy = GetService();
    if (accountProxy == nullptr) {
        ACCOUNT_LOGE("Get proxy failed");
        return std::make_pair(false, OhosAccountInfo());
    }

    return accountProxy->QueryOhosAccountInfoByUserId(userId);
}

ErrCode OhosAccountKitsImpl::QueryDeviceAccountId(std::int32_t& accountId)
{
    auto accountProxy = GetService();
    if (accountProxy == nullptr) {
        ACCOUNT_LOGE("Get proxy failed");
        return ERR_ACCOUNT_ZIDL_ACCOUNT_PROXY_ERROR;
    }

    return accountProxy->QueryDeviceAccountId(accountId);
}

std::int32_t OhosAccountKitsImpl::GetDeviceAccountIdByUID(std::int32_t& uid)
{
    std::int32_t accountID = uid / UID_TRANSFORM_DIVISOR;
    return accountID;
}

sptr<IRemoteObject> OhosAccountKitsImpl::GetDomainAccountService()
{
    auto accountProxy = GetService();
    if (accountProxy == nullptr) {
        ACCOUNT_LOGE("Get proxy failed");
        return nullptr;
    }
    return accountProxy->GetDomainAccountService();
}
} // namespace AccountSA
} // namespace OHOS
