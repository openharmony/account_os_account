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
        deathRecipient_ = new DeathRecipient();
    }

    if ((object->IsProxyObject()) && (!object->AddDeathRecipient(deathRecipient_))) {
        ACCOUNT_LOGE("Failed to add death recipient");
    }

    ACCOUNT_LOGI("get remote object ok");
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

template<typename F, typename... Args>
ErrCode OhosAccountKitsImpl::CallService(F func, Args&&... args)
{
    auto service = GetService();
    if (service == nullptr) {
        ACCOUNT_LOGE("get service failed");
        return ERR_DEAD_OBJECT;
    }

    ErrCode result = (service->*func)(std::forward<Args>(args)...);
    if (SUCCEEDED(result)) {
        return ERR_OK;
    }

    // Reset service instance if 'ERR_DEAD_OBJECT' happened.
    if (result == ERR_DEAD_OBJECT) {
        ResetService(service);
    }

    ACCOUNT_LOGE("Callservice failed with: %{public}d", result);
    return result;
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

std::pair<bool, OhosAccountInfo> OhosAccountKitsImpl::QueryOhosAccountInfo()
{
    auto accountProxy = GetService();
    if (accountProxy == nullptr) {
        ACCOUNT_LOGE("Get proxy failed");
        return std::make_pair(false, OhosAccountInfo());
    }

    return accountProxy->QueryOhosAccountInfo();
}

ErrCode OhosAccountKitsImpl::QueryDeviceAccountId(std::int32_t& accountId)
{
    auto ret = CallService(&IAccount::QueryDeviceAccountId, accountId);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Query device account id failed: %{public}d", ret);
    }
    return ret;
}

std::int32_t OhosAccountKitsImpl::GetDeviceAccountIdByUID(std::int32_t& uid)
{
    auto accountProxy = GetService();
    if (accountProxy == nullptr) {
        ACCOUNT_LOGE("Get proxy failed");
        return ERR_DEAD_OBJECT;
    }

    return accountProxy->QueryDeviceAccountIdFromUid(uid);
}
} // namespace AccountSA
} // namespace OHOS
