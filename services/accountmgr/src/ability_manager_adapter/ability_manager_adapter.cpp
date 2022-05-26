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

#include "ability_manager_adapter.h"
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AAFwk {
using namespace AccountSA;
std::shared_ptr<AbilityManagerAdapter> AbilityManagerAdapter::instance_ = nullptr;
std::mutex AbilityManagerAdapter::instanceMutex_;

std::shared_ptr<AbilityManagerAdapter> AbilityManagerAdapter::GetInstance()
{
    std::lock_guard<std::mutex> lock(instanceMutex_);
    if (instance_ == nullptr) {
        instance_ = std::make_shared<AbilityManagerAdapter>();
    }
    return instance_;
}

AbilityManagerAdapter::AbilityManagerAdapter()
{}

AbilityManagerAdapter::~AbilityManagerAdapter()
{}

ErrCode AbilityManagerAdapter::ConnectAbility(const AAFwk::Want &want, const sptr<AAFwk::IAbilityConnection> &connect,
    const sptr<IRemoteObject> &callerToken, int32_t userId)
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    auto abms = GetAbilityManager();
    if (abms == nullptr) {
        ACCOUNT_LOGE("ability manager proxy is nullptr.");
        return ERR_ACCOUNT_COMMON_CONNECT_ABILITY_MANAGER_SERVICE_ERROR;
    }
    ACCOUNT_LOGI("Connect ability called, bundleName:%{public}s, abilityName:%{public}s, userId:%{public}d.",
        want.GetElement().GetBundleName().c_str(), want.GetElement().GetAbilityName().c_str(), userId);
    return abms->ConnectAbility(want, connect, callerToken, userId);
}

ErrCode AbilityManagerAdapter::DisconnectAbility(const sptr<AAFwk::IAbilityConnection> &connect)
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    auto abms = GetAbilityManager();
    if (abms == nullptr) {
        ACCOUNT_LOGE("ability manager proxy is nullptr.");
        return ERR_ACCOUNT_COMMON_CONNECT_ABILITY_MANAGER_SERVICE_ERROR;
    }
    ACCOUNT_LOGI("Disconnect ability begin.");
    return abms->DisconnectAbility(connect);
}

void AbilityManagerAdapter::Connect()
{
    if (proxy_ != nullptr) {
        return;
    }
    sptr<ISystemAbilityManager> systemManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemManager == nullptr) {
        ACCOUNT_LOGE("Fail to get system ability registry.");
        return;
    }
    sptr<IRemoteObject> remoteObj = systemManager->GetSystemAbility(ABILITY_MGR_SERVICE_ID);
    if (remoteObj == nullptr) {
        ACCOUNT_LOGE("Fail to connect ability manager service.");
        return;
    }

    deathRecipient_ = sptr<IRemoteObject::DeathRecipient>(new (std::nothrow) AbilityMgrDeathRecipient());
    if (deathRecipient_ == nullptr) {
        ACCOUNT_LOGE("Failed to create AbilityMgrDeathRecipient!");
        return;
    }
    if ((remoteObj->IsProxyObject()) && (!remoteObj->AddDeathRecipient(deathRecipient_))) {
        ACCOUNT_LOGE("Add death recipient to AbilityManagerService failed.");
        return;
    }

    proxy_ = iface_cast<AAFwk::IAbilityManager>(remoteObj);
    if (proxy_ == nullptr) {
        ACCOUNT_LOGE("proxy_ is nullptr!");
        return;
    }
    ACCOUNT_LOGI("Connect ability manager service success.");
}

ErrCode AbilityManagerAdapter::StartUser(int accountId)
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    auto abms = GetAbilityManager();
    if (abms == nullptr) {
        ACCOUNT_LOGE("ability manager proxy is nullptr.");
        return ERR_ACCOUNT_COMMON_CONNECT_ABILITY_MANAGER_SERVICE_ERROR;
    }
    return abms->StartUser(accountId);
}

ErrCode AbilityManagerAdapter::StopUser(int accountId, const sptr<AAFwk::IStopUserCallback> &callback)
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    auto abms = GetAbilityManager();
    if (abms == nullptr) {
        ACCOUNT_LOGE("ability manager proxy is nullptr.");
        return ERR_ACCOUNT_COMMON_CONNECT_ABILITY_MANAGER_SERVICE_ERROR;
    }
    return abms->StopUser(accountId, callback);
}

sptr<AAFwk::IAbilityManager> AbilityManagerAdapter::GetAbilityManager()
{
    if (!proxy_) {
        Connect();
    }
    return proxy_;
}

void AbilityManagerAdapter::ResetProxy(const wptr<IRemoteObject>& remote)
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    auto serviceRemote = proxy_->AsObject();
    if ((serviceRemote != nullptr) && (serviceRemote == remote.promote())) {
        serviceRemote->RemoveDeathRecipient(deathRecipient_);
        proxy_ = nullptr;
    }
}

void AbilityManagerAdapter::AbilityMgrDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    ACCOUNT_LOGI("AbilityMgrDeathRecipient handle remote died.");
    AbilityManagerAdapter::GetInstance()->ResetProxy(remote);
}
}  // namespace AAFwk
}  // namespace OHOS
