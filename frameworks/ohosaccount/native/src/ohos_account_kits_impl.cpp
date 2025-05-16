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
#include "system_ability_status_change_listener.h"

namespace OHOS {
namespace AccountSA {
std::function<void(int32_t, const std::string &)> ohosCallbackFunc()
{
    return [](int32_t systemAbilityId, const std::string &dvid) {
        if (systemAbilityId == SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN) {
            OhosAccountKitsImpl::GetInstance().RestoreSubscribe();
        }
    };
}

OhosAccountKitsImpl &OhosAccountKitsImpl::GetInstance()
{
    static OhosAccountKitsImpl *instance = new (std::nothrow) OhosAccountKitsImpl();
    return *instance;
}

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
    if (!isSubscribeSA_) {
        isSubscribeSA_ = true;
        SubscribeSystemAbility(ohosCallbackFunc());
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
    OhosAccountKitsImpl::GetInstance().ResetService(remote);
}

ErrCode OhosAccountKitsImpl::UpdateOhosAccountInfo(const std::string& accountName, const std::string& uid,
    const std::string& eventStr)
{
    auto accountProxy = GetService();
    if (accountProxy == nullptr) {
        ACCOUNT_LOGE("Get proxy failed");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return accountProxy->UpdateOhosAccountInfo(accountName, uid, eventStr);
}

ErrCode OhosAccountKitsImpl::SetOhosAccountInfo(
    const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr)
{
    auto accountProxy = GetService();
    if (accountProxy == nullptr) {
        ACCOUNT_LOGE("Get proxy failed");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    if (!ohosAccountInfo.IsValid()) {
        ACCOUNT_LOGE("OhosAccountInfo check failed");
        SetNativeErrMsg("Invalid accountInfo. Please check the value of accountInfo."
            "(1) The length of the accountInfo.nickname must be less than 1025."
            "(2) The avatar must be less than 10MB."
            "(3) The length of the accountInfo.scalableData must be less than 1025.");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    return accountProxy->SetOhosAccountInfo(ohosAccountInfo, eventStr);
}

ErrCode OhosAccountKitsImpl::SetOsAccountDistributedInfo(
    const int32_t localId, const OhosAccountInfo& ohosAccountInfo, const std::string& eventStr)
{
    auto accountProxy = GetService();
    if (accountProxy == nullptr) {
        ACCOUNT_LOGE("Get proxy failed");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    if (!ohosAccountInfo.IsValid()) {
        ACCOUNT_LOGE("OhosAccountInfo check failed");
        SetNativeErrMsg("Invalid accountInfo. Please check the value of accountInfo."
            "(1) The length of the accountInfo.nickname must be less than 1025."
            "(2) The avatar must be less than 10MB."
            "(3) The length of the accountInfo.scalableData must be less than 1025.");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    return accountProxy->SetOsAccountDistributedInfo(localId, ohosAccountInfo, eventStr);
}

std::pair<bool, OhosAccountInfo> OhosAccountKitsImpl::QueryOhosAccountInfo()
{
    OhosAccountInfo accountInfo;
    ErrCode result = QueryOhosAccountInfo(accountInfo);
    return std::make_pair(result == ERR_OK, accountInfo);
}

ErrCode OhosAccountKitsImpl::QueryDistributedVirtualDeviceId(std::string &dvid)
{
    auto accountProxy = GetService();
    if (accountProxy == nullptr) {
        ACCOUNT_LOGE("Get proxy failed");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return accountProxy->QueryDistributedVirtualDeviceId(dvid);
}

ErrCode OhosAccountKitsImpl::QueryDistributedVirtualDeviceId(const std::string &bundleName, int32_t localId,
    std::string &dvid)
{
    auto accountProxy = GetService();
    if (accountProxy == nullptr) {
        ACCOUNT_LOGE("Get proxy failed");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return accountProxy->QueryDistributedVirtualDeviceId(bundleName, localId, dvid);
}

ErrCode OhosAccountKitsImpl::QueryOhosAccountInfo(OhosAccountInfo &accountInfo)
{
    auto accountProxy = GetService();
    if (accountProxy == nullptr) {
        ACCOUNT_LOGE("Get proxy failed");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return accountProxy->QueryOhosAccountInfo(accountInfo);
}

ErrCode OhosAccountKitsImpl::GetOhosAccountInfo(OhosAccountInfo &accountInfo)
{
    auto accountProxy = GetService();
    if (accountProxy == nullptr) {
        ACCOUNT_LOGE("Get proxy failed");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return accountProxy->GetOhosAccountInfo(accountInfo);
}

ErrCode OhosAccountKitsImpl::GetOsAccountDistributedInfo(int32_t localId, OhosAccountInfo &accountInfo)
{
    auto accountProxy = GetService();
    if (accountProxy == nullptr) {
        ACCOUNT_LOGE("Get proxy failed");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return accountProxy->GetOsAccountDistributedInfo(localId, accountInfo);
}

std::pair<bool, OhosAccountInfo> OhosAccountKitsImpl::QueryOsAccountDistributedInfo(std::int32_t localId)
{
    OhosAccountInfo accountInfo;
    ErrCode result = QueryOsAccountDistributedInfo(localId, accountInfo);
    return std::make_pair(result == ERR_OK, accountInfo);
}

ErrCode OhosAccountKitsImpl::QueryOsAccountDistributedInfo(std::int32_t localId, OhosAccountInfo &accountInfo)
{
    auto accountProxy = GetService();
    if (accountProxy == nullptr) {
        ACCOUNT_LOGE("Get proxy failed");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return accountProxy->QueryOsAccountDistributedInfo(localId, accountInfo);
}

ErrCode OhosAccountKitsImpl::QueryDeviceAccountId(std::int32_t& accountId)
{
    auto accountProxy = GetService();
    if (accountProxy == nullptr) {
        ACCOUNT_LOGE("Get proxy failed");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return accountProxy->QueryDeviceAccountId(accountId);
}

ErrCode OhosAccountKitsImpl::SubscribeDistributedAccountEvent(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type,
    const std::shared_ptr<DistributedAccountSubscribeCallback> &callback)
{
    ACCOUNT_LOGI("Subscribe distributed account event in client.");
    if (callback == nullptr) {
        ACCOUNT_LOGE("Callback is nullptr.");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }

    auto accountProxy = GetService();
    if (accountProxy == nullptr) {
        ACCOUNT_LOGE("Get proxy failed.");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    sptr<IRemoteObject> listener = nullptr;
    std::lock_guard<std::mutex> lock(eventListenersMutex_);
    bool isIPC = true;
    std::set<DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE> typeList;
    DistributedAccountEventService::GetInstance()->GetAllType(typeList);
    if (typeList.find(type) != typeList.end()) {
        isIPC = false;
    }
    ErrCode result = CreateDistributedAccountEventService(type, callback, listener);
    if (result == ERR_OHOSACCOUNT_KIT_CALLBACK_ALREADY_REGISTERED_ERROR) {
        ACCOUNT_LOGE("Callback already registered.");
        return ERR_OK;
    }
    if (listener == nullptr) {
        ACCOUNT_LOGE("Create event service failed.");
        return ERR_OHOSACCOUNT_KIT_SUBSCRIBE_ERROR;
    }

    if (!isIPC) {
        return ERR_OK;
    }
    result = accountProxy->SubscribeDistributedAccountEvent(type, listener);
    if (result != ERR_OK) {
        DistributedAccountEventService::GetInstance()->DeleteType(type, callback);
    }
    return result;
}

ErrCode OhosAccountKitsImpl::UnsubscribeDistributedAccountEvent(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type,
    const std::shared_ptr<DistributedAccountSubscribeCallback> &callback)
{
    ACCOUNT_LOGI("Unsubscribe distributed account event in client.");
    if (callback == nullptr) {
        ACCOUNT_LOGE("Callback is nullptr.");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }

    auto accountProxy = GetService();
    if (accountProxy == nullptr) {
        ACCOUNT_LOGE("Get proxy failed.");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    std::lock_guard<std::mutex> lock(eventListenersMutex_);
    if (!(DistributedAccountEventService::GetInstance()->IsTypeExist(type, callback))) {
        ACCOUNT_LOGE("No specified callback has been registered.");
        return ERR_OHOSACCOUNT_KIT_NO_SPECIFIED_CALLBACK_HAS_BEEN_REGISTERED;
    }
    DistributedAccountEventService::GetInstance()->DeleteType(type, callback);

    ErrCode result = ERR_OK;
    std::set<DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE> typeList;
    DistributedAccountEventService::GetInstance()->GetAllType(typeList);
    if (typeList.find(type) == typeList.end()) {
        result = accountProxy->UnsubscribeDistributedAccountEvent(type,
            DistributedAccountEventService::GetInstance()->AsObject());
    }
    if (result != ERR_OK) {
        DistributedAccountEventService::GetInstance()->AddType(type, callback);
    }

    return result;
}

ErrCode OhosAccountKitsImpl::CreateDistributedAccountEventService(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type,
    const std::shared_ptr<DistributedAccountSubscribeCallback> &callback,
    sptr<IRemoteObject> &subscribeListener)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("Callback is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }

    if (DistributedAccountEventService::GetInstance()->IsTypeExist(type, callback)) {
        ACCOUNT_LOGI("Callback already has distributed account event listener.");
        return ERR_OHOSACCOUNT_KIT_CALLBACK_ALREADY_REGISTERED_ERROR;
    }

    if (DistributedAccountEventService::GetInstance()->GetCallbackSize() ==
        Constants::DISTRIBUTED_SUBSCRIBER_MAX_SIZE) {
        ACCOUNT_LOGE("The maximum number of eventListeners has been reached.");
        return ERR_OHOSACCOUNT_KIT_SUBSCRIBE_MAX_SIZE_ERROR;
    }

    subscribeListener = DistributedAccountEventService::GetInstance()->AsObject();

    DistributedAccountEventService::GetInstance()->AddType(type, callback);
    return ERR_OK;
}

void OhosAccountKitsImpl::RestoreSubscribe()
{
    auto accountProxy = GetService();
    if (accountProxy == nullptr) {
        ACCOUNT_LOGE("Get proxy failed.");
        return ;
    }

    std::lock_guard<std::mutex> lock(eventListenersMutex_);
    std::set<DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE> typeList;
    DistributedAccountEventService::GetInstance()->GetAllType(typeList);
    for (auto type : typeList) {
        ErrCode subscribeState = accountProxy->SubscribeDistributedAccountEvent(type,
            DistributedAccountEventService::GetInstance()->AsObject());
        if (subscribeState != ERR_OK) {
            ACCOUNT_LOGE("Restore subscribe failed, res=%{public}d.", subscribeState);
        }
    }
}

std::int32_t OhosAccountKitsImpl::GetDeviceAccountIdByUID(std::int32_t& uid)
{
    std::int32_t accountID = uid / UID_TRANSFORM_DIVISOR;
    return accountID;
}

ErrCode OhosAccountKitsImpl::SubscribeSystemAbility(const DomainAccountSubscribeSACallbackFunc& callbackFunc)
{
    sptr<ISystemAbilityStatusChange> statusChangeListener =
        new (std::nothrow) SystemAbilityStatusChangeListener(callbackFunc);
    if (statusChangeListener == nullptr) {
        ACCOUNT_LOGE("statusChangeListener is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == NULL) {
        ACCOUNT_LOGE("samgrProxy is NULL");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    int32_t ret = samgrProxy->SubscribeSystemAbility(SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN, statusChangeListener);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("SubscribeSystemAbility is failed");
        return ret;
    }
    return ERR_OK;
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

sptr<IRemoteObject> OhosAccountKitsImpl::GetOsAccountService()
{
    auto accountProxy = GetService();
    if (accountProxy == nullptr) {
        ACCOUNT_LOGE("Get proxy failed");
        return nullptr;
    }
    return accountProxy->GetOsAccountService();
}

sptr<IRemoteObject> OhosAccountKitsImpl::GetAppAccountService()
{
    auto accountProxy = GetService();
    if (accountProxy == nullptr) {
        ACCOUNT_LOGE("Get proxy failed");
        return nullptr;
    }
    return accountProxy->GetAppAccountService();
}

sptr<IRemoteObject> OhosAccountKitsImpl::GetAccountIAMService()
{
    auto accountProxy = GetService();
    if (accountProxy == nullptr) {
        ACCOUNT_LOGE("Get proxy failed");
        return nullptr;
    }
    return accountProxy->GetAccountIAMService();
}
} // namespace AccountSA
} // namespace OHOS
