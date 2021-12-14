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

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_proxy.h"
#include "iaccount.h"
#include "iservice_registry.h"
#include "os_account_constants.h"
#include "os_account_death_recipient.h"
#include "system_ability_definition.h"

#include "os_account.h"

namespace OHOS {
namespace AccountSA {
ErrCode OsAccount::CreateOsAccount(const std::string &name, const int &type, OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("enter");
    ACCOUNT_LOGI("name.size(): %{public}zu", name.size());
    ACCOUNT_LOGI("NAME_MAX_SIZE: %{public}d", Constants::LOCAL_NAME_MAX_SIZE);
    if (name.size() > Constants::LOCAL_NAME_MAX_SIZE) {
        return ERR_OSACCOUNT_KIT_LOCAL_NAME_OUTFLOW_ERROR;
    }
    if (name.size() <= 0) {
        return ERR_OSACCOUNT_KIT_LOCAL_NAME_EMPTY_ERROR;
    }
    if (type <= Constants::STANDARD_TYPE) {
        return ERR_OSACCOUNT_KIT_TYPE_ERROR;
    }
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_");
        return result;
    }

    return osAccountProxy_->CreateOsAccount(name, type, osAccountInfo);
}

ErrCode OsAccount::RemoveOsAccount(const int id)
{
    ACCOUNT_LOGI("enter");
    ACCOUNT_LOGI("id: %{public}d", id);
    if (id <= Constants::START_USER_ID) {
        return ERR_OSACCOUNT_KIT_CANNOT_DELETE_ID_ERROR;
    }
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_");
        return result;
    }

    return osAccountProxy_->RemoveOsAccount(id);
}

ErrCode OsAccount::IsOsAccountExists(const int id, bool &isOsAccountExists)
{
    ACCOUNT_LOGI("OsAccount::IsOsAccountExists start");
    ACCOUNT_LOGI("id: %{public}d", id);

    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_");
        return result;
    }

    return osAccountProxy_->IsOsAccountExists(id, isOsAccountExists);
}

ErrCode OsAccount::IsOsAccountActived(const int id, bool &isOsAccountActived)
{
    ACCOUNT_LOGI("OsAccount::IsOsAccountActived start");
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_");
        return result;
    }

    return osAccountProxy_->IsOsAccountActived(id, isOsAccountActived);
}

ErrCode OsAccount::IsOsAccountConstraintEnable(const int id, const std::string &constraint, bool &isConstraintEnable)
{
    ACCOUNT_LOGI("OsAccount::IsOsAccountConstraintEnable start");
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_");
        return result;
    }

    return osAccountProxy_->IsOsAccountConstraintEnable(id, constraint, isConstraintEnable);
}

ErrCode OsAccount::IsOsAccountVerified(const int id, bool &isOsAccountVerified)
{
    ACCOUNT_LOGI("OsAccount::IsOsAccountVerified start");
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_");
        return result;
    }

    return osAccountProxy_->IsOsAccountVerified(id, isOsAccountVerified);
}

ErrCode OsAccount::GetCreatedOsAccountsCount(int &osAccountsCount)
{
    ACCOUNT_LOGI("OsAccount::GetCreatedOsAccountsCount start");
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_");
        return result;
    }

    return osAccountProxy_->GetCreatedOsAccountsCount(osAccountsCount);
}

ErrCode OsAccount::GetOsAccountLocalIdFromProcess(int &id)
{
    ACCOUNT_LOGI("OsAccount::GetOsAccountLocalIdFromProcess start");
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_");
        return result;
    }

    return osAccountProxy_->GetOsAccountLocalIdFromProcess(id);
}

ErrCode OsAccount::GetOsAccountLocalIdFromUid(const int uid, int &id)
{
    ACCOUNT_LOGI("OsAccount::GetOsAccountLocalIdFromUid start");
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_");
        return result;
    }

    return osAccountProxy_->GetOsAccountLocalIdFromUid(uid, id);
}

ErrCode OsAccount::QueryMaxOsAccountNumber(int &maxOsAccountNumber)
{
    ACCOUNT_LOGI("OsAccount::QueryMaxOsAccountNumber start");
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_");
        return result;
    }

    return osAccountProxy_->QueryMaxOsAccountNumber(maxOsAccountNumber);
}

ErrCode OsAccount::GetOsAccountAllConstraints(const int id, std::vector<std::string> &constraints)
{
    ACCOUNT_LOGI("OsAccount::GetOsAccountAllConstraints start");
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_");
        return result;
    }

    return osAccountProxy_->GetOsAccountAllConstraints(id, constraints);
}

ErrCode OsAccount::QueryAllCreatedOsAccounts(std::vector<OsAccountInfo> &osAccountInfos)
{
    ACCOUNT_LOGI("OsAccount::QueryAllCreatedOsAccounts start");
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_");
        return result;
    }

    return osAccountProxy_->QueryAllCreatedOsAccounts(osAccountInfos);
}

ErrCode OsAccount::QueryCurrentOsAccount(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccount::QueryCurrentOsAccount start");
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_");
        return result;
    }

    return osAccountProxy_->QueryCurrentOsAccount(osAccountInfo);
}

ErrCode OsAccount::QueryOsAccountById(const int id, OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccount::QueryOsAccountById start");
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_");
        return result;
    }

    return osAccountProxy_->QueryOsAccountById(id, osAccountInfo);
}

ErrCode OsAccount::GetOsAccountTypeFromProcess(int &type)
{
    ACCOUNT_LOGI("OsAccount::GetOsAccountTypeFromProcess start");
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_");
        return result;
    }

    return osAccountProxy_->GetOsAccountTypeFromProcess(type);
}

ErrCode OsAccount::GetOsAccountProfilePhoto(const int id, std::string &photo)
{
    ACCOUNT_LOGI("OsAccount::GetOsAccountProfilePhoto start");
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_");
        return result;
    }

    return osAccountProxy_->GetOsAccountProfilePhoto(id, photo);
}

ErrCode OsAccount::IsMultiOsAccountEnable(bool &isMultiOsAccountEnable)
{
    ACCOUNT_LOGI("OsAccount::IsMultiOsAccountEnable start");
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_");
        return result;
    }

    return osAccountProxy_->IsMultiOsAccountEnable(isMultiOsAccountEnable);
}

ErrCode OsAccount::SetOsAccountName(const int id, const std::string &localName)
{
    ACCOUNT_LOGI("OsAccount::SetOsAccountName start");
    if (localName.size() > Constants::LOCAL_NAME_MAX_SIZE) {
        return ERR_OSACCOUNT_KIT_LOCAL_NAME_OUTFLOW_ERROR;
    }
    if (localName.size() <= 0) {
        return ERR_OSACCOUNT_KIT_LOCAL_NAME_EMPTY_ERROR;
    }
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_");
        return result;
    }

    return osAccountProxy_->SetOsAccountName(id, localName);
}

ErrCode OsAccount::SetOsAccountConstraints(const int id, const std::vector<std::string> &constraints, const bool enable)
{
    ACCOUNT_LOGI("OsAccount::SetOsAccountConstraints start");
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_");
        return result;
    }

    return osAccountProxy_->SetOsAccountConstraints(id, constraints, enable);
}

ErrCode OsAccount::SetOsAccountProfilePhoto(const int id, const std::string &photo)
{
    ACCOUNT_LOGI("OsAccount::SetOsAccountProfilePhoto start");
    if (photo.size() > Constants::LOCAL_PHOTO_MAX_SIZE) {
        return ERR_OSACCOUNT_KIT_PHOTO_OUTFLOW_ERROR;
    }
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_");
        return result;
    }

    return osAccountProxy_->SetOsAccountProfilePhoto(id, photo);
}

ErrCode OsAccount::GetDistributedVirtualDeviceId(std::int32_t &deviceId)
{
    ACCOUNT_LOGI("OsAccount::GetDistributedVirtualDeviceId start");
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_");
        return result;
    }

    return osAccountProxy_->GetDistributedVirtualDeviceId(deviceId);
}

ErrCode OsAccount::ActivateOsAccount(const int id)
{
    ACCOUNT_LOGI("OsAccount::ActivateOsAccount start");
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_");
        return result;
    }

    return osAccountProxy_->ActivateOsAccount(id);
}

ErrCode OsAccount::StartOsAccount(const int id)
{
    ACCOUNT_LOGI("OsAccount::StartOsAccount start");
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_");
        return result;
    }

    return osAccountProxy_->StartOsAccount(id);
}

ErrCode OsAccount::StopOsAccount(const int id)
{
    ACCOUNT_LOGI("OsAccount::StopOsAccount start");
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_");
        return result;
    }
    return osAccountProxy_->StopOsAccount(id);
}

ErrCode OsAccount::GetOsAccountLocalIdBySerialNumber(const int64_t serialNumber, int &id)
{
    ACCOUNT_LOGI("OsAccount::GetOsAccountLocalIdBySerialNumber start");
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_");
        return result;
    }
    return osAccountProxy_->GetOsAccountLocalIdBySerialNumber(serialNumber, id);
}

ErrCode OsAccount::GetSerialNumberByOsAccountLocalId(const int &id, int64_t &serialNumber)
{
    ACCOUNT_LOGI("OsAccount::GetSerialNumberByOsAccountLocalId start");
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_");
        return result;
    }
    return osAccountProxy_->GetSerialNumberByOsAccountLocalId(id, serialNumber);
}

ErrCode OsAccount::SubscribeOsAccount(const std::shared_ptr<OsAccountSubscriber> &subscriber)
{
    ACCOUNT_LOGI("enter");

    if (subscriber == nullptr) {
        ACCOUNT_LOGE("subscriber is nullptr");
        return ERR_OSACCOUNT_KIT_SUBSCRIBER_IS_NULLPTR;
    }

    OsAccountSubscribeInfo subscribeInfo;
    if (subscriber->GetSubscribeInfo(subscribeInfo) != ERR_OK) {
        ACCOUNT_LOGE("get subscribeInfo failed");
        return ERR_OSACCOUNT_KIT_GET_SUBSCRIBE_INFO_ERROR;
    }
    OS_ACCOUNT_SUBSCRIBE_TYPE osAccountSubscribeType;
    if (subscribeInfo.GetOsAccountSubscribeType(osAccountSubscribeType) != ERR_OK) {
        ACCOUNT_LOGE("failed to get owners");
        return ERR_OSACCOUNT_KIT_GET_OS_ACCOUNT_SUBSCRIBE_TYPE_ERROR;
    }
    std::string name;
    if (subscribeInfo.GetName(name) != ERR_OK) {
        ACCOUNT_LOGE("failed to get owners");
        return ERR_OSACCOUNT_KIT_GET_NAME_ERROR;
    }
    if (GetOsAccountProxy() != ERR_OK) {
        ACCOUNT_LOGE("app account proxy is nullptr");
        return ERR_APPACCOUNT_KIT_APP_ACCOUNT_PROXY_IS_NULLPTR;
    }

    sptr<IRemoteObject> osAccountEventListener = nullptr;
    ErrCode subscribeState = CreateOsAccountEventListener(subscriber, osAccountEventListener);
    if (subscribeState == INITIAL_SUBSCRIPTION) {
        return osAccountProxy_->SubscribeOsAccount(subscribeInfo, osAccountEventListener);
    } else if (subscribeState == ALREADY_SUBSCRIBED) {
        return ERR_OK;
    } else {
        return ERR_OSACCOUNT_KIT_SUBSCRIBE_ERROR;
    }
}

ErrCode OsAccount::UnsubscribeOsAccount(const std::shared_ptr<OsAccountSubscriber> &subscriber)
{
    ACCOUNT_LOGI("enter");

    if (subscriber == nullptr) {
        ACCOUNT_LOGE("subscriber is nullptr");
        return ERR_APPACCOUNT_KIT_SUBSCRIBER_IS_NULLPTR;
    }

    if (GetOsAccountProxy() != ERR_OK) {
        ACCOUNT_LOGE("app account proxy is nullptr");
        return ERR_APPACCOUNT_KIT_APP_ACCOUNT_PROXY_IS_NULLPTR;
    }

    std::lock_guard<std::mutex> lock(eventListenersMutex_);

    auto eventListener = eventListeners_.find(subscriber);
    if (eventListener != eventListeners_.end()) {
        ErrCode result = osAccountProxy_->UnsubscribeOsAccount(eventListener->second->AsObject());
        if (result == ERR_OK) {
            eventListener->second->Stop();
            eventListeners_.erase(eventListener);
        }

        return result;
    } else {
        ACCOUNT_LOGI("no specified subscriber has been registered");
        return ERR_OSACCOUNT_KIT_NO_SPECIFIED_SUBSCRIBER_HAS_BEEN_REGESITERED;
    }
}

OS_ACCOUNT_SWITCH_MOD OsAccount::GetOsAccountSwitchMod()
{
    ACCOUNT_LOGI("OsAccount::GetOsAccountSwitchMod start");
    GetOsAccountProxy();
    return osAccountProxy_->GetOsAccountSwitchMod();
}

ErrCode OsAccount::ResetOsAccountProxy()
{
    ACCOUNT_LOGI("enter");

    std::lock_guard<std::mutex> lock(mutex_);
    if ((osAccountProxy_ != nullptr) && (osAccountProxy_->AsObject() != nullptr)) {
        osAccountProxy_->AsObject()->RemoveDeathRecipient(deathRecipient_);
    }
    osAccountProxy_ = nullptr;

    return ERR_OK;
}

ErrCode OsAccount::IsCurrentOsAccountVerified(bool &isOsAccountVerified)
{
    ACCOUNT_LOGI("OsAccount::IsCurrentOsAccountVerified start");
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_");
        return result;
    }
    return osAccountProxy_->IsCurrentOsAccountVerified(isOsAccountVerified);
}

ErrCode OsAccount::IsOsAccountCompleted(const int id, bool &isOsAccountCompleted)
{
    ACCOUNT_LOGI("OsAccount::IsOsAccountCompleted start");
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_");
        return result;
    }
    return osAccountProxy_->IsOsAccountCompleted(id, isOsAccountCompleted);
}

ErrCode OsAccount::SetCurrentOsAccountIsVerified(const bool isOsAccountVerified)
{
    ACCOUNT_LOGI("OsAccount::SetCurrentOsAccountIsVerified start");
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_");
        return result;
    }
    return osAccountProxy_->SetCurrentOsAccountIsVerified(isOsAccountVerified);
}

ErrCode OsAccount::SetOsAccountIsVerified(const int id, const bool isOsAccountVerified)
{
    ACCOUNT_LOGI("OsAccount::SetOsAccountIsVerified start");
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_");
        return result;
    }
    return osAccountProxy_->SetOsAccountIsVerified(id, isOsAccountVerified);
}

ErrCode OsAccount::GetOsAccountProxy()
{
    ACCOUNT_LOGI("enter");

    if (!osAccountProxy_) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!osAccountProxy_) {
            sptr<ISystemAbilityManager> systemAbilityManager =
                SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
            if (!systemAbilityManager) {
                ACCOUNT_LOGE("failed to get system ability manager");
                return ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR;
            }

            sptr<IRemoteObject> remoteObject =
                systemAbilityManager->GetSystemAbility(SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN);
            if (!remoteObject) {
                ACCOUNT_LOGE("failed to get account system ability");
                return ERR_OSACCOUNT_KIT_GET_ACCOUNT_SYSTEM_ABILITY_ERROR;
            }

            sptr<IAccount> accountProxy = iface_cast<AccountProxy>(remoteObject);
            if ((!accountProxy) || (!accountProxy->AsObject())) {
                ACCOUNT_LOGE("failed to cast account proxy");
                return ERR_OSACCOUNT_KIT_CAST_ACCOUNT_PROXY_ERROR;
            }

            auto osAccountRemoteObject = accountProxy->GetOsAccountService();
            if (!osAccountRemoteObject) {
                ACCOUNT_LOGE("failed to get app account service");
                return ERR_OSACCOUNT_KIT_GET_APP_ACCOUNT_SERVICE_ERROR;
            }

            osAccountProxy_ = iface_cast<IOsAccount>(osAccountRemoteObject);
            if ((!osAccountProxy_) || (!osAccountProxy_->AsObject())) {
                ACCOUNT_LOGE("failed to cast app account proxy");
                return ERR_OSACCOUNT_KIT_GET_APP_ACCOUNT_PROXY_ERROR;
            }

            deathRecipient_ = new (std::nothrow) OsAccountDeathRecipient();
            if (!deathRecipient_) {
                ACCOUNT_LOGE("failed to create app account death recipient");
                return ERR_OSACCOUNT_KIT_CREATE_APP_ACCOUNT_DEATH_RECIPIENT_ERROR;
            }

            osAccountProxy_->AsObject()->AddDeathRecipient(deathRecipient_);
        }
    }

    return ERR_OK;
}

ErrCode OsAccount::CreateOsAccountEventListener(
    const std::shared_ptr<OsAccountSubscriber> &subscriber, sptr<IRemoteObject> &osAccountEventListener)
{
    ACCOUNT_LOGI("enter");

    if (subscriber == nullptr) {
        ACCOUNT_LOGE("subscriber is nullptr");
        return SUBSCRIBE_FAILD;
    }

    std::lock_guard<std::mutex> lock(eventListenersMutex_);

    auto eventListener = eventListeners_.find(subscriber);
    if (eventListener != eventListeners_.end()) {
        osAccountEventListener = eventListener->second->AsObject();
        ACCOUNT_LOGI("subscriber already has app account event listener");
        return ALREADY_SUBSCRIBED;
    } else {
        if (eventListeners_.size() == Constants::SUBSCRIBER_MAX_SIZE) {
            ACCOUNT_LOGE("the maximum number of subscribers has been reached");
            return SUBSCRIBE_FAILD;
        }

        sptr<OsAccountEventListener> listener = new (std::nothrow) OsAccountEventListener(subscriber);
        if (!listener) {
            ACCOUNT_LOGE("the os account event listener is null");
            return SUBSCRIBE_FAILD;
        }
        osAccountEventListener = listener->AsObject();
        eventListeners_[subscriber] = listener;
    }

    return INITIAL_SUBSCRIPTION;
}
}  // namespace AccountSA
}  // namespace OHOS
