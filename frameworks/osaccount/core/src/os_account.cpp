/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "os_account.h"
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_proxy.h"
#include "iaccount.h"
#include "iservice_registry.h"
#include "ohos_account_kits.h"
#include "os_account_constants.h"
#include "os_account_death_recipient.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AccountSA {
static ErrCode CheckInvalidLocalId(int localId)
{
    if (localId > Constants::MAX_USER_ID) {
        ACCOUNT_LOGE("id %{public}d is out of range", localId);
        return ERR_OSACCOUNT_KIT_LOCAL_ID_INVALID_ERROR;
    }
    return ERR_OK;
}

static ErrCode CheckLocalId(int localId)
{
    if (localId < Constants::START_USER_ID) {
        ACCOUNT_LOGE("id %{public}d is system reserved", localId);
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    return CheckInvalidLocalId(localId);
}

OsAccount &OsAccount::GetInstance()
{
    static OsAccount instance;
    return instance;
}

ErrCode OsAccount::CreateOsAccount(const std::string &name, const OsAccountType &type, OsAccountInfo &osAccountInfo)
{
    if (name.size() > Constants::LOCAL_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("name length %{public}zu is too long!", name.size());
        return ERR_OSACCOUNT_KIT_LOCAL_NAME_OUTFLOW_ERROR;
    }
    if (name.empty()) {
        ACCOUNT_LOGE("name is empty!");
        return ERR_OSACCOUNT_KIT_LOCAL_NAME_EMPTY_ERROR;
    }
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }

    return osAccountProxy_->CreateOsAccount(name, type, osAccountInfo);
}

ErrCode OsAccount::CreateOsAccountForDomain(
    const OsAccountType &type, const DomainAccountInfo &domainInfo, OsAccountInfo &osAccountInfo)
{
    if (domainInfo.domain_.empty() ||
        domainInfo.domain_.size() > Constants::DOMAIN_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("domain is empty or too long, len %{public}zu.", domainInfo.domain_.size());
        return ERR_OSACCOUNT_KIT_DOMAIN_NAME_LENGTH_INVALID_ERROR;
    }

    if (domainInfo.accountName_.empty() ||
        domainInfo.accountName_.size() > Constants::DOMAIN_ACCOUNT_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("account name is empty or too long, len %{public}zu.", domainInfo.accountName_.size());
        return ERR_OSACCOUNT_KIT_DOMAIN_ACCOUNT_NAME_LENGTH_INVALID_ERROR;
    }

    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }

    return osAccountProxy_->CreateOsAccountForDomain(type, domainInfo, osAccountInfo);
}

ErrCode OsAccount::RemoveOsAccount(const int id)
{
    if (id <= Constants::START_USER_ID) {
        ACCOUNT_LOGE("cannot remove system preinstalled user");
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    if (id > Constants::MAX_USER_ID) {
        ACCOUNT_LOGE("localId %{public}d is out of range", id);
        return ERR_OSACCOUNT_KIT_LOCAL_ID_INVALID_ERROR;
    }
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }

    return osAccountProxy_->RemoveOsAccount(id);
}

ErrCode OsAccount::IsOsAccountExists(const int id, bool &isOsAccountExists)
{
    isOsAccountExists = false;
    ErrCode result = CheckLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
    result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }

    return osAccountProxy_->IsOsAccountExists(id, isOsAccountExists);
}

ErrCode OsAccount::IsOsAccountActived(const int id, bool &isOsAccountActived)
{
    isOsAccountActived = false;
    ErrCode result = CheckInvalidLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
    result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }

    return osAccountProxy_->IsOsAccountActived(id, isOsAccountActived);
}

ErrCode OsAccount::IsOsAccountConstraintEnable(const int id, const std::string &constraint, bool &isConstraintEnable)
{
    isConstraintEnable = false;
    ErrCode result = CheckLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
    result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }

    return osAccountProxy_->IsOsAccountConstraintEnable(id, constraint, isConstraintEnable);
}

ErrCode OsAccount::CheckOsAccountConstraintEnabled(const int id, const std::string &constraint, bool &isEnabled)
{
    isEnabled = false;
    ErrCode ret = CheckLocalId(id);
    if (ret != ERR_OK) {
        return ret;
    }
    ret = GetOsAccountProxy();
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", ret);
        return ret;
    }
    return osAccountProxy_->CheckOsAccountConstraintEnabled(id, constraint, isEnabled);
}

ErrCode OsAccount::IsOsAccountVerified(const int id, bool &isVerified)
{
    isVerified = false;
    ErrCode result = CheckInvalidLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
    result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }

    return osAccountProxy_->IsOsAccountVerified(id, isVerified);
}

ErrCode OsAccount::GetCreatedOsAccountsCount(unsigned int &osAccountsCount)
{
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }

    return osAccountProxy_->GetCreatedOsAccountsCount(osAccountsCount);
}

ErrCode OsAccount::GetOsAccountLocalIdFromProcess(int &id)
{
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }

    return osAccountProxy_->GetOsAccountLocalIdFromProcess(id);
}

ErrCode OsAccount::IsMainOsAccount(bool &isMainOsAccount)
{
    isMainOsAccount = false;
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }

    return osAccountProxy_->IsMainOsAccount(isMainOsAccount);
}

ErrCode OsAccount::GetOsAccountLocalIdFromDomain(const DomainAccountInfo &domainInfo, int &id)
{
    if (domainInfo.domain_.empty() ||
        domainInfo.domain_.size() > Constants::DOMAIN_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("invalid domain name length %{public}zu.", domainInfo.domain_.size());
        return ERR_OSACCOUNT_KIT_DOMAIN_NAME_LENGTH_INVALID_ERROR;
    }

    if (domainInfo.accountName_.empty() ||
        domainInfo.accountName_.size() > Constants::DOMAIN_ACCOUNT_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("invalid domain account name length %{public}zu.", domainInfo.accountName_.size());
        return ERR_OSACCOUNT_KIT_DOMAIN_ACCOUNT_NAME_LENGTH_INVALID_ERROR;
    }

    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }

    return osAccountProxy_->GetOsAccountLocalIdFromDomain(domainInfo, id);
}

ErrCode OsAccount::QueryMaxOsAccountNumber(int &maxOsAccountNumber)
{
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }

    return osAccountProxy_->QueryMaxOsAccountNumber(maxOsAccountNumber);
}

ErrCode OsAccount::GetOsAccountAllConstraints(const int id, std::vector<std::string> &constraints)
{
    ErrCode result = CheckInvalidLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
    result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }

    return osAccountProxy_->GetOsAccountAllConstraints(id, constraints);
}

ErrCode OsAccount::QueryAllCreatedOsAccounts(std::vector<OsAccountInfo> &osAccountInfos)
{
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }

    return osAccountProxy_->QueryAllCreatedOsAccounts(osAccountInfos);
}

ErrCode OsAccount::QueryCurrentOsAccount(OsAccountInfo &osAccountInfo)
{
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }

    return osAccountProxy_->QueryCurrentOsAccount(osAccountInfo);
}

ErrCode OsAccount::QueryOsAccountById(const int id, OsAccountInfo &osAccountInfo)
{
    ErrCode result = CheckLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
    result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }

    return osAccountProxy_->QueryOsAccountById(id, osAccountInfo);
}

ErrCode OsAccount::GetOsAccountTypeFromProcess(OsAccountType &type)
{
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }

    return osAccountProxy_->GetOsAccountTypeFromProcess(type);
}

ErrCode OsAccount::GetOsAccountProfilePhoto(const int id, std::string &photo)
{
    ErrCode result = CheckLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
    result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }

    return osAccountProxy_->GetOsAccountProfilePhoto(id, photo);
}

ErrCode OsAccount::IsMultiOsAccountEnable(bool &isMultiOsAccountEnable)
{
    isMultiOsAccountEnable = false;
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }

    return osAccountProxy_->IsMultiOsAccountEnable(isMultiOsAccountEnable);
}

ErrCode OsAccount::SetOsAccountName(const int id, const std::string &localName)
{
    ErrCode result = CheckLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
    if (localName.size() > Constants::LOCAL_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("name length %{public}zu too long!", localName.size());
        return ERR_OSACCOUNT_KIT_LOCAL_NAME_OUTFLOW_ERROR;
    }
    if (localName.empty()) {
        ACCOUNT_LOGE("name is empty!");
        return ERR_OSACCOUNT_KIT_LOCAL_NAME_EMPTY_ERROR;
    }
    result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }

    return osAccountProxy_->SetOsAccountName(id, localName);
}

ErrCode OsAccount::SetOsAccountConstraints(
    const int id, const std::vector<std::string> &constraints, const bool enable)
{
    ErrCode result = CheckLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
    result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }

    return osAccountProxy_->SetOsAccountConstraints(id, constraints, enable);
}

ErrCode OsAccount::SetOsAccountProfilePhoto(const int id, const std::string &photo)
{
    if (photo.empty()) {
        ACCOUNT_LOGE("photo is empty");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMTER;
    }
    ErrCode result = CheckLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
    if (photo.size() > Constants::LOCAL_PHOTO_MAX_SIZE) {
        ACCOUNT_LOGE("photo size %{public}zu too long!", photo.size());
        return ERR_OSACCOUNT_KIT_PHOTO_OUTFLOW_ERROR;
    }
    result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }

    return osAccountProxy_->SetOsAccountProfilePhoto(id, photo);
}

ErrCode OsAccount::GetDistributedVirtualDeviceId(std::string &deviceId)
{
    deviceId = "";
    std::pair<bool, OhosAccountInfo> res = OhosAccountKits::GetInstance().QueryOhosAccountInfo();
    if (res.first) {
        if (res.second.uid_ != DEFAULT_OHOS_ACCOUNT_UID) {
            deviceId = res.second.uid_;
        }
        return ERR_OK;
    }
    return ERR_OSACCOUNT_KIT_GET_DISTRIBUTED_VIRTUAL_DEVICE_ID_ERROR;
}

ErrCode OsAccount::ActivateOsAccount(const int id)
{
    ErrCode result = CheckLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
    result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }

    return osAccountProxy_->ActivateOsAccount(id);
}

ErrCode OsAccount::StartOsAccount(const int id)
{
    ErrCode result = CheckLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
    result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }

    return osAccountProxy_->StartOsAccount(id);
}

ErrCode OsAccount::StopOsAccount(const int id)
{
    ErrCode result = CheckLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
    result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }
    return osAccountProxy_->StopOsAccount(id);
}

ErrCode OsAccount::GetOsAccountLocalIdBySerialNumber(const int64_t serialNumber, int &id)
{
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }
    return osAccountProxy_->GetOsAccountLocalIdBySerialNumber(serialNumber, id);
}

ErrCode OsAccount::GetSerialNumberByOsAccountLocalId(const int &id, int64_t &serialNumber)
{
    ErrCode result = CheckInvalidLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
    result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }
    return osAccountProxy_->GetSerialNumberByOsAccountLocalId(id, serialNumber);
}

ErrCode OsAccount::SubscribeOsAccount(const std::shared_ptr<OsAccountSubscriber> &subscriber)
{
    if (subscriber == nullptr) {
        ACCOUNT_LOGE("subscriber is nullptr");
        return ERR_OSACCOUNT_KIT_SUBSCRIBER_IS_NULLPTR;
    }

    OsAccountSubscribeInfo subscribeInfo;
    subscriber->GetSubscribeInfo(subscribeInfo);
    OS_ACCOUNT_SUBSCRIBE_TYPE osAccountSubscribeType;
    subscribeInfo.GetOsAccountSubscribeType(osAccountSubscribeType);
    std::string name;
    subscribeInfo.GetName(name);

    if (GetOsAccountProxy() != ERR_OK) {
        ACCOUNT_LOGE("os account proxy is nullptr");
        return ERR_APPACCOUNT_KIT_APP_ACCOUNT_PROXY_IS_NULLPTR;
    }

    sptr<IRemoteObject> osAccountEventListener = nullptr;
    ErrCode subscribeState = CreateOsAccountEventListener(subscriber, osAccountEventListener);
    if (subscribeState == INITIAL_SUBSCRIPTION) {
        subscribeState = osAccountProxy_->SubscribeOsAccount(subscribeInfo, osAccountEventListener);
        if (subscribeState != ERR_OK) {
            eventListeners_.erase(subscriber);
        }
        return subscribeState;
    } else if (subscribeState == ALREADY_SUBSCRIBED) {
        return ERR_OK;
    } else {
        return ERR_OSACCOUNT_KIT_SUBSCRIBE_ERROR;
    }
}

ErrCode OsAccount::UnsubscribeOsAccount(const std::shared_ptr<OsAccountSubscriber> &subscriber)
{
    if (subscriber == nullptr) {
        ACCOUNT_LOGE("subscriber is nullptr");
        return ERR_APPACCOUNT_KIT_SUBSCRIBER_IS_NULLPTR;
    }

    if (GetOsAccountProxy() != ERR_OK) {
        ACCOUNT_LOGE("os account proxy is nullptr");
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
        ACCOUNT_LOGE("no specified subscriber has been registered");
        return ERR_OSACCOUNT_KIT_NO_SPECIFIED_SUBSCRIBER_HAS_BEEN_REGISTERED;
    }
}

OS_ACCOUNT_SWITCH_MOD OsAccount::GetOsAccountSwitchMod()
{
    if (GetOsAccountProxy() != ERR_OK) {
        ACCOUNT_LOGE("os account proxy is nullptr");
        return OS_ACCOUNT_SWITCH_MOD::ERROR_MOD;
    }
    return osAccountProxy_->GetOsAccountSwitchMod();
}

ErrCode OsAccount::DumpState(const int &id, std::vector<std::string> &state)
{
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }

    return osAccountProxy_->DumpState(id, state);
}

ErrCode OsAccount::ResetOsAccountProxy()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if ((osAccountProxy_ != nullptr) && (osAccountProxy_->AsObject() != nullptr)) {
        osAccountProxy_->AsObject()->RemoveDeathRecipient(deathRecipient_);
    }
    osAccountProxy_ = nullptr;

    return ERR_OK;
}

ErrCode OsAccount::IsCurrentOsAccountVerified(bool &isVerified)
{
    isVerified = false;
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }
    return osAccountProxy_->IsCurrentOsAccountVerified(isVerified);
}

ErrCode OsAccount::IsOsAccountCompleted(const int id, bool &isOsAccountCompleted)
{
    isOsAccountCompleted = false;
    ErrCode result = CheckLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
    result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }
    return osAccountProxy_->IsOsAccountCompleted(id, isOsAccountCompleted);
}

ErrCode OsAccount::SetCurrentOsAccountIsVerified(const bool isVerified)
{
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }
    return osAccountProxy_->SetCurrentOsAccountIsVerified(isVerified);
}

ErrCode OsAccount::SetOsAccountIsVerified(const int id, const bool isVerified)
{
    ErrCode result = CheckLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
    result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }
    return osAccountProxy_->SetOsAccountIsVerified(id, isVerified);
}

ErrCode OsAccount::GetOsAccountProxy()
{
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
                ACCOUNT_LOGE("failed to get os account service");
                return ERR_OSACCOUNT_KIT_GET_APP_ACCOUNT_SERVICE_ERROR;
            }

            osAccountProxy_ = iface_cast<IOsAccount>(osAccountRemoteObject);
            if ((!osAccountProxy_) || (!osAccountProxy_->AsObject())) {
                ACCOUNT_LOGE("failed to cast os account proxy");
                osAccountProxy_ = nullptr;
                return ERR_OSACCOUNT_KIT_GET_APP_ACCOUNT_PROXY_ERROR;
            }

            deathRecipient_ = new (std::nothrow) OsAccountDeathRecipient();
            if (!deathRecipient_) {
                ACCOUNT_LOGE("failed to create os account death recipient");
                osAccountProxy_ = nullptr;
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
    if (subscriber == nullptr) {
        ACCOUNT_LOGE("subscriber is nullptr");
        return SUBSCRIBE_FAILED;
    }

    std::lock_guard<std::mutex> lock(eventListenersMutex_);

    auto eventListener = eventListeners_.find(subscriber);
    if (eventListener != eventListeners_.end()) {
        osAccountEventListener = eventListener->second->AsObject();
        ACCOUNT_LOGI("subscriber already has os account event listener");
        return ALREADY_SUBSCRIBED;
    } else {
        if (eventListeners_.size() == Constants::SUBSCRIBER_MAX_SIZE) {
            ACCOUNT_LOGE("the maximum number of subscribers has been reached");
            return SUBSCRIBE_FAILED;
        }

        sptr<OsAccountEventListener> listener = new (std::nothrow) OsAccountEventListener(subscriber);
        if (!listener) {
            ACCOUNT_LOGE("memory allocation for listener failed!");
            return SUBSCRIBE_FAILED;
        }
        osAccountEventListener = listener->AsObject();
        eventListeners_[subscriber] = listener;
    }

    return INITIAL_SUBSCRIPTION;
}

ErrCode OsAccount::GetCreatedOsAccountNumFromDatabase(const std::string& storeID, int &createdOsAccountNum)
{
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }
    return osAccountProxy_->GetCreatedOsAccountNumFromDatabase(storeID, createdOsAccountNum);
}

ErrCode OsAccount::GetSerialNumberFromDatabase(const std::string& storeID, int64_t &serialNumber)
{
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }
    return osAccountProxy_->GetSerialNumberFromDatabase(storeID, serialNumber);
}

ErrCode OsAccount::GetMaxAllowCreateIdFromDatabase(const std::string& storeID, int &id)
{
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }
    return osAccountProxy_->GetMaxAllowCreateIdFromDatabase(storeID, id);
}

ErrCode OsAccount::GetOsAccountFromDatabase(const std::string& storeID, const int id, OsAccountInfo &osAccountInfo)
{
    ErrCode result = CheckLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
    result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }
    return osAccountProxy_->GetOsAccountFromDatabase(storeID, id, osAccountInfo);
}

ErrCode OsAccount::GetOsAccountListFromDatabase(const std::string& storeID, std::vector<OsAccountInfo> &osAccountList)
{
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }
    return osAccountProxy_->GetOsAccountListFromDatabase(storeID, osAccountList);
}

ErrCode OsAccount::QueryActiveOsAccountIds(std::vector<int32_t>& ids)
{
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_, result %{public}d.", result);
        return result;
    }
    return osAccountProxy_->QueryActiveOsAccountIds(ids);
}

ErrCode OsAccount::QueryOsAccountConstraintSourceTypes(const int32_t id, const std::string &constraint,
    std::vector<ConstraintSourceTypeInfo> &constraintSourceTypeInfos)
{
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_");
        return result;
    }

    return osAccountProxy_->QueryOsAccountConstraintSourceTypes(id, constraint, constraintSourceTypeInfos);
}

ErrCode OsAccount::SetGlobalOsAccountConstraints(const std::vector<std::string> &constraints,
    const bool enable, const int32_t enforcerId, const bool isDeviceOwner)
{
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_");
        return result;
    }

    return osAccountProxy_->SetGlobalOsAccountConstraints(constraints, enable, enforcerId, isDeviceOwner);
}

ErrCode OsAccount::SetSpecificOsAccountConstraints(const std::vector<std::string> &constraints,
    const bool enable, const int32_t targetId, const int32_t enforcerId, const bool isDeviceOwner)
{
    ErrCode result = GetOsAccountProxy();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get osAccountProxy_");
        return result;
    }

    return osAccountProxy_->SetSpecificOsAccountConstraints(constraints, enable, targetId, enforcerId, isDeviceOwner);
}
}  // namespace AccountSA
}  // namespace OHOS
