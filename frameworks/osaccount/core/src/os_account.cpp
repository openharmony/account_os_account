/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#include "account_permission_manager.h"
#include "account_proxy.h"
#include "domain_account_callback_service.h"
#include "ohos_account_kits_impl.h"
#include "os_account_constants.h"
#include "os_account_death_recipient.h"

namespace OHOS {
namespace AccountSA {
static ErrCode CheckInvalidLocalId(int localId)
{
    if (localId > Constants::MAX_USER_ID) {
        ACCOUNT_LOGE("id %{public}d is out of range", localId);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
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
    static OsAccount *instance = new (std::nothrow) OsAccount();
    return *instance;
}

ErrCode OsAccount::CreateOsAccount(const std::string &name, const OsAccountType &type, OsAccountInfo &osAccountInfo)
{
    size_t localNameSize = name.size();
    if (localNameSize == 0 || localNameSize > Constants::LOCAL_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("CreateOsAccount local name length %{public}zu is invalid!", localNameSize);
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return proxy->CreateOsAccount(name, type, osAccountInfo);
}

ErrCode OsAccount::CreateOsAccount(const std::string& localName, const std::string& shortName,
    const OsAccountType& type, OsAccountInfo& osAccountInfo, const CreateOsAccountOptions &options)
{
    size_t localNameSize = localName.size();
    if (localNameSize == 0 || localNameSize > Constants::LOCAL_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("CreateOsAccount local name length %{public}zu is invalid!", localNameSize);
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    size_t shortNameSize = shortName.size();
    if (shortNameSize == 0 || shortNameSize > Constants::SHORT_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("CreateOsAccount short name length %{public}zu is invalid!", shortNameSize);
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->CreateOsAccount(localName, shortName, type, osAccountInfo, options);
}

ErrCode OsAccount::CreateOsAccountWithFullInfo(OsAccountInfo &osAccountInfo)
{
    ErrCode code = osAccountInfo.ParamCheck();
    if (code != ERR_OK) {
        return code;
    }

    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->CreateOsAccountWithFullInfo(osAccountInfo);
}

ErrCode OsAccount::UpdateOsAccountWithFullInfo(OsAccountInfo &osAccountInfo)
{
    ErrCode code = osAccountInfo.ParamCheck();
    if (code != ERR_OK) {
        return code;
    }

    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->UpdateOsAccountWithFullInfo(osAccountInfo);
}

ErrCode OsAccount::CreateOsAccountForDomain(const OsAccountType &type, const DomainAccountInfo &domainInfo,
    const std::shared_ptr<DomainAccountCallback> &callback, const CreateOsAccountForDomainOptions& options)
{
    if (domainInfo.domain_.empty() ||
        domainInfo.domain_.size() > Constants::DOMAIN_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("Domain is empty or too long, len=%{public}zu.", domainInfo.domain_.size());
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    if (domainInfo.accountName_.empty() ||
        domainInfo.accountName_.size() > Constants::LOCAL_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("Account name is empty or too long, len=%{public}zu.", domainInfo.accountName_.size());
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    if (options.hasShortName && ((options.shortName.size() > Constants::SHORT_NAME_MAX_SIZE) ||
        (options.shortName == ""))) {
        ACCOUNT_LOGE("Account short name is empty or too long, len=%{public}zu.", options.shortName.size());
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    sptr<DomainAccountCallbackService> callbackService = new (std::nothrow) DomainAccountCallbackService(callback);
    return proxy->CreateOsAccountForDomain(type, domainInfo, callbackService, options);
}

ErrCode OsAccount::RemoveOsAccount(const int id)
{
    if (id <= Constants::START_USER_ID) {
        ACCOUNT_LOGE("cannot remove system preinstalled user");
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    if (id > Constants::MAX_USER_ID) {
        ACCOUNT_LOGE("localId %{public}d is out of range", id);
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return proxy->RemoveOsAccount(id);
}

ErrCode OsAccount::IsOsAccountExists(const int id, bool &isOsAccountExists)
{
    isOsAccountExists = false;
    ErrCode result = CheckLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return proxy->IsOsAccountExists(id, isOsAccountExists);
}

ErrCode OsAccount::IsOsAccountActived(const int id, bool &isOsAccountActived)
{
    isOsAccountActived = false;
    ErrCode result = CheckInvalidLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return proxy->IsOsAccountActived(id, isOsAccountActived);
}

ErrCode OsAccount::IsOsAccountConstraintEnable(const int id, const std::string &constraint, bool &isConstraintEnable)
{
    isConstraintEnable = false;
    ErrCode result = CheckLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return proxy->IsOsAccountConstraintEnable(id, constraint, isConstraintEnable);
}

ErrCode OsAccount::CheckOsAccountConstraintEnabled(const int id, const std::string &constraint, bool &isEnabled)
{
    isEnabled = false;
    ErrCode ret = CheckLocalId(id);
    if (ret != ERR_OK) {
        return ret;
    }
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->CheckOsAccountConstraintEnabled(id, constraint, isEnabled);
}

ErrCode OsAccount::IsOsAccountVerified(const int id, bool &isVerified)
{
    isVerified = false;
    ErrCode result = CheckInvalidLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return proxy->IsOsAccountVerified(id, isVerified);
}

ErrCode OsAccount::GetCreatedOsAccountsCount(unsigned int &osAccountsCount)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return proxy->GetCreatedOsAccountsCount(osAccountsCount);
}

ErrCode OsAccount::GetOsAccountLocalIdFromProcess(int &id)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return proxy->GetOsAccountLocalIdFromProcess(id);
}

ErrCode OsAccount::IsMainOsAccount(bool &isMainOsAccount)
{
    isMainOsAccount = false;
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return proxy->IsMainOsAccount(isMainOsAccount);
}

ErrCode OsAccount::GetOsAccountLocalIdFromDomain(const DomainAccountInfo &domainInfo, int &id)
{
    if (domainInfo.domain_.empty() ||
        domainInfo.domain_.size() > Constants::DOMAIN_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("invalid domain name length %{public}zu.", domainInfo.domain_.size());
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    if (domainInfo.accountName_.empty() ||
        domainInfo.accountName_.size() > Constants::LOCAL_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("invalid domain account name length %{public}zu.", domainInfo.accountName_.size());
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return proxy->GetOsAccountLocalIdFromDomain(domainInfo, id);
}

ErrCode OsAccount::QueryMaxOsAccountNumber(uint32_t &maxOsAccountNumber)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return proxy->QueryMaxOsAccountNumber(maxOsAccountNumber);
}

ErrCode OsAccount::QueryMaxLoggedInOsAccountNumber(uint32_t &maxNum)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return proxy->QueryMaxLoggedInOsAccountNumber(maxNum);
}

ErrCode OsAccount::GetOsAccountAllConstraints(const int id, std::vector<std::string> &constraints)
{
    ErrCode result = CheckInvalidLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return proxy->GetOsAccountAllConstraints(id, constraints);
}

ErrCode OsAccount::QueryAllCreatedOsAccounts(std::vector<OsAccountInfo> &osAccountInfos)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return proxy->QueryAllCreatedOsAccounts(osAccountInfos);
}

ErrCode OsAccount::QueryCurrentOsAccount(OsAccountInfo &osAccountInfo)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return proxy->QueryCurrentOsAccount(osAccountInfo);
}

ErrCode OsAccount::QueryOsAccountById(const int id, OsAccountInfo &osAccountInfo)
{
    ErrCode result = CheckLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return proxy->QueryOsAccountById(id, osAccountInfo);
}

ErrCode OsAccount::GetOsAccountTypeFromProcess(OsAccountType &type)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return proxy->GetOsAccountTypeFromProcess(type);
}

ErrCode OsAccount::GetOsAccountType(const int id, OsAccountType& type)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return proxy->GetOsAccountType(id, type);
}

ErrCode OsAccount::GetOsAccountProfilePhoto(const int id, std::string &photo)
{
    ErrCode result = CheckLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return proxy->GetOsAccountProfilePhoto(id, photo);
}

ErrCode OsAccount::IsMultiOsAccountEnable(bool &isMultiOsAccountEnable)
{
    isMultiOsAccountEnable = false;
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return proxy->IsMultiOsAccountEnable(isMultiOsAccountEnable);
}

ErrCode OsAccount::SetOsAccountName(const int id, const std::string &localName)
{
    ErrCode result = CheckLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
    if (localName.size() > Constants::LOCAL_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("name length %{public}zu too long!", localName.size());
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    if (localName.empty()) {
        ACCOUNT_LOGE("name is empty!");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return proxy->SetOsAccountName(id, localName);
}

ErrCode OsAccount::SetOsAccountConstraints(
    const int id, const std::vector<std::string> &constraints, const bool enable)
{
    ErrCode result = CheckLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return proxy->SetOsAccountConstraints(id, constraints, enable);
}

ErrCode OsAccount::SetOsAccountProfilePhoto(const int id, const std::string &photo)
{
    if (photo.empty()) {
        ACCOUNT_LOGE("photo is empty");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    ErrCode result = CheckLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
    if (photo.size() > Constants::LOCAL_PHOTO_MAX_SIZE) {
        ACCOUNT_LOGE("photo size %{public}zu too long!", photo.size());
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return proxy->SetOsAccountProfilePhoto(id, photo);
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
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return proxy->ActivateOsAccount(id);
}

ErrCode OsAccount::DeactivateOsAccount(const int id)
{
    ErrCode result = CheckLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return proxy->DeactivateOsAccount(id);
}

ErrCode OsAccount::DeactivateAllOsAccounts()
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return proxy->DeactivateAllOsAccounts();
}

ErrCode OsAccount::StartOsAccount(const int id)
{
    ErrCode result = CheckLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return proxy->StartOsAccount(id);
}

ErrCode OsAccount::GetOsAccountLocalIdBySerialNumber(const int64_t serialNumber, int &id)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->GetOsAccountLocalIdBySerialNumber(serialNumber, id);
}

ErrCode OsAccount::GetSerialNumberByOsAccountLocalId(const int &id, int64_t &serialNumber)
{
    ErrCode result = CheckInvalidLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->GetSerialNumberByOsAccountLocalId(id, serialNumber);
}

ErrCode OsAccount::SubscribeOsAccount(const std::shared_ptr<OsAccountSubscriber> &subscriber)
{
    if (subscriber == nullptr) {
        ACCOUNT_LOGE("subscriber is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }

    OsAccountSubscribeInfo subscribeInfo;
    subscriber->GetSubscribeInfo(subscribeInfo);
    OS_ACCOUNT_SUBSCRIBE_TYPE osAccountSubscribeType;
    subscribeInfo.GetOsAccountSubscribeType(osAccountSubscribeType);
    std::string name;
    subscribeInfo.GetName(name);

    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    sptr<IRemoteObject> osAccountEventListener = nullptr;
    ErrCode subscribeState = CreateOsAccountEventListener(subscriber, osAccountEventListener);
    if (subscribeState == INITIAL_SUBSCRIPTION) {
        subscribeState = proxy->SubscribeOsAccount(subscribeInfo, osAccountEventListener);
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
    ErrCode result = AccountPermissionManager::CheckSystemApp(false);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("is not system application, result = %{public}u.", result);
        return result;
    }
    if (subscriber == nullptr) {
        ACCOUNT_LOGE("subscriber is nullptr");
        return ERR_APPACCOUNT_KIT_SUBSCRIBER_IS_NULLPTR;
    }

    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    std::lock_guard<std::mutex> lock(eventListenersMutex_);

    auto eventListener = eventListeners_.find(subscriber);
    if (eventListener != eventListeners_.end()) {
        result = proxy->UnsubscribeOsAccount(eventListener->second->AsObject());
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
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return OS_ACCOUNT_SWITCH_MOD::ERROR_MOD;
    }
    return proxy->GetOsAccountSwitchMod();
}

ErrCode OsAccount::DumpState(const int &id, std::vector<std::string> &state)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return proxy->DumpState(id, state);
}

ErrCode OsAccount::ResetOsAccountProxy()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if ((proxy_ != nullptr) && (proxy_->AsObject() != nullptr)) {
        proxy_->AsObject()->RemoveDeathRecipient(deathRecipient_);
    }
    proxy_ = nullptr;
    return ERR_OK;
}

ErrCode OsAccount::IsCurrentOsAccountVerified(bool &isVerified)
{
    isVerified = false;
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->IsCurrentOsAccountVerified(isVerified);
}

ErrCode OsAccount::IsOsAccountCompleted(const int id, bool &isOsAccountCompleted)
{
    isOsAccountCompleted = false;
    ErrCode result = CheckLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->IsOsAccountCompleted(id, isOsAccountCompleted);
}

ErrCode OsAccount::SetCurrentOsAccountIsVerified(const bool isVerified)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->SetCurrentOsAccountIsVerified(isVerified);
}

ErrCode OsAccount::SetOsAccountIsVerified(const int id, const bool isVerified)
{
    ErrCode result = CheckLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->SetOsAccountIsVerified(id, isVerified);
}

sptr<IOsAccount> OsAccount::GetOsAccountProxy()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy_ != nullptr) {
        return proxy_;
    }
    sptr<IRemoteObject> object = OhosAccountKitsImpl::GetInstance().GetOsAccountService();
    if (object == nullptr) {
        ACCOUNT_LOGE("failed to get os account service");
        return nullptr;
    }
    deathRecipient_ = new (std::nothrow) OsAccountDeathRecipient();
    if (deathRecipient_ == nullptr) {
        ACCOUNT_LOGE("failed to create os account death recipient");
        return nullptr;
    }
    if (!object->AddDeathRecipient(deathRecipient_)) {
        ACCOUNT_LOGE("failed to add os account death recipient");
        deathRecipient_ = nullptr;
        return nullptr;
    }
    proxy_ = iface_cast<IOsAccount>(object);
    if (proxy_ == nullptr) {
        ACCOUNT_LOGE("failed to get os account proxy");
    }
    return proxy_;
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
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->GetCreatedOsAccountNumFromDatabase(storeID, createdOsAccountNum);
}

ErrCode OsAccount::GetSerialNumberFromDatabase(const std::string& storeID, int64_t &serialNumber)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->GetSerialNumberFromDatabase(storeID, serialNumber);
}

ErrCode OsAccount::GetMaxAllowCreateIdFromDatabase(const std::string& storeID, int &id)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->GetMaxAllowCreateIdFromDatabase(storeID, id);
}

ErrCode OsAccount::GetOsAccountFromDatabase(const std::string& storeID, const int id, OsAccountInfo &osAccountInfo)
{
    ErrCode result = CheckLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->GetOsAccountFromDatabase(storeID, id, osAccountInfo);
}

ErrCode OsAccount::GetOsAccountListFromDatabase(const std::string& storeID, std::vector<OsAccountInfo> &osAccountList)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->GetOsAccountListFromDatabase(storeID, osAccountList);
}

ErrCode OsAccount::QueryActiveOsAccountIds(std::vector<int32_t>& ids)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->QueryActiveOsAccountIds(ids);
}

ErrCode OsAccount::QueryOsAccountConstraintSourceTypes(const int32_t id, const std::string &constraint,
    std::vector<ConstraintSourceTypeInfo> &constraintSourceTypeInfos)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return proxy->QueryOsAccountConstraintSourceTypes(id, constraint, constraintSourceTypeInfos);
}

ErrCode OsAccount::SetGlobalOsAccountConstraints(const std::vector<std::string> &constraints,
    const bool enable, const int32_t enforcerId, const bool isDeviceOwner)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return proxy->SetGlobalOsAccountConstraints(constraints, enable, enforcerId, isDeviceOwner);
}

ErrCode OsAccount::SetSpecificOsAccountConstraints(const std::vector<std::string> &constraints,
    const bool enable, const int32_t targetId, const int32_t enforcerId, const bool isDeviceOwner)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    return proxy->SetSpecificOsAccountConstraints(constraints, enable, targetId, enforcerId, isDeviceOwner);
}

ErrCode OsAccount::SetDefaultActivatedOsAccount(const int32_t id)
{
    ErrCode result = CheckLocalId(id);
    if (result != ERR_OK) {
        return result;
    }
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->SetDefaultActivatedOsAccount(id);
}

ErrCode OsAccount::GetDefaultActivatedOsAccount(int32_t &id)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->GetDefaultActivatedOsAccount(id);
}

ErrCode OsAccount::GetOsAccountShortName(std::string &shortName)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->GetOsAccountShortName(shortName);
}

ErrCode OsAccount::GetOsAccountName(std::string &name)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->GetOsAccountName(name);
}

ErrCode OsAccount::GetOsAccountShortNameById(const int32_t id, std::string &shortName)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->GetOsAccountShortNameById(id, shortName);
}

ErrCode OsAccount::IsOsAccountForeground(bool &isForeground)
{
    return IsOsAccountForegroundCommon(-1, Constants::DEFAULT_DISPALY_ID, isForeground);
}

ErrCode OsAccount::IsOsAccountForeground(const int32_t localId, bool &isForeground)
{
    if (localId < Constants::ADMIN_LOCAL_ID) {
        ACCOUNT_LOGE("LocalId %{public}d is invlaid", localId);
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    return IsOsAccountForegroundCommon(localId, Constants::DEFAULT_DISPALY_ID, isForeground);
}

ErrCode OsAccount::IsOsAccountForeground(const int32_t localId, const uint64_t displayId, bool &isForeground)
{
    if (localId < Constants::ADMIN_LOCAL_ID) {
        ACCOUNT_LOGE("LocalId %{public}d is invlaid", localId);
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    if (displayId != Constants::DEFAULT_DISPALY_ID) {
        ACCOUNT_LOGE("DisplayId %{public}llu not exist", static_cast<unsigned long long>(displayId));
        return ERR_ACCOUNT_COMMON_DISPLAY_ID_NOT_EXIST_ERROR;
    }
    return IsOsAccountForegroundCommon(localId, displayId, isForeground);
}

ErrCode OsAccount::IsOsAccountForegroundCommon(const int32_t localId, const uint64_t displayId, bool &isForeground)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->IsOsAccountForeground(localId, displayId, isForeground);
}

ErrCode OsAccount::GetForegroundOsAccountLocalId(int32_t &localId)
{
    return GetForegroundLocalIdCommon(Constants::DEFAULT_DISPALY_ID, localId);
}

ErrCode OsAccount::GetForegroundOsAccountLocalId(const uint64_t displayId, int32_t &localId)
{
    if (displayId != Constants::DEFAULT_DISPALY_ID) {
        ACCOUNT_LOGE("DisplayId %{public}llu not exist", static_cast<unsigned long long>(displayId));
        return ERR_ACCOUNT_COMMON_DISPLAY_ID_NOT_EXIST_ERROR;
    }
    return GetForegroundLocalIdCommon(displayId, localId);
}

ErrCode OsAccount::GetForegroundLocalIdCommon(const uint64_t displayId, int32_t &localId)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->GetForegroundOsAccountLocalId(displayId, localId);
}

ErrCode OsAccount::GetForegroundOsAccounts(std::vector<ForegroundOsAccount> &accounts)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->GetForegroundOsAccounts(accounts);
}

ErrCode OsAccount::GetBackgroundOsAccountLocalIds(std::vector<int32_t> &localIds)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->GetBackgroundOsAccountLocalIds(localIds);
}

ErrCode OsAccount::SetOsAccountToBeRemoved(int32_t localId, bool toBeRemoved)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return proxy->SetOsAccountToBeRemoved(localId, toBeRemoved);
}
}  // namespace AccountSA
}  // namespace OHOS
