/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
#include "os_account_info_json_parser.h"
#include "system_ability_definition.h"
#include "string_raw_data.h"

namespace OHOS {
namespace AccountSA {
namespace {
bool ReadOsAccountInfo(const StringRawData& stringRawData, OsAccountInfo& osAccountInfo)
{
    std::string accountStr;
    stringRawData.Unmarshalling(accountStr);
    auto jsonObject = CreateJsonFromString(accountStr);
    if (jsonObject == nullptr) {
        ACCOUNT_LOGE("AccountStr is discarded");
        return false;
    }
    return FromJson(jsonObject.get(), osAccountInfo);
}

bool ReadOsAccountInfoVector(const StringRawData& stringRawData, std::vector<OsAccountInfo>& osAccountInfos)
{
    std::string accountStrs;
    stringRawData.Unmarshalling(accountStrs);
    auto accountsJson = CreateJsonFromString(accountStrs);
    if (accountsJson == nullptr) {
        ACCOUNT_LOGE("AccountStrs is discarded");
        return false;
    }

    if (!IsArray(accountsJson)) {
        ACCOUNT_LOGE("IsArray failed, please check accountsJson");
        return false;
    }

    auto arraySize = GetItemNum(accountsJson);
    for (int i = 0; i < arraySize; ++i) {
        cJSON *item = GetItemFromArray(accountsJson, i);
        if (item != nullptr) {
            OsAccountInfo accountInfo;
            FromJson(item, accountInfo);
            osAccountInfos.emplace_back(accountInfo);
        }
    }
    return true;
}

ErrCode ConvertToAccountErrCode(ErrCode idlErrCode)
{
    if (idlErrCode == ERR_INVALID_VALUE) {
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (idlErrCode == ERR_INVALID_DATA) {
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return idlErrCode;
}
}  // namespace
static ErrCode CheckLocalId(int localId)
{
    if (localId < 0) {
        ACCOUNT_LOGE("id %{public}d is invalid", localId);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    return ERR_OK;
}

OsAccount &OsAccount::GetInstance()
{
    static OsAccount *instance = new (std::nothrow) OsAccount();
    return *instance;
}

OsAccount::OsAccount()
{
    auto callbackFunc = [] (int32_t systemAbilityId, const std::string &deviceId) {
        if (systemAbilityId == SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN) {
            OsAccount::GetInstance().RestoreListenerRecords();
            OsAccount::GetInstance().RestoreConstraintSubscriberRecords();
        }
    };
    OhosAccountKitsImpl::GetInstance().SubscribeSystemAbility(callbackFunc);
}

void OsAccount::RestoreConstraintSubscriberRecords()
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("GetProxy failed");
        return;
    }
    OsAccountConstraintSubscriberManager::GetInstance()->RestoreConstraintSubscriberRecords(proxy);
}

void OsAccount::RestoreListenerRecords()
{
    std::lock_guard<std::mutex> lock(eventListenersMutex_);
    if (listenerManager_ == nullptr || listenerManager_->Size() == 0) {
        return;
    }
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("GetProxy failed");
        return;
    }
    ErrCode result = proxy->SubscribeOsAccount(listenerManager_->GetTotalSubscribeInfo(), listenerManager_);
    result = ConvertToAccountErrCode(result);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SubscribeOsAccount failed, errCode=%{public}d", result);
    }
    ACCOUNT_LOGI("Restore ListenerManager success, record=%{public}d", listenerManager_->Size());
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

    auto typeValue = static_cast<int32_t>(type);
    StringRawData stringRawData;
    auto errCode = proxy->CreateOsAccount(name, typeValue, stringRawData);
    if (errCode == ERR_OK && !ReadOsAccountInfo(stringRawData, osAccountInfo)) {
        ACCOUNT_LOGE("Read osAccountInfo failed, please check osAccountInfo");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    return ConvertToAccountErrCode(errCode);
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
    if (options.hasShortName && (shortNameSize == 0 || shortNameSize > Constants::SHORT_NAME_MAX_SIZE)) {
        ACCOUNT_LOGE("CreateOsAccount short name length %{public}zu is invalid!", shortNameSize);
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    auto typeValue = static_cast<int32_t>(type);
    StringRawData stringRawData;
    auto errCode = proxy->CreateOsAccount(localName, shortName, typeValue, stringRawData, options);
    if (errCode == ERR_OK && !ReadOsAccountInfo(stringRawData, osAccountInfo)) {
        ACCOUNT_LOGE("Read osAccountInfo failed, please check osAccountInfo");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::CreateOsAccountWithFullInfo(OsAccountInfo &osAccountInfo, const CreateOsAccountOptions &options)
{
    ErrCode code = osAccountInfo.ParamCheck();
    if (code != ERR_OK) {
        return code;
    }

    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    auto errCode = proxy->CreateOsAccountWithFullInfo(osAccountInfo, options);
    return ConvertToAccountErrCode(errCode);
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
    auto errCode = proxy->UpdateOsAccountWithFullInfo(osAccountInfo);
    return ConvertToAccountErrCode(errCode);
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
    auto typeValue = static_cast<int32_t>(type);
    auto errCode = proxy->CreateOsAccountForDomain(typeValue, domainInfo, callbackService, options);
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::RemoveOsAccount(const int id)
{
    if (id < 0) {
        ACCOUNT_LOGE("Id is invalid");
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    auto errCode = proxy->RemoveOsAccount(id);
    return ConvertToAccountErrCode(errCode);
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

    auto errCode = proxy->IsOsAccountExists(id, isOsAccountExists);
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::IsOsAccountActived(const int id, bool &isOsAccountActived)
{
    isOsAccountActived = false;
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    auto errCode = proxy->IsOsAccountActived(id, isOsAccountActived);
    return ConvertToAccountErrCode(errCode);
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

    auto errCode = proxy->IsOsAccountConstraintEnable(id, constraint, isConstraintEnable);
    return ConvertToAccountErrCode(errCode);
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
    auto errCode = proxy->CheckOsAccountConstraintEnabled(id, constraint, isEnabled);
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::IsOsAccountVerified(const int id, bool &isVerified)
{
    isVerified = false;
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    auto errCode = proxy->IsOsAccountVerified(id, isVerified);
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::IsOsAccountDeactivating(const int id, bool &isDeactivating)
{
    isDeactivating = false;
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    auto errCode = proxy->IsOsAccountDeactivating(id, isDeactivating);
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::GetCreatedOsAccountsCount(unsigned int &osAccountsCount)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    auto errCode = proxy->GetCreatedOsAccountsCount(osAccountsCount);
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::GetOsAccountLocalIdFromProcess(int &id)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    auto errCode = proxy->GetOsAccountLocalIdFromProcess(id);
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::IsMainOsAccount(bool &isMainOsAccount)
{
    isMainOsAccount = false;
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    auto errCode = proxy->IsMainOsAccount(isMainOsAccount);
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::GetOsAccountLocalIdFromDomain(const DomainAccountInfo &domainInfo, int &id)
{
    if (domainInfo.domain_.empty() ||
        domainInfo.domain_.size() > Constants::DOMAIN_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("invalid domain name length %{public}zu.", domainInfo.domain_.size());
        NativeErrMsg() = "Invalid domainInfo.domain."
            "The length of the domainInfo.domain must be greater than 0 and less than 1025";
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    if (domainInfo.accountName_.empty() ||
        domainInfo.accountName_.size() > Constants::LOCAL_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("invalid domain account name length %{public}zu.", domainInfo.accountName_.size());
        NativeErrMsg() = "Invalid domainInfo.accountName."
            "The length of domainInfo.accountName must be greater than 0, and less than or equal to LOGIN_NAME_MAX";
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    auto errCode = proxy->GetOsAccountLocalIdFromDomain(domainInfo, id);
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::QueryMaxOsAccountNumber(uint32_t &maxOsAccountNumber)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    auto errCode = proxy->QueryMaxOsAccountNumber(maxOsAccountNumber);
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::QueryMaxLoggedInOsAccountNumber(uint32_t &maxNum)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    auto errCode = proxy->QueryMaxLoggedInOsAccountNumber(maxNum);
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::GetOsAccountAllConstraints(const int id, std::vector<std::string> &constraints)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    std::vector<std::string> constraintsVec;
    auto errCode = proxy->GetOsAccountAllConstraints(id, constraintsVec);
    if (errCode == ERR_OK) {
        constraints = std::move(constraintsVec);
    }
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::QueryAllCreatedOsAccounts(std::vector<OsAccountInfo> &osAccountInfos)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    StringRawData stringRawData;
    auto errCode = proxy->QueryAllCreatedOsAccounts(stringRawData);
    if (errCode == ERR_OK) {
        ReadOsAccountInfoVector(stringRawData, osAccountInfos);
    }
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::QueryCurrentOsAccount(OsAccountInfo &osAccountInfo)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    StringRawData stringRawData;
    auto errCode = proxy->QueryCurrentOsAccount(stringRawData);
    if (errCode == ERR_OK && !ReadOsAccountInfo(stringRawData, osAccountInfo)) {
        ACCOUNT_LOGE("Read osAccountInfo failed, please check osAccountInfo");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    return ConvertToAccountErrCode(errCode);
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

    StringRawData stringRawData;
    auto errCode = proxy->QueryOsAccountById(id, stringRawData);
    if (errCode == ERR_OK && !ReadOsAccountInfo(stringRawData, osAccountInfo)) {
        ACCOUNT_LOGE("Read osAccountInfo failed, please check osAccountInfo");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::GetOsAccountTypeFromProcess(OsAccountType &type)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    auto typeValue = static_cast<int32_t>(OsAccountType::ADMIN);
    auto errCode = proxy->GetOsAccountTypeFromProcess(typeValue);
    type = static_cast<OsAccountType>(typeValue);
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::GetOsAccountType(const int id, OsAccountType& type)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    auto typeValue = static_cast<int32_t>(OsAccountType::ADMIN);
    auto errCode = proxy->GetOsAccountType(id, typeValue);
    type = static_cast<OsAccountType>(typeValue);
    return ConvertToAccountErrCode(errCode);
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

    StringRawData stringRawData;
    auto errCode = proxy->GetOsAccountProfilePhoto(id, stringRawData);
    if (errCode == ERR_OK) {
        stringRawData.Unmarshalling(photo);
    }
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::IsMultiOsAccountEnable(bool &isMultiOsAccountEnable)
{
    isMultiOsAccountEnable = false;
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    auto errCode = proxy->IsMultiOsAccountEnable(isMultiOsAccountEnable);
    return ConvertToAccountErrCode(errCode);
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

    auto errCode = proxy->SetOsAccountName(id, localName);
    return ConvertToAccountErrCode(errCode);
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

    auto errCode = proxy->SetOsAccountConstraints(id, constraints, enable);
    return ConvertToAccountErrCode(errCode);
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

    StringRawData stringRawData;
    stringRawData.Marshalling(photo);
    auto errCode = proxy->SetOsAccountProfilePhoto(id, stringRawData);
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::GetDistributedVirtualDeviceId(std::string &dvid)
{
    return OhosAccountKitsImpl::GetInstance().QueryDistributedVirtualDeviceId(dvid);
}

ErrCode OsAccount::QueryDistributedVirtualDeviceId(const std::string &bundleName, int32_t localId, std::string &dvid)
{
    return OhosAccountKitsImpl::GetInstance().QueryDistributedVirtualDeviceId(bundleName, localId, dvid);
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

    auto errCode = proxy->ActivateOsAccount(id);
    return ConvertToAccountErrCode(errCode);
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

    auto errCode = proxy->DeactivateOsAccount(id);
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::DeactivateAllOsAccounts()
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    auto errCode = proxy->DeactivateAllOsAccounts();
    return ConvertToAccountErrCode(errCode);
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

    auto errCode = proxy->StartOsAccount(id);
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::GetOsAccountLocalIdBySerialNumber(const int64_t serialNumber, int &id)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    auto errCode = proxy->GetOsAccountLocalIdBySerialNumber(serialNumber, id);
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::GetSerialNumberByOsAccountLocalId(const int &id, int64_t &serialNumber)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    auto errCode = proxy->GetSerialNumberByOsAccountLocalId(id, serialNumber);
    return ConvertToAccountErrCode(errCode);
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
    std::set<OsAccountState> states;
    subscribeInfo.GetStates(states);
    if (states.size() > Constants::MAX_SUBSCRIBED_STATES_SIZE ||
        (osAccountSubscribeType == OsAccountState::INVALID_TYPE && states.empty())) {
        ACCOUNT_LOGE("The states is oversize or empty");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    std::lock_guard<std::mutex> lock(eventListenersMutex_);
    if (listenerManager_ == nullptr) {
        ACCOUNT_LOGI("Listenermager is nullptr");
        listenerManager_ = new (std::nothrow) OsAccountEventListener();
        if (listenerManager_ == nullptr) {
            ACCOUNT_LOGE("Memory allocation for listener failed!");
            return ERR_OSACCOUNT_KIT_SUBSCRIBE_ERROR;
        }
    }

    ErrCode result = listenerManager_->InsertRecord(subscriber);
    if (result != ERR_OK) {
        return result;
    }
    result = proxy->SubscribeOsAccount(listenerManager_->GetTotalSubscribeInfo(), listenerManager_);
    ConvertToAccountErrCode(result);
    if (result != ERR_OK) {
        listenerManager_->RemoveRecord(subscriber);
        ACCOUNT_LOGE("SubscribeOsAccount failed, errCode=%{public}d", result);
    }
    return result;
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

    std::lock_guard<std::mutex> lock(eventListenersMutex_);
    if (listenerManager_ == nullptr) {
        return ERR_OSACCOUNT_KIT_NO_SPECIFIED_SUBSCRIBER_HAS_BEEN_REGISTERED;
    }
    listenerManager_->RemoveRecord(subscriber);
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    if (listenerManager_->Size() != 0) {
        result = proxy->SubscribeOsAccount(listenerManager_->GetTotalSubscribeInfo(), listenerManager_);
        return result;
    }

    result = proxy->UnsubscribeOsAccount(listenerManager_);
    ConvertToAccountErrCode(result);
    if (result != ERR_OK) {
        listenerManager_->InsertRecord(subscriber);
        return result;
    }
    listenerManager_ = nullptr;
    return ERR_OK;
}

OS_ACCOUNT_SWITCH_MOD OsAccount::GetOsAccountSwitchMod()
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return OS_ACCOUNT_SWITCH_MOD::ERROR_MOD;
    }
    int32_t switchMod = 0;
    proxy->GetOsAccountSwitchMod(switchMod);
    return static_cast<OS_ACCOUNT_SWITCH_MOD>(switchMod);
}

ErrCode OsAccount::DumpState(const int &id, std::vector<std::string> &state)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    auto errCode = proxy->DumpState(id, state);
    return ConvertToAccountErrCode(errCode);
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
    auto errCode = proxy->IsCurrentOsAccountVerified(isVerified);
    return ConvertToAccountErrCode(errCode);
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
    auto errCode = proxy->IsOsAccountCompleted(id, isOsAccountCompleted);
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::SetCurrentOsAccountIsVerified(const bool isVerified)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    auto errCode = proxy->SetCurrentOsAccountIsVerified(isVerified);
    return ConvertToAccountErrCode(errCode);
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
    auto errCode = proxy->SetOsAccountIsVerified(id, isVerified);
    return ConvertToAccountErrCode(errCode);
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
    if ((object->IsProxyObject()) && (!object->AddDeathRecipient(deathRecipient_))) {
        ACCOUNT_LOGE("failed to add os account death recipient");
        deathRecipient_ = nullptr;
        return nullptr;
    }
    proxy_ = iface_cast<IOsAccount>(object);
    if (proxy_ == nullptr) {
        ACCOUNT_LOGE("failed to get os account proxy");
        object->RemoveDeathRecipient(deathRecipient_);
        deathRecipient_ = nullptr;
    }
    return proxy_;
}

ErrCode OsAccount::GetCreatedOsAccountNumFromDatabase(const std::string& storeID, int &createdOsAccountNum)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    auto errCode = proxy->GetCreatedOsAccountNumFromDatabase(storeID, createdOsAccountNum);
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::GetSerialNumberFromDatabase(const std::string& storeID, int64_t &serialNumber)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    auto errCode = proxy->GetSerialNumberFromDatabase(storeID, serialNumber);
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::GetMaxAllowCreateIdFromDatabase(const std::string& storeID, int &id)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    auto errCode = proxy->GetMaxAllowCreateIdFromDatabase(storeID, id);
    return ConvertToAccountErrCode(errCode);
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
    StringRawData stringRawData;
    auto errCode = proxy->GetOsAccountFromDatabase(storeID, id, stringRawData);
    if (errCode == ERR_OK && !ReadOsAccountInfo(stringRawData, osAccountInfo)) {
        ACCOUNT_LOGE("Read osAccountInfo failed, please check osAccountInfo");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::GetOsAccountListFromDatabase(const std::string& storeID, std::vector<OsAccountInfo> &osAccountList)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    StringRawData stringRawData;
    auto errCode = proxy->GetOsAccountListFromDatabase(storeID, stringRawData);
    if (errCode == ERR_OK) {
        ReadOsAccountInfoVector(stringRawData, osAccountList);
    }
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::QueryActiveOsAccountIds(std::vector<int32_t>& ids)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    std::vector<int32_t> idsVec;
    auto errCode = proxy->QueryActiveOsAccountIds(idsVec);
    if (errCode == ERR_OK) {
        ids = std::move(idsVec);
    }
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::QueryOsAccountConstraintSourceTypes(const int32_t id, const std::string &constraint,
    std::vector<ConstraintSourceTypeInfo> &constraintSourceTypeInfos)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    constraintSourceTypeInfos.clear();
    auto errCode = proxy->QueryOsAccountConstraintSourceTypes(id, constraint, constraintSourceTypeInfos);
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::SetGlobalOsAccountConstraints(const std::vector<std::string> &constraints,
    const bool enable, const int32_t enforcerId, const bool isDeviceOwner)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    auto errCode = proxy->SetGlobalOsAccountConstraints(constraints, enable, enforcerId, isDeviceOwner);
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::SetSpecificOsAccountConstraints(const std::vector<std::string> &constraints,
    const bool enable, const int32_t targetId, const int32_t enforcerId, const bool isDeviceOwner)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    auto errCode = proxy->SetSpecificOsAccountConstraints(constraints, enable, targetId, enforcerId, isDeviceOwner);
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::SubscribeOsAccountConstraints(const std::shared_ptr<OsAccountConstraintSubscriber> &subscriber)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("GetProxy failed");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return OsAccountConstraintSubscriberManager::GetInstance()->SubscribeOsAccountConstraints(subscriber, proxy);
}

ErrCode OsAccount::UnsubscribeOsAccountConstraints(const std::shared_ptr<OsAccountConstraintSubscriber> &subscriber)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        ACCOUNT_LOGE("GetProxy failed");
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    return OsAccountConstraintSubscriberManager::GetInstance()->UnsubscribeOsAccountConstraints(subscriber, proxy);
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
    auto errCode = proxy->SetDefaultActivatedOsAccount(id);
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::GetDefaultActivatedOsAccount(int32_t &id)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    auto errCode = proxy->GetDefaultActivatedOsAccount(id);
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::GetOsAccountShortName(std::string &shortName)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    auto errCode = proxy->GetOsAccountShortName(shortName);
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::GetOsAccountName(std::string &name)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    auto errCode = proxy->GetOsAccountName(name);
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::GetOsAccountNameById(int32_t id, std::string &name)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    auto errCode = proxy->GetOsAccountNameById(id, name);
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::GetOsAccountShortNameById(const int32_t id, std::string &shortName)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    auto errCode = proxy->GetOsAccountShortNameById(id, shortName);
    return ConvertToAccountErrCode(errCode);
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
    auto errCode = proxy->IsOsAccountForeground(localId, displayId, isForeground);
    return ConvertToAccountErrCode(errCode);
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
    auto errCode = proxy->GetForegroundOsAccountLocalId(displayId, localId);
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::GetForegroundOsAccounts(std::vector<ForegroundOsAccount> &accounts)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    accounts.clear();
    auto errCode = proxy->GetForegroundOsAccounts(accounts);
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::GetBackgroundOsAccountLocalIds(std::vector<int32_t> &localIds)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    localIds.clear();
    auto errCode = proxy->GetBackgroundOsAccountLocalIds(localIds);
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::SetOsAccountToBeRemoved(int32_t localId, bool toBeRemoved)
{
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    auto errCode = proxy->SetOsAccountToBeRemoved(localId, toBeRemoved);
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::GetOsAccountDomainInfo(const int32_t localId, DomainAccountInfo &domainInfo)
{
    ErrCode result = CheckLocalId(localId);
    if (result != ERR_OK) {
        return result;
    }
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    domainInfo.Clear();
    auto errCode = proxy->GetOsAccountDomainInfo(localId, domainInfo);
    return ConvertToAccountErrCode(errCode);
}

#ifdef SUPPORT_LOCK_OS_ACCOUNT
ErrCode OsAccount::PublishOsAccountLockEvent(const int32_t localId, bool isLocking)
{
    ErrCode result = CheckLocalId(localId);
    if (result != ERR_OK) {
        return result;
    }

    if (localId < Constants::START_USER_ID) {
        ACCOUNT_LOGE("Not allow to lock account id:%{public}d!", localId);
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }

    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    auto errCode = proxy->PublishOsAccountLockEvent(localId, isLocking);
    return ConvertToAccountErrCode(errCode);
}

ErrCode OsAccount::LockOsAccount(const int32_t localId)
{
    ErrCode result = CheckLocalId(localId);
    if (result != ERR_OK) {
        return result;
    }

    if (localId < Constants::START_USER_ID) {
        ACCOUNT_LOGE("Not allow to lock account id:%{public}d!", localId);
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }

    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    auto errCode = proxy->LockOsAccount(localId);
    return ConvertToAccountErrCode(errCode);
}
#endif

ErrCode OsAccount::BindDomainAccount(
    const int32_t localId, const DomainAccountInfo &domainInfo, const std::shared_ptr<DomainAccountCallback> &callback)
{
    ErrCode result = CheckLocalId(localId);
    if (result != ERR_OK) {
        return result;
    }
    if (domainInfo.domain_.empty() || domainInfo.domain_.size() > Constants::DOMAIN_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("Domain is empty or too long, len=%{public}zu.", domainInfo.domain_.size());
        NativeErrMsg() = "Invalid domainInfo.domain. "
                          "The length of the domainInfo.domain must be greater than 0 and less than or equal to 128";
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    if (domainInfo.accountName_.empty() || domainInfo.accountName_.size() > Constants::LOCAL_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("Account name is empty or too long, len=%{public}zu.", domainInfo.accountName_.size());
        NativeErrMsg() = "Invalid domainInfo.accountName. "
                          "The length of the domainInfo.accountName must be greater than 0 and less than or equal to "
                          "LOGIN_NAME_MAX";
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    if (callback == nullptr) {
        ACCOUNT_LOGE("Callback is null.");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    sptr<DomainAccountCallbackService> callbackService = sptr<DomainAccountCallbackService>::MakeSptr(callback);
    auto proxy = GetOsAccountProxy();
    if (proxy == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }
    auto errCode = proxy->BindDomainAccount(localId, domainInfo, callbackService);
    return ConvertToAccountErrCode(errCode);
}
}  // namespace AccountSA
}  // namespace OHOS
