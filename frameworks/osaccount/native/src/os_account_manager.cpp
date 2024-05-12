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
#include "os_account_manager.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "account_permission_manager.h"
#include "os_account.h"

namespace OHOS {
namespace AccountSA {

ErrCode OsAccountManager::CreateOsAccount(
    const std::string &name, const OsAccountType &type, OsAccountInfo &osAccountInfo)
{
    return OsAccount::GetInstance().CreateOsAccount(name, type, osAccountInfo);
}

ErrCode OsAccountManager::CreateOsAccount(
    const std::string &localName, const std::string &shortName, const OsAccountType &type, OsAccountInfo &osAccountInfo)
{
    return OsAccount::GetInstance().CreateOsAccount(localName, shortName, type, osAccountInfo);
}

ErrCode OsAccountManager::CreateOsAccount(const std::string& localName, const std::string& shortName,
    const OsAccountType& type, const CreateOsAccountOptions& options, OsAccountInfo& osAccountInfo)
{
    return OsAccount::GetInstance().CreateOsAccount(localName, shortName, type, osAccountInfo, options);
}

ErrCode OsAccountManager::CreateOsAccountWithFullInfo(OsAccountInfo &osAccountInfo)
{
    return OsAccount::GetInstance().CreateOsAccountWithFullInfo(osAccountInfo);
}

ErrCode OsAccountManager::UpdateOsAccountWithFullInfo(OsAccountInfo &osAccountInfo)
{
    return OsAccount::GetInstance().UpdateOsAccountWithFullInfo(osAccountInfo);
}

ErrCode OsAccountManager::CreateOsAccountForDomain(const OsAccountType &type, const DomainAccountInfo &domainInfo,
    const std::shared_ptr<DomainAccountCallback> &callback, const CreateOsAccountForDomainOptions &options)
{
    return OsAccount::GetInstance().CreateOsAccountForDomain(type, domainInfo, callback, options);
}

ErrCode OsAccountManager::RemoveOsAccount(const int id)
{
    return OsAccount::GetInstance().RemoveOsAccount(id);
}

ErrCode OsAccountManager::IsOsAccountExists(const int id, bool &isOsAccountExists)
{
    return OsAccount::GetInstance().IsOsAccountExists(id, isOsAccountExists);
}

ErrCode OsAccountManager::IsOsAccountActived(const int id, bool &isOsAccountActived)
{
    return OsAccount::GetInstance().IsOsAccountActived(id, isOsAccountActived);
}

ErrCode OsAccountManager::IsOsAccountConstraintEnable(
    const int id, const std::string &constraint, bool &isConstraintEnable)
{
    return OsAccount::GetInstance().IsOsAccountConstraintEnable(id, constraint, isConstraintEnable);
}

ErrCode OsAccountManager::CheckOsAccountConstraintEnabled(
    const int id, const std::string &constraint, bool &isEnabled)
{
    return OsAccount::GetInstance().CheckOsAccountConstraintEnabled(id, constraint, isEnabled);
}

ErrCode OsAccountManager::IsOsAccountVerified(const int id, bool &isVerified)
{
    return OsAccount::GetInstance().IsOsAccountVerified(id, isVerified);
}

ErrCode OsAccountManager::GetCreatedOsAccountsCount(unsigned int &osAccountsCount)
{
    return OsAccount::GetInstance().GetCreatedOsAccountsCount(osAccountsCount);
}

ErrCode OsAccountManager::GetOsAccountLocalIdFromProcess(int &id)
{
    return OsAccount::GetInstance().GetOsAccountLocalIdFromProcess(id);
}

ErrCode OsAccountManager::IsMainOsAccount(bool &isMainOsAccount)
{
    return OsAccount::GetInstance().IsMainOsAccount(isMainOsAccount);
}

ErrCode OsAccountManager::GetOsAccountLocalIdFromUid(const int uid, int &id)
{
    if (uid < 0) {
        ACCOUNT_LOGE("invalid uid %{public}d.", uid);
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    id = uid / UID_TRANSFORM_DIVISOR;
    return ERR_OK;
}

ErrCode OsAccountManager::GetBundleIdFromUid(const int uid, int &bundleId)
{
    ErrCode result = AccountPermissionManager::CheckSystemApp(false);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("is not system application, result = %{public}u.", result);
        return result;
    }
    if (uid < 0) {
        ACCOUNT_LOGE("invalid uid %{public}d.", uid);
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    bundleId = uid % UID_TRANSFORM_DIVISOR;
    return ERR_OK;
}

ErrCode OsAccountManager::GetOsAccountLocalIdFromDomain(const DomainAccountInfo &domainInfo, int &id)
{
    return OsAccount::GetInstance().GetOsAccountLocalIdFromDomain(domainInfo, id);
}

ErrCode OsAccountManager::QueryMaxOsAccountNumber(uint32_t &maxOsAccountNumber)
{
    return OsAccount::GetInstance().QueryMaxOsAccountNumber(maxOsAccountNumber);
}

ErrCode OsAccountManager::QueryMaxLoggedInOsAccountNumber(uint32_t &maxNum)
{
    return OsAccount::GetInstance().QueryMaxLoggedInOsAccountNumber(maxNum);
}

ErrCode OsAccountManager::GetOsAccountAllConstraints(const int id, std::vector<std::string> &constraints)
{
    return OsAccount::GetInstance().GetOsAccountAllConstraints(id, constraints);
}

ErrCode OsAccountManager::QueryAllCreatedOsAccounts(std::vector<OsAccountInfo> &osAccountInfos)
{
    return OsAccount::GetInstance().QueryAllCreatedOsAccounts(osAccountInfos);
}

ErrCode OsAccountManager::QueryCurrentOsAccount(OsAccountInfo &osAccountInfo)
{
    return OsAccount::GetInstance().QueryCurrentOsAccount(osAccountInfo);
}

ErrCode OsAccountManager::QueryOsAccountById(const int id, OsAccountInfo &osAccountInfo)
{
    return OsAccount::GetInstance().QueryOsAccountById(id, osAccountInfo);
}

ErrCode OsAccountManager::GetOsAccountTypeFromProcess(OsAccountType &type)
{
    return OsAccount::GetInstance().GetOsAccountTypeFromProcess(type);
}

ErrCode OsAccountManager::GetOsAccountType(const int id, OsAccountType& type)
{
    return OsAccount::GetInstance().GetOsAccountType(id, type);
}

ErrCode OsAccountManager::GetOsAccountProfilePhoto(const int id, std::string &photo)
{
    return OsAccount::GetInstance().GetOsAccountProfilePhoto(id, photo);
}

ErrCode OsAccountManager::IsMultiOsAccountEnable(bool &isMultiOsAccountEnable)
{
    return OsAccount::GetInstance().IsMultiOsAccountEnable(isMultiOsAccountEnable);
}

ErrCode OsAccountManager::SetOsAccountName(const int id, const std::string &localName)
{
    return OsAccount::GetInstance().SetOsAccountName(id, localName);
}

ErrCode OsAccountManager::SetOsAccountConstraints(
    const int id, const std::vector<std::string> &constraints, const bool enable)
{
    return OsAccount::GetInstance().SetOsAccountConstraints(id, constraints, enable);
}

ErrCode OsAccountManager::SetOsAccountProfilePhoto(const int id, const std::string &photo)
{
    return OsAccount::GetInstance().SetOsAccountProfilePhoto(id, photo);
}

ErrCode OsAccountManager::GetDistributedVirtualDeviceId(std::string &deviceId)
{
    return OsAccount::GetInstance().GetDistributedVirtualDeviceId(deviceId);
}

ErrCode OsAccountManager::ActivateOsAccount(const int id)
{
    return OsAccount::GetInstance().ActivateOsAccount(id);
}

ErrCode OsAccountManager::DeactivateOsAccount(const int id)
{
    return OsAccount::GetInstance().DeactivateOsAccount(id);
}

ErrCode OsAccountManager::DeactivateAllOsAccounts()
{
    return OsAccount::GetInstance().DeactivateAllOsAccounts();
}

ErrCode OsAccountManager::StartOsAccount(const int id)
{
    return OsAccount::GetInstance().StartOsAccount(id);
}

ErrCode OsAccountManager::GetOsAccountLocalIdBySerialNumber(const int64_t serialNumber, int &id)
{
    return OsAccount::GetInstance().GetOsAccountLocalIdBySerialNumber(serialNumber, id);
}

ErrCode OsAccountManager::GetSerialNumberByOsAccountLocalId(const int &id, int64_t &serialNumber)
{
    return OsAccount::GetInstance().GetSerialNumberByOsAccountLocalId(id, serialNumber);
}

ErrCode OsAccountManager::SubscribeOsAccount(const std::shared_ptr<OsAccountSubscriber> &subscriber)
{
    return OsAccount::GetInstance().SubscribeOsAccount(subscriber);
}

ErrCode OsAccountManager::UnsubscribeOsAccount(const std::shared_ptr<OsAccountSubscriber> &subscriber)
{
    return OsAccount::GetInstance().UnsubscribeOsAccount(subscriber);
}
OS_ACCOUNT_SWITCH_MOD OsAccountManager::GetOsAccountSwitchMod()
{
    return OsAccount::GetInstance().GetOsAccountSwitchMod();
}

ErrCode OsAccountManager::IsCurrentOsAccountVerified(bool &isVerified)
{
    return OsAccount::GetInstance().IsCurrentOsAccountVerified(isVerified);
}

ErrCode OsAccountManager::IsOsAccountCompleted(const int id, bool &isOsAccountCompleted)
{
    return OsAccount::GetInstance().IsOsAccountCompleted(id, isOsAccountCompleted);
}

ErrCode OsAccountManager::SetCurrentOsAccountIsVerified(const bool isVerified)
{
    return OsAccount::GetInstance().SetCurrentOsAccountIsVerified(isVerified);
}

ErrCode OsAccountManager::SetOsAccountIsVerified(const int id, const bool isVerified)
{
    return OsAccount::GetInstance().SetOsAccountIsVerified(id, isVerified);
}

ErrCode OsAccountManager::GetCreatedOsAccountNumFromDatabase(const std::string& storeID, int &createdOsAccountNum)
{
    return OsAccount::GetInstance().GetCreatedOsAccountNumFromDatabase(
        storeID, createdOsAccountNum);
}

ErrCode OsAccountManager::GetSerialNumberFromDatabase(const std::string& storeID, int64_t &serialNumber)
{
    return OsAccount::GetInstance().GetSerialNumberFromDatabase(storeID, serialNumber);
}

ErrCode OsAccountManager::GetMaxAllowCreateIdFromDatabase(const std::string& storeID, int &id)
{
    return OsAccount::GetInstance().GetMaxAllowCreateIdFromDatabase(storeID, id);
}

ErrCode OsAccountManager::GetOsAccountFromDatabase(const std::string& storeID,
                                                   const int id,
                                                   OsAccountInfo &osAccountInfo)
{
    return OsAccount::GetInstance().GetOsAccountFromDatabase(storeID, id, osAccountInfo);
}

ErrCode OsAccountManager::GetOsAccountListFromDatabase(const std::string& storeID,
                                                       std::vector<OsAccountInfo> &osAccountList)
{
    return OsAccount::GetInstance().GetOsAccountListFromDatabase(storeID, osAccountList);
}

ErrCode OsAccountManager::QueryActiveOsAccountIds(std::vector<int32_t>& ids)
{
    return OsAccount::GetInstance().QueryActiveOsAccountIds(ids);
}

ErrCode OsAccountManager::QueryOsAccountConstraintSourceTypes(const int32_t id, const std::string constraint,
    std::vector<ConstraintSourceTypeInfo> &constraintSourceTypeInfos)
{
    return OsAccount::GetInstance().
        QueryOsAccountConstraintSourceTypes(id, constraint, constraintSourceTypeInfos);
}

ErrCode OsAccountManager::SetGlobalOsAccountConstraints(const std::vector<std::string> &constraints,
    const bool enable, const int32_t enforcerId, const bool isDeviceOwner)
{
    return OsAccount::GetInstance().
        SetGlobalOsAccountConstraints(constraints, enable, enforcerId, isDeviceOwner);
}

ErrCode OsAccountManager::SetSpecificOsAccountConstraints(const std::vector<std::string> &constraints,
    const bool enable, const int32_t targetId, const int32_t enforcerId, const bool isDeviceOwner)
{
    return OsAccount::GetInstance().
        SetSpecificOsAccountConstraints(constraints, enable, targetId, enforcerId, isDeviceOwner);
}

ErrCode OsAccountManager::SetDefaultActivatedOsAccount(const int32_t id)
{
    return OsAccount::GetInstance().SetDefaultActivatedOsAccount(id);
}

ErrCode OsAccountManager::GetDefaultActivatedOsAccount(int32_t &id)
{
    return OsAccount::GetInstance().GetDefaultActivatedOsAccount(id);
}

ErrCode OsAccountManager::GetOsAccountShortName(std::string &shortName)
{
    return OsAccount::GetInstance().GetOsAccountShortName(shortName);
}

ErrCode OsAccountManager::GetOsAccountShortName(const int32_t id, std::string &shortName)
{
    return OsAccount::GetInstance().GetOsAccountShortNameById(id, shortName);
}

ErrCode OsAccountManager::GetOsAccountName(std::string &name)
{
    return OsAccount::GetInstance().GetOsAccountName(name);
}

ErrCode OsAccountManager::IsOsAccountForeground(bool &isForeground)
{
    return OsAccount::GetInstance().IsOsAccountForeground(isForeground);
}

ErrCode OsAccountManager::IsOsAccountForeground(const int32_t localId, bool &isForeground)
{
    return OsAccount::GetInstance().IsOsAccountForeground(localId, isForeground);
}

ErrCode OsAccountManager::IsOsAccountForeground(const int32_t localId, const uint64_t displayId, bool &isForeground)
{
    return OsAccount::GetInstance().IsOsAccountForeground(localId, displayId, isForeground);
}

ErrCode OsAccountManager::GetForegroundOsAccountLocalId(int32_t &localId)
{
    return OsAccount::GetInstance().GetForegroundOsAccountLocalId(localId);
}

ErrCode OsAccountManager::GetForegroundOsAccountLocalId(const uint64_t displayId, int32_t &localId)
{
    return OsAccount::GetInstance().GetForegroundOsAccountLocalId(displayId, localId);
}

ErrCode OsAccountManager::GetForegroundOsAccounts(std::vector<ForegroundOsAccount> &accounts)
{
    return OsAccount::GetInstance().GetForegroundOsAccounts(accounts);
}

ErrCode OsAccountManager::GetBackgroundOsAccountLocalIds(std::vector<int32_t> &localIds)
{
    return OsAccount::GetInstance().GetBackgroundOsAccountLocalIds(localIds);
}

ErrCode OsAccountManager::SetOsAccountToBeRemoved(int32_t localId, bool toBeRemoved)
{
    return OsAccount::GetInstance().SetOsAccountToBeRemoved(localId, toBeRemoved);
}
}  // namespace AccountSA
}  // namespace OHOS
