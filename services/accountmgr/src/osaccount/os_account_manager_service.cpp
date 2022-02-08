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
#include "os_account_manager_service.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "iinner_os_account_manager.h"
#include "ipc_skeleton.h"
#include "os_account_constants.h"

namespace OHOS {
namespace AccountSA {
namespace {
const std::string DUMP_TAB_CHARACTER = "\t";
const std::map<OsAccountType, std::string> DUMP_TYPE_MAP = {
    {OsAccountType::ADMIN, "admin"},
    {OsAccountType::NORMAL, "normal"},
    {OsAccountType::GUEST, "guest"},
};
}  // namespace

OsAccountManagerService::OsAccountManagerService()
{
    innerManager_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
    permissionManagerPtr_ = DelayedSingleton<AccountPermissionManager>::GetInstance();
    bundleManagerPtr_ = DelayedSingleton<AccountBundleManager>::GetInstance();
}
OsAccountManagerService::~OsAccountManagerService()
{}

ErrCode OsAccountManagerService::CreateOsAccount(
    const std::string &name, const OsAccountType &type, OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountManager CreateOsAccount START");
    bool isMultiOsAccountEnable = false;
    innerManager_->IsMultiOsAccountEnable(isMultiOsAccountEnable);
    if (!isMultiOsAccountEnable) {
        return ERR_OSACCOUNT_SERVICE_MANAGER_NOT_ENABLE_MULTI_ERROR;
    }
    auto callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid >= Constants::APP_UID_START) {
        std::string bundleName;
        ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get bundle name");
            return result;
        }

        result = permissionManagerPtr_->VerifyPermission(
            callingUid, AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, bundleName);
        if (result != ERR_OK || !permissionManagerPtr_->IsSystemUid(callingUid)) {
            ACCOUNT_LOGE("failed to verify permission for MANAGE_LOCAL_ACCOUNTS,or not system app error");
            return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
        }
    }
    if (name.size() > Constants::LOCAL_NAME_MAX_SIZE) {
        return ERR_OSACCOUNT_SERVICE_MANAGER_NAME_SIZE_OVERFLOW_ERROR;
    }
    if (name.size() <= 0) {
        return ERR_OSACCOUNT_SERVICE_MANAGER_NAME_SIZE_EMPTY_ERROR;
    }
    bool isAllowedCreateAdmin = false;
    ErrCode errCode = innerManager_->IsAllowedCreateAdmin(isAllowedCreateAdmin);
    if (errCode != ERR_OK) {
        return errCode;
    }
    if (!isAllowedCreateAdmin && type == OsAccountType::ADMIN) {
        return ERR_OSACCOUNT_SERVICE_MANAGER_CREATE_OSACCOUNT_TYPE_ERROR;
    }
    return innerManager_->CreateOsAccount(name, type, osAccountInfo);
}

ErrCode OsAccountManagerService::CreateOsAccountForDomain(
    const OsAccountType &type, const DomainAccountInfo &domainInfo, OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountManager CreateOsAccountForDomain START");
    bool isMultiOsAccountEnable = false;
    innerManager_->IsMultiOsAccountEnable(isMultiOsAccountEnable);
    if (!isMultiOsAccountEnable) {
        return ERR_OSACCOUNT_SERVICE_MANAGER_NOT_ENABLE_MULTI_ERROR;
    }
    auto callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid >= Constants::APP_UID_START) {
        std::string bundleName;
        ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get bundle name");
            return result;
        }

        result = permissionManagerPtr_->VerifyPermission(
            callingUid, AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, bundleName);
        if (result != ERR_OK || !permissionManagerPtr_->IsSystemUid(callingUid)) {
            ACCOUNT_LOGI("failed to verify permission for MANAGE_LOCAL_ACCOUNTS,or not system app error");
            return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
        }
    }
    if (domainInfo.accountName_.empty() || domainInfo.domain_.empty()) {
        return ERR_OSACCOUNT_SERVICE_MANAGER_NAME_SIZE_EMPTY_ERROR;
    }
    if (domainInfo.accountName_.size() > Constants::DOMAIN_ACCOUNT_NAME_MAX_SIZE ||
        domainInfo.domain_.size() > Constants::DOMAIN_NAME_MAX_SIZE) {
        return ERR_OSACCOUNT_SERVICE_MANAGER_NAME_SIZE_OVERFLOW_ERROR;
    }
    bool isAllowedCreateAdmin = false;
    ErrCode errCode = innerManager_->IsAllowedCreateAdmin(isAllowedCreateAdmin);
    if (errCode != ERR_OK) {
        return errCode;
    }
    if (!isAllowedCreateAdmin && type == OsAccountType::ADMIN) {
        return ERR_OSACCOUNT_SERVICE_MANAGER_CREATE_OSACCOUNT_TYPE_ERROR;
    }
    return innerManager_->CreateOsAccountForDomain(type, domainInfo, osAccountInfo);
}

ErrCode OsAccountManagerService::RemoveOsAccount(const int id)
{
    auto callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid >= Constants::APP_UID_START) {
        std::string bundleName;

        ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get bundle name");
            return result;
        }

        result = permissionManagerPtr_->VerifyPermission(
            callingUid, AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, bundleName);
        if (result != ERR_OK || !permissionManagerPtr_->IsSystemUid(callingUid)) {
            ACCOUNT_LOGI("failed to verify permission for MANAGE_LOCAL_ACCOUNTS,or not system app error");
            return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
        }
    }
    if (id <= Constants::START_USER_ID) {
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    return innerManager_->RemoveOsAccount(id);
}

ErrCode OsAccountManagerService::IsOsAccountExists(const int id, bool &isOsAccountExists)
{
    ACCOUNT_LOGI("OsAccountManager IsOsAccountExists START");
    return innerManager_->IsOsAccountExists(id, isOsAccountExists);
}

ErrCode OsAccountManagerService::IsOsAccountActived(const int id, bool &isOsAccountActived)
{
    auto callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid >= Constants::APP_UID_START) {
        std::string bundleName;

        ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get bundle name");
            return result;
        }

        result = permissionManagerPtr_->VerifyPermission(
            callingUid, AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, bundleName);
        ErrCode errCode = permissionManagerPtr_->VerifyPermission(
            callingUid, AccountPermissionManager::INTERACT_ACROSS_LOCAL_ACCOUNTS, bundleName);
        if (result != ERR_OK && errCode != ERR_OK) {
            ACCOUNT_LOGI("failed to verify permission for MANAGE_LOCAL_ACCOUNTS or INTERACT_ACROSS_LOCAL_ACCOUNTS");
            return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
        }
    }
    return innerManager_->IsOsAccountActived(id, isOsAccountActived);
}

ErrCode OsAccountManagerService::IsOsAccountConstraintEnable(
    const int id, const std::string &constraint, bool &isConstraintEnable)
{
    auto callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid >= Constants::APP_UID_START) {
        std::string bundleName;

        ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get bundle name");
            return result;
        }

        result = permissionManagerPtr_->VerifyPermission(
            callingUid, AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGI("failed to verify permission for MANAGE_LOCAL_ACCOUNTS");
            return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
        }
    }
    return innerManager_->IsOsAccountConstraintEnable(id, constraint, isConstraintEnable);
}

ErrCode OsAccountManagerService::IsOsAccountVerified(const int id, bool &isVerified)
{
    auto callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid >= Constants::APP_UID_START) {
        std::string bundleName;

        ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get bundle name");
            return result;
        }

        result = permissionManagerPtr_->VerifyPermission(
            callingUid, AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, bundleName);
        ErrCode errCode = permissionManagerPtr_->VerifyPermission(
            callingUid, AccountPermissionManager::INTERACT_ACROSS_LOCAL_ACCOUNTS, bundleName);
        if (result != ERR_OK && errCode != ERR_OK) {
            ACCOUNT_LOGI("failed to verify permission for INTERACT_ACROSS_LOCAL_ACCOUNTS or MANAGE_LOCAL_ACCOUNTS");
            return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
        }
    }
    return innerManager_->IsOsAccountVerified(id, isVerified);
}

ErrCode OsAccountManagerService::GetCreatedOsAccountsCount(unsigned int &osAccountsCount)
{
    auto callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid >= Constants::APP_UID_START) {
        std::string bundleName;

        ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get bundle name");
            return result;
        }

        result = permissionManagerPtr_->VerifyPermission(
            callingUid, AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGI("failed to verify permission for MANAGE_LOCAL_ACCOUNTS");
            return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
        }
    }
    return innerManager_->GetCreatedOsAccountsCount(osAccountsCount);
}

ErrCode OsAccountManagerService::GetOsAccountLocalIdFromProcess(int &id)
{
    const std::int32_t uid = IPCSkeleton::GetCallingUid();
    id = uid / UID_TRANSFORM_DIVISOR;
    return ERR_OK;
}

ErrCode OsAccountManagerService::GetOsAccountLocalIdFromDomain(const DomainAccountInfo &domainInfo, int &id)
{
    return innerManager_->GetOsAccountLocalIdFromDomain(domainInfo, id);
}

ErrCode OsAccountManagerService::QueryMaxOsAccountNumber(int &maxOsAccountNumber)
{
    return innerManager_->QueryMaxOsAccountNumber(maxOsAccountNumber);
}

ErrCode OsAccountManagerService::GetOsAccountAllConstraints(const int id, std::vector<std::string> &constraints)
{
    auto callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid >= Constants::APP_UID_START) {
        std::string bundleName;

        ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get bundle name");
            return result;
        }

        result = permissionManagerPtr_->VerifyPermission(
            callingUid, AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGI("failed to verify permission for MANAGE_LOCAL_ACCOUNTS");
            return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
        }
    }
    return innerManager_->GetOsAccountAllConstraints(id, constraints);
}

ErrCode OsAccountManagerService::QueryAllCreatedOsAccounts(std::vector<OsAccountInfo> &osAccountInfos)
{
    return innerManager_->QueryAllCreatedOsAccounts(osAccountInfos);
}

ErrCode OsAccountManagerService::QueryCurrentOsAccount(OsAccountInfo &osAccountInfo)
{
    auto callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid >= Constants::APP_UID_START) {
        std::string bundleName;

        ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get bundle name");
            return result;
        }

        result = permissionManagerPtr_->VerifyPermission(
            callingUid, AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGI("failed to verify permission for MANAGE_LOCAL_ACCOUNTS");
            return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
        }
    }
    int id = callingUid / UID_TRANSFORM_DIVISOR;
    return innerManager_->QueryOsAccountById(id, osAccountInfo);
}

ErrCode OsAccountManagerService::QueryOsAccountById(const int id, OsAccountInfo &osAccountInfo)
{
    auto callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid >= Constants::APP_UID_START) {
        std::string bundleName;

        ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get bundle name");
            return result;
        }

        result = permissionManagerPtr_->VerifyPermission(
            callingUid, AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, bundleName);
        ErrCode errCode = permissionManagerPtr_->VerifyPermission(
            callingUid, AccountPermissionManager::INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION, bundleName);
        if ((result != ERR_OK && errCode != ERR_OK) || !permissionManagerPtr_->IsSystemUid(callingUid)) {
            ACCOUNT_LOGI("failed to verify permission for MANAGE_LOCAL_ACCOUNTS or "
                         "INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION,or not system app error");
            return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
        }
    }
    return innerManager_->QueryOsAccountById(id, osAccountInfo);
}

ErrCode OsAccountManagerService::GetOsAccountTypeFromProcess(OsAccountType &type)
{
    const std::int32_t uid = IPCSkeleton::GetCallingUid();
    int id = uid / UID_TRANSFORM_DIVISOR;
    return innerManager_->GetOsAccountType(id, type);
}

ErrCode OsAccountManagerService::GetOsAccountProfilePhoto(const int id, std::string &photo)
{
    auto callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid >= Constants::APP_UID_START) {
        std::string bundleName;

        ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get bundle name");
            return result;
        }

        result = permissionManagerPtr_->VerifyPermission(
            callingUid, AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, bundleName);
        if (result != ERR_OK || !permissionManagerPtr_->IsSystemUid(callingUid)) {
            ACCOUNT_LOGI("failed to verify permission for MANAGE_LOCAL_ACCOUNTS,or not system app error");
            return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
        }
    }
    return innerManager_->GetOsAccountProfilePhoto(id, photo);
}

ErrCode OsAccountManagerService::IsMultiOsAccountEnable(bool &isMultiOsAccountEnable)
{
    return innerManager_->IsMultiOsAccountEnable(isMultiOsAccountEnable);
}

ErrCode OsAccountManagerService::SetOsAccountName(const int id, const std::string &name)
{
    if (name.size() > Constants::LOCAL_NAME_MAX_SIZE) {
        return ERR_OSACCOUNT_SERVICE_MANAGER_NAME_SIZE_OVERFLOW_ERROR;
    }
    if (name.size() <= 0) {
        return ERR_OSACCOUNT_SERVICE_MANAGER_NAME_SIZE_EMPTY_ERROR;
    }
    if (id < Constants::START_USER_ID) {
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    return innerManager_->SetOsAccountName(id, name);
}

ErrCode OsAccountManagerService::SetOsAccountConstraints(
    const int id, const std::vector<std::string> &constraints, const bool enable)
{
    auto callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid >= Constants::APP_UID_START) {
        std::string bundleName;

        ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get bundle name");
            return result;
        }

        result = permissionManagerPtr_->VerifyPermission(
            callingUid, AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, bundleName);
        if (result != ERR_OK || !permissionManagerPtr_->IsSystemUid(callingUid)) {
            ACCOUNT_LOGI("failed to verify permission for MANAGE_LOCAL_ACCOUNTS,or not system app error");
            return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
        }
    }
    if (id < Constants::START_USER_ID) {
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    return innerManager_->SetOsAccountConstraints(id, constraints, enable);
}

ErrCode OsAccountManagerService::SetOsAccountProfilePhoto(const int id, const std::string &photo)
{
    auto callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid >= Constants::APP_UID_START) {
        std::string bundleName;

        ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get bundle name");
            return result;
        }

        result = permissionManagerPtr_->VerifyPermission(
            callingUid, AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGI("failed to verify permission for MANAGE_LOCAL_ACCOUNTS");
            return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
        }
        if (photo.size() > Constants::LOCAL_PHOTO_MAX_SIZE) {
            return ERR_OSACCOUNT_SERVICE_MANAGER_PHOTO_SIZE_OVERFLOW_ERROR;
        }
    }
    if (id < Constants::START_USER_ID) {
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    return innerManager_->SetOsAccountProfilePhoto(id, photo);
}

ErrCode OsAccountManagerService::ActivateOsAccount(const int id)
{
    auto callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid >= Constants::APP_UID_START) {
        std::string bundleName;

        ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get bundle name");
            return result;
        }

        result = permissionManagerPtr_->VerifyPermission(
            callingUid, AccountPermissionManager::INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION, bundleName);
        if (result != ERR_OK || !permissionManagerPtr_->IsSystemUid(callingUid)) {
            ACCOUNT_LOGI(
                "failed to verify permission for INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION,or not system app error");
            return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
        }
    }
    if (id < Constants::START_USER_ID) {
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    return innerManager_->ActivateOsAccount(id);
}

ErrCode OsAccountManagerService::StartOsAccount(const int id)
{
    auto callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid >= Constants::APP_UID_START) {
        std::string bundleName;

        ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get bundle name");
            return result;
        }

        result = permissionManagerPtr_->VerifyPermission(
            callingUid, AccountPermissionManager::INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGI("failed to verify permission for INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION");
            return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
        }
    }
    if (id < Constants::START_USER_ID) {
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    return innerManager_->StartOsAccount(id);
}

ErrCode OsAccountManagerService::StopOsAccount(const int id)
{
    auto callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid >= Constants::APP_UID_START) {
        std::string bundleName;

        ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get bundle name");
            return result;
        }

        result = permissionManagerPtr_->VerifyPermission(
            callingUid, AccountPermissionManager::INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGI("failed to verify permission for INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION");
            return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
        }
    }
    if (id < Constants::START_USER_ID) {
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    return innerManager_->StopOsAccount(id);
}

ErrCode OsAccountManagerService::SubscribeOsAccount(
    const OsAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener)
{
    ACCOUNT_LOGI("enter");
    auto callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid >= Constants::APP_UID_START) {
        std::string bundleName;

        ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get bundle name");
            return result;
        }

        result = permissionManagerPtr_->VerifyPermission(
            callingUid, AccountPermissionManager::INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION, bundleName);
        if (result != ERR_OK || !permissionManagerPtr_->IsSystemUid(callingUid)) {
            ACCOUNT_LOGI("failed to verify permission for INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION, or not system app");
            return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
        }
    }
    return innerManager_->SubscribeOsAccount(subscribeInfo, eventListener);
}

ErrCode OsAccountManagerService::UnsubscribeOsAccount(const sptr<IRemoteObject> &eventListener)
{
    ACCOUNT_LOGI("enter");
    auto callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid >= Constants::APP_UID_START) {
        std::string bundleName;

        ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get bundle name");
            return result;
        }

        result = permissionManagerPtr_->VerifyPermission(
            callingUid, AccountPermissionManager::INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION, bundleName);
        if (result != ERR_OK || !permissionManagerPtr_->IsSystemUid(callingUid)) {
            ACCOUNT_LOGI(
                "failed to verify permission for INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION, or not system app ");
            return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
        }
    }
    return innerManager_->UnsubscribeOsAccount(eventListener);
}

ErrCode OsAccountManagerService::GetOsAccountLocalIdBySerialNumber(const int64_t serialNumber, int &id)
{
    ACCOUNT_LOGI("enter");
    ErrCode errCode = innerManager_->GetOsAccountLocalIdBySerialNumber(serialNumber, id);
    if (errCode != ERR_OK) {
        return errCode;
    }
    return ERR_OK;
}

ErrCode OsAccountManagerService::GetSerialNumberByOsAccountLocalId(const int &id, int64_t &serialNumber)
{
    ACCOUNT_LOGI("enter");
    return innerManager_->GetSerialNumberByOsAccountLocalId(id, serialNumber);
}
OS_ACCOUNT_SWITCH_MOD OsAccountManagerService::GetOsAccountSwitchMod()
{
    ACCOUNT_LOGI("enter");

    return innerManager_->GetOsAccountSwitchMod();
}

ErrCode OsAccountManagerService::IsCurrentOsAccountVerified(bool &isVerified)
{
    auto callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid >= Constants::APP_UID_START) {
        std::string bundleName;

        ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get bundle name");
            return result;
        }

        result = permissionManagerPtr_->VerifyPermission(
            callingUid, AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, bundleName);
        ErrCode errCode = permissionManagerPtr_->VerifyPermission(
            callingUid, AccountPermissionManager::INTERACT_ACROSS_LOCAL_ACCOUNTS, bundleName);
        if (result != ERR_OK && errCode != ERR_OK) {
            ACCOUNT_LOGI("failed to verify permission for INTERACT_ACROSS_LOCAL_ACCOUNTS or MANAGE_LOCAL_ACCOUNTS");
            return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
        }
    }
    int id = callingUid / UID_TRANSFORM_DIVISOR;
    return innerManager_->IsOsAccountVerified(id, isVerified);
}

ErrCode OsAccountManagerService::IsOsAccountCompleted(const int id, bool &isOsAccountCompleted)
{
    auto callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid >= Constants::APP_UID_START) {
        std::string bundleName;

        ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get bundle name");
            return result;
        }

        result = permissionManagerPtr_->VerifyPermission(
            callingUid, AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, bundleName);
        ErrCode errCode = permissionManagerPtr_->VerifyPermission(
            callingUid, AccountPermissionManager::INTERACT_ACROSS_LOCAL_ACCOUNTS, bundleName);
        if (result != ERR_OK && errCode != ERR_OK) {
            ACCOUNT_LOGI("failed to verify permission for INTERACT_ACROSS_LOCAL_ACCOUNTS or MANAGE_LOCAL_ACCOUNTS");
            return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
        }
    }
    return innerManager_->IsOsAccountCompleted(id, isOsAccountCompleted);
}

ErrCode OsAccountManagerService::SetCurrentOsAccountIsVerified(const bool isVerified)
{
    auto callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid >= Constants::APP_UID_START) {
        std::string bundleName;

        ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get bundle name");
            return result;
        }

        result = permissionManagerPtr_->VerifyPermission(
            callingUid, AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGI("failed to verify permission for MANAGE_LOCAL_ACCOUNTS");
            return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
        }
    }
    int id = callingUid / UID_TRANSFORM_DIVISOR;
    if (id < Constants::START_USER_ID) {
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    return innerManager_->SetOsAccountIsVerified(id, isVerified);
}

ErrCode OsAccountManagerService::SetOsAccountIsVerified(const int id, const bool isVerified)
{
    auto callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid >= Constants::APP_UID_START) {
        std::string bundleName;

        ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get bundle name");
            return result;
        }

        result = permissionManagerPtr_->VerifyPermission(
            callingUid, AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGI("failed to verify permission for MANAGE_LOCAL_ACCOUNTS");
            return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
        }
    }
    if (id < Constants::START_USER_ID) {
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    return innerManager_->SetOsAccountIsVerified(id, isVerified);
}

ErrCode OsAccountManagerService::DumpState(const int &id, std::vector<std::string> &state)
{
    ACCOUNT_LOGI("enter");

    state.clear();

    ErrCode result = ERR_OK;
    std::vector<OsAccountInfo> osAccountInfos;

    if (id == -1) {
        result = innerManager_->QueryAllCreatedOsAccounts(osAccountInfos);
        if (result != ERR_OK) {
            return result;
        }
    } else {
        OsAccountInfo osAccountInfo;
        result = innerManager_->QueryOsAccountById(id, osAccountInfo);
        if (result != ERR_OK) {
            return result;
        }

        osAccountInfos.emplace_back(osAccountInfo);
    }

    return DumpStateByAccounts(osAccountInfos, state);
}

ErrCode OsAccountManagerService::GetCreatedOsAccountNumFromDatabase(const std::string& storeID,
    int &createdOsAccountNum)
{
    auto callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid >= Constants::APP_UID_START) {
        std::string bundleName;

        ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get bundle name");
            return result;
        }

        result = permissionManagerPtr_->VerifyPermission(
            callingUid, AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGI("failed to verify permission for MANAGE_LOCAL_ACCOUNTS");
            return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
        }
    }
    return innerManager_->GetCreatedOsAccountNumFromDatabase(storeID, createdOsAccountNum);
}

void OsAccountManagerService::CreateBasicAccounts()
{
    ACCOUNT_LOGE("CreateBasicAccounts enter!");
    innerManager_->Init();
    ACCOUNT_LOGE("CreateBasicAccounts exit!");
}

ErrCode OsAccountManagerService::GetSerialNumberFromDatabase(const std::string& storeID,
    int64_t &serialNumber)
{
    return innerManager_->GetSerialNumberFromDatabase(storeID, serialNumber);
}

ErrCode OsAccountManagerService::GetMaxAllowCreateIdFromDatabase(const std::string& storeID, int &id)
{
    auto callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid >= Constants::APP_UID_START) {
        std::string bundleName;

        ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get bundle name");
            return result;
        }

        result = permissionManagerPtr_->VerifyPermission(
            callingUid, AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGI("failed to verify permission for MANAGE_LOCAL_ACCOUNTS");
            return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
        }
    }
    return innerManager_->GetMaxAllowCreateIdFromDatabase(storeID, id);
}

ErrCode OsAccountManagerService::GetOsAccountFromDatabase(const std::string& storeID,
    const int id, OsAccountInfo &osAccountInfo)
{
    auto callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid >= Constants::APP_UID_START) {
        std::string bundleName;

        ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get bundle name");
            return result;
        }

        result = permissionManagerPtr_->VerifyPermission(
            callingUid, AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGI("failed to verify permission for MANAGE_LOCAL_ACCOUNTS");
            return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
        }
    }
    return innerManager_->GetOsAccountFromDatabase(storeID, id, osAccountInfo);
}

ErrCode OsAccountManagerService::GetOsAccountListFromDatabase(const std::string& storeID,
    std::vector<OsAccountInfo> &osAccountList)
{
    auto callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid >= Constants::APP_UID_START) {
        std::string bundleName;

        ErrCode result = bundleManagerPtr_->GetBundleName(callingUid, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to get bundle name");
            return result;
        }

        result = permissionManagerPtr_->VerifyPermission(
            callingUid, AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGI("failed to verify permission for MANAGE_LOCAL_ACCOUNTS");
            return ERR_OSACCOUNT_SERVICE_PERMISSION_DENIED;
        }
    }
    return innerManager_->GetOsAccountListFromDatabase(storeID, osAccountList);
}

ErrCode OsAccountManagerService::DumpStateByAccounts(
    const std::vector<OsAccountInfo> &osAccountInfos, std::vector<std::string> &state)
{
    ACCOUNT_LOGI("enter");

    for (auto osAccountInfo : osAccountInfos) {
        std::string info = "";

        std::string localId = std::to_string(osAccountInfo.GetLocalId());
        state.emplace_back("ID: " + localId);

        std::string localName = osAccountInfo.GetLocalName();
        state.emplace_back(DUMP_TAB_CHARACTER + "Name: " + localName);

        std::string type = "";
        auto it = DUMP_TYPE_MAP.find(osAccountInfo.GetType());
        if (it != DUMP_TYPE_MAP.end()) {
            type = it->second;
        } else {
            type = "unknown";
        }
        state.emplace_back(DUMP_TAB_CHARACTER + "Type: " + type);

        std::string status = "";
        if (osAccountInfo.GetIsActived()) {
            status = "active";
        } else {
            status = "inactive";
        }
        state.emplace_back(DUMP_TAB_CHARACTER + "Status: " + status);

        state.emplace_back(DUMP_TAB_CHARACTER + "Constraints:");
        auto constraints = osAccountInfo.GetConstraints();
        for (auto constraint : constraints) {
            state.emplace_back(DUMP_TAB_CHARACTER + DUMP_TAB_CHARACTER + constraint);
        }

        std::string verifiedStatus = "";
        if (osAccountInfo.GetIsVerified()) {
            verifiedStatus = "true";
        } else {
            verifiedStatus = "false";
        }
        state.emplace_back(DUMP_TAB_CHARACTER + "Verified: " + verifiedStatus);

        int64_t serialNumber = osAccountInfo.GetSerialNumber();
        state.emplace_back(DUMP_TAB_CHARACTER + "Serial Number: " + std::to_string(serialNumber));

        std::string createCompletedStatus = "";
        if (osAccountInfo.GetIsCreateCompleted()) {
            createCompletedStatus = "true";
        } else {
            createCompletedStatus = "false";
        }
        state.emplace_back(DUMP_TAB_CHARACTER + "Create Completed: " + createCompletedStatus);

        state.emplace_back("\n");
    }

    return ERR_OK;
}

ErrCode OsAccountManagerService::QueryActiveOsAccountIds(std::vector<int>& ids)
{
    return innerManager_->QueryActiveOsAccountIds(ids);
}
}  // namespace AccountSA
}  // namespace OHOS
