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

#include "account_log_wrapper.h"
#include "iinner_os_account_manager.h"
#include "ipc_skeleton.h"
#include "os_account_constants.h"

#include "os_account_manager_service.h"

namespace OHOS {
namespace AccountSA {
OsAccountManagerService::OsAccountManagerService()
{
    ACCOUNT_LOGI("OsAccountManager OsAccountManagerService START");
    innerManager_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
    permissionManagerPtr_ = DelayedSingleton<AccountPermissionManager>::GetInstance();
    bundleManagerPtr_ = DelayedSingleton<AccountBundleManager>::GetInstance();
}
OsAccountManagerService::~OsAccountManagerService()
{
    ACCOUNT_LOGI("OsAccountManager ~OsAccountManagerService START");
}

ErrCode OsAccountManagerService::CreateOsAccount(
    const std::string &name, const OsAccountType &type, OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountManager CreateOsAccount START");
    bool isMultiOsAccountEnable = false;
    innerManager_->IsMultiOsAccountEnable(isMultiOsAccountEnable);
    if (!isMultiOsAccountEnable) {
        return ERR_OS_ACCOUNT_SERVICE_MANAGER_NOT_ENABLE_MULTI_ERROR;
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
        if (result != ERR_OK) {
            ACCOUNT_LOGI("failed to verify permission for DISTRIBUTED_DATASYNC, result = %{public}d", result);
            return result;
        }
    }
    if (name.size() > Constants::LOCAL_NAME_MAX_SIZE) {
        return ERR_OS_ACCOUNT_SERVICE_MANAGER_NAME_SIZE_OVERFLOW_ERROR;
    }
    if (name.size() <= 0) {
        return ERR_OS_ACCOUNT_SERVICE_MANAGER_NAME_SIZE_EMPTY_ERROR;
    }
    bool isAllowedCreateAdmin = false;
    ErrCode errCode = innerManager_->IsAllowedCreateAdmin(isAllowedCreateAdmin);
    if (errCode != ERR_OK) {
        return errCode;
    }
    if (!isAllowedCreateAdmin && type == OsAccountType::ADMIN) {
        return ERR_OS_ACCOUNT_SERVICE_MANAGER_CREATE_OSACCOUNT_TYPE_ERROR;
    }
    return innerManager_->CreateOsAccount(name, type, osAccountInfo);
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
        if (result != ERR_OK) {
            ACCOUNT_LOGI("failed to verify permission for DISTRIBUTED_DATASYNC, result = %{public}d", result);
            return result;
        }
    }
    if (id <= Constants::START_USER_ID) {
        return ERR_OS_ACCOUNT_SERVICE_MANAGER_ID_ERROR;
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
            ACCOUNT_LOGI("failed to verify permission for DISTRIBUTED_DATASYNC, result = %{public}d", result);
            return result;
        }
    }
    if (id < Constants::START_USER_ID) {
        return ERR_OS_ACCOUNT_SERVICE_MANAGER_ID_ERROR;
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
            ACCOUNT_LOGI("failed to verify permission for DISTRIBUTED_DATASYNC, result = %{public}d", result);
            return result;
        }
    }
    if (id < Constants::START_USER_ID) {
        return ERR_OS_ACCOUNT_SERVICE_MANAGER_ID_ERROR;
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
            ACCOUNT_LOGI("failed to verify permission for DISTRIBUTED_DATASYNC, result = %{public}d", result);
            return result;
        }
    }
    if (id < Constants::START_USER_ID) {
        return ERR_OS_ACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    return innerManager_->IsOsAccountVerified(id, isVerified);
}

ErrCode OsAccountManagerService::GetCreatedOsAccountsCount(int &osAccountsCount)
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
            ACCOUNT_LOGI("failed to verify permission for DISTRIBUTED_DATASYNC, result = %{public}d", result);
            return result;
        }
    }
    return innerManager_->GetCreatedOsAccountsCount(osAccountsCount);
}

ErrCode OsAccountManagerService::GetOsAccountLocalIdFromProcess(int &id)
{
    const std::int32_t uid = IPCSkeleton::GetCallingUid();
    id = uid / Constants::UID_TRANSFORM_DIVISOR;
    if (id < Constants::START_USER_ID) {
        return ERR_OS_ACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountManagerService::GetOsAccountLocalIdFromUid(const int uid, int &id)
{
    id = uid / Constants::UID_TRANSFORM_DIVISOR;
    if (id < Constants::START_USER_ID) {
        return ERR_OS_ACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    return ERR_OK;
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
            ACCOUNT_LOGI("failed to verify permission for DISTRIBUTED_DATASYNC, result = %{public}d", result);
            return result;
        }
    }
    if (id < Constants::START_USER_ID) {
        return ERR_OS_ACCOUNT_SERVICE_MANAGER_ID_ERROR;
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
            ACCOUNT_LOGI("failed to verify permission for DISTRIBUTED_DATASYNC, result = %{public}d", result);
            return result;
        }
    }
    int id = callingUid / Constants::UID_TRANSFORM_DIVISOR;
    if (id < Constants::START_USER_ID) {
        return ERR_OS_ACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
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
        if (result != ERR_OK && errCode != ERR_OK) {
            ACCOUNT_LOGI("failed to verify permission for DISTRIBUTED_DATASYNC and "
                         "INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION, result = %{public}d",
                result);
            return result;
        }
    }
    if (id < Constants::START_USER_ID) {
        return ERR_OS_ACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    return innerManager_->QueryOsAccountById(id, osAccountInfo);
}

ErrCode OsAccountManagerService::GetOsAccountTypeFromProcess(OsAccountType &type)
{
    const std::int32_t uid = IPCSkeleton::GetCallingUid();
    int id = uid / Constants::UID_TRANSFORM_DIVISOR;
    if (id < Constants::START_USER_ID) {
        return ERR_OS_ACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
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
        if (result != ERR_OK) {
            ACCOUNT_LOGI("failed to verify permission for DISTRIBUTED_DATASYNC, result = %{public}d", result);
            return result;
        }
    }
    if (id < Constants::START_USER_ID) {
        return ERR_OS_ACCOUNT_SERVICE_MANAGER_ID_ERROR;
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
        return ERR_OS_ACCOUNT_SERVICE_MANAGER_NAME_SIZE_OVERFLOW_ERROR;
    }
    if (name.size() <= 0) {
        return ERR_OS_ACCOUNT_SERVICE_MANAGER_NAME_SIZE_EMPTY_ERROR;
    }
    if (id < Constants::START_USER_ID) {
        return ERR_OS_ACCOUNT_SERVICE_MANAGER_ID_ERROR;
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
        if (result != ERR_OK) {
            ACCOUNT_LOGI("failed to verify permission for DISTRIBUTED_DATASYNC, result = %{public}d", result);
            return result;
        }
    }
    if (id < Constants::START_USER_ID) {
        return ERR_OS_ACCOUNT_SERVICE_MANAGER_ID_ERROR;
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
            ACCOUNT_LOGI("failed to verify permission for DISTRIBUTED_DATASYNC, result = %{public}d", result);
            return result;
        }
        if (photo.size() > Constants::LOCAL_PHOTO_MAX_SIZE) {
            return ERR_OS_ACCOUNT_SERVICE_MANAGER_PHOTO_SIZE_OVERFLOW_ERROR;
        }
    }
    if (id < Constants::START_USER_ID) {
        return ERR_OS_ACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    return innerManager_->SetOsAccountProfilePhoto(id, photo);
}

ErrCode OsAccountManagerService::GetDistributedVirtualDeviceId(std::string &deviceId)
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
            callingUid, AccountPermissionManager::DISTRIBUTED_DATASYNC, bundleName);
        if (result != ERR_OK) {
            ACCOUNT_LOGI("failed to verify permission for DISTRIBUTED_DATASYNC, result = %{public}d", result);
            return result;
        }
    }
    return innerManager_->GetDistributedVirtualDeviceId(deviceId, callingUid);
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
        if (result != ERR_OK) {
            ACCOUNT_LOGI("failed to verify permission for DISTRIBUTED_DATASYNC, result = %{public}d", result);
            return result;
        }
    }
    if (id < Constants::START_USER_ID) {
        return ERR_OS_ACCOUNT_SERVICE_MANAGER_ID_ERROR;
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
            ACCOUNT_LOGI("failed to verify permission for DISTRIBUTED_DATASYNC, result = %{public}d", result);
            return result;
        }
    }
    if (id < Constants::START_USER_ID) {
        return ERR_OS_ACCOUNT_SERVICE_MANAGER_ID_ERROR;
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
            ACCOUNT_LOGI("failed to verify permission for DISTRIBUTED_DATASYNC, result = %{public}d", result);
            return result;
        }
    }
    if (id < Constants::START_USER_ID) {
        return ERR_OS_ACCOUNT_SERVICE_MANAGER_ID_ERROR;
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
        if (result != ERR_OK) {
            ACCOUNT_LOGI("failed to verify permission for DISTRIBUTED_DATASYNC, result = %{public}d", result);
            return result;
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
        if (result != ERR_OK) {
            ACCOUNT_LOGI("failed to verify permission for DISTRIBUTED_DATASYNC, result = %{public}d", result);
            return result;
        }
    }
    return innerManager_->UnsubscribeOsAccount(eventListener);
}

ErrCode OsAccountManagerService::GetOsAccountLocalIdBySerialNumber(const int64_t serialNumber, int &id)
{
    ACCOUNT_LOGI("enter");
    if (serialNumber < Constants::CARRY_NUM * Constants::SERIAL_NUMBER_NUM_START_FOR_ADMIN + Constants::START_USER_ID) {
        return ERR_OS_ACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    return innerManager_->GetOsAccountLocalIdBySerialNumber(serialNumber, id);
}

ErrCode OsAccountManagerService::GetSerialNumberByOsAccountLocalId(const int &id, int64_t &serialNumber)
{
    ACCOUNT_LOGI("enter");
    if (id < Constants::START_USER_ID) {
        return ERR_OS_ACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
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
            ACCOUNT_LOGI("failed to verify permission for DISTRIBUTED_DATASYNC, result = %{public}d", result);
            return result;
        }
    }
    int id = callingUid / Constants::UID_TRANSFORM_DIVISOR;
    if (id < Constants::START_USER_ID) {
        return ERR_OS_ACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
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
            ACCOUNT_LOGI("failed to verify permission for DISTRIBUTED_DATASYNC, result = %{public}d", result);
            return result;
        }
    }
    if (id < Constants::START_USER_ID) {
        return ERR_OS_ACCOUNT_SERVICE_MANAGER_ID_ERROR;
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
            ACCOUNT_LOGI("failed to verify permission for DISTRIBUTED_DATASYNC, result = %{public}d", result);
            return result;
        }
    }
    int id = callingUid / Constants::UID_TRANSFORM_DIVISOR;
    if (id < Constants::START_USER_ID) {
        return ERR_OS_ACCOUNT_SERVICE_MANAGER_ID_ERROR;
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
            ACCOUNT_LOGI("failed to verify permission for DISTRIBUTED_DATASYNC, result = %{public}d", result);
            return result;
        }
    }
    if (id < Constants::START_USER_ID) {
        return ERR_OS_ACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    return innerManager_->SetOsAccountIsVerified(id, isVerified);
}
}  // namespace AccountSA
}  // namespace OHOS
