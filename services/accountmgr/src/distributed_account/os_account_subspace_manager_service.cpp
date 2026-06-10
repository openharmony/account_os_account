/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "os_account_subspace_manager_service.h"
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_permission_manager.h"
#include "iinner_os_account_manager.h"
#include "ohos_account_manager.h"
#include "os_account_constants.h"

namespace OHOS {
namespace AccountSA {
namespace {
ErrCode CheckSubspacePermission()
{
    ErrCode ret = AccountPermissionManager::CheckSystemApp();
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Caller is not system app, ret=%{public}d", ret);
        return ret;
    }
    ErrCode permRet = AccountPermissionManager::VerifyPermission("ohos.permission.MANAGE_LOCAL_ACCOUNTS");
    if (permRet != ERR_OK) {
        ACCOUNT_LOGE("Permission check failed: MANAGE_LOCAL_ACCOUNTS, ret=%{public}d", permRet);
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    return ERR_OK;
}
}  // namespace

int32_t OsAccountSubProfileManagerService::CreateOsAccountSubProfile(
    int32_t osAccountId, OsAccountSubspaceResult &subspaceResult)
{
    ErrCode permRet = CheckSubspacePermission();
    if (permRet != ERR_OK) {
        return permRet;
    }
    ErrCode restrictedRet = IInnerOsAccountManager::GetInstance().CheckLocalIdRestricted(osAccountId);
    if (restrictedRet != ERR_OK) {
        return restrictedRet;
    }
    OsAccountInfo osAccountInfo;
    ErrCode ret = IInnerOsAccountManager::GetInstance().GetOsAccountInfoById(osAccountId, osAccountInfo);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("OsAccount not exist, osAccountId=%{public}d, ret=%{public}d", osAccountId, ret);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    ret = OhosAccountManager::GetInstance().CreateOsAccountSubspace(
        osAccountId, subspaceResult);
    return ret;
}

int32_t OsAccountSubProfileManagerService::DeleteOsAccountSubProfile(
    int32_t osAccountId, int32_t subspaceId)
{
    ErrCode permRet = CheckSubspacePermission();
    if (permRet != ERR_OK) {
        return permRet;
    }
    // Restricted accounts (e.g. ADMIN) cannot create subspaces, so there are no
    // subspaces to delete under them. SUBSPACE_NOT_FOUND is the correct response —
    // SUBSPACE_RESTRICTED is reserved for attempts to delete the index-0 subspace.
    ErrCode restrictedRet = IInnerOsAccountManager::GetInstance().CheckLocalIdRestricted(osAccountId);
    if (restrictedRet != ERR_OK) {
        return ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND;
    }
    if (subspaceId / Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER != osAccountId) {
        ACCOUNT_LOGE("subspaceId %{public}d does not belong to osAccountId %{public}d",
            subspaceId, osAccountId);
        return ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND;
    }
    if (subspaceId % Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER == 0) {
        ACCOUNT_LOGE("Cannot delete the primary subspace (index 0)");
        return ERR_OS_ACCOUNT_SUBSPACE_RESTRICTED;
    }
    ErrCode ret = OhosAccountManager::GetInstance().DeleteOsAccountSubspace(
        osAccountId, subspaceId);
    return ret;
}

int32_t OsAccountSubProfileManagerService::SwitchOsAccountSubProfile(
    int32_t osAccountId, int32_t subspaceId)
{
    ErrCode permRet = CheckSubspacePermission();
    if (permRet != ERR_OK) {
        return permRet;
    }
    // Restricted accounts (e.g. ADMIN) cannot create subspaces, so there are no
    // subspaces to switch to. SUBSPACE_NOT_FOUND is the correct response.
    // ERR_OS_ACCOUNT_SUBSPACE_RESTRICTED was designed for switch but is not yet
    // returned from any code path.
    ErrCode restrictedRet = IInnerOsAccountManager::GetInstance().CheckLocalIdRestricted(osAccountId);
    if (restrictedRet != ERR_OK) {
        return ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND;
    }
    if (subspaceId / Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER != osAccountId) {
        ACCOUNT_LOGE("subspaceId %{public}d does not belong to osAccountId %{public}d",
            subspaceId, osAccountId);
        return ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND;
    }
    int32_t fromSubspaceId = 0;
    ErrCode ret = OhosAccountManager::GetInstance().SwitchOsAccountSubspace(
        osAccountId, subspaceId, fromSubspaceId);
    return ret;
}
}  // namespace AccountSA
}  // namespace OHOS
#endif  // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE