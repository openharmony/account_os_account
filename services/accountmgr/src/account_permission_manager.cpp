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

#include "account_bundle_manager.h"
#include "account_log_wrapper.h"
#include "ipc_skeleton.h"
#include "ohos_account_kits.h"
#include "permission/permission_kit.h"

#include "account_permission_manager.h"

using namespace OHOS::Security::Permission;

namespace OHOS {
namespace AccountSA {
const std::string AccountPermissionManager::DISTRIBUTED_DATASYNC = "ohos.permission.DISTRIBUTED_DATASYNC";
const std::string AccountPermissionManager::GET_ACCOUNTS_PRIVILEGED = "ohos.permission.GET_ACCOUNTS_PRIVILEGED";
const std::string AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS = "ohos.permission.MANAGE_LOCAL_ACCOUNTS";
const std::string AccountPermissionManager::INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION =
    "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION";
const std::string AccountPermissionManager::INTERACT_ACROSS_LOCAL_ACCOUNTS =
    "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS";
AccountPermissionManager::AccountPermissionManager()
{
    ACCOUNT_LOGI("enter");
}

AccountPermissionManager::~AccountPermissionManager()
{
    ACCOUNT_LOGI("enter");
}

ErrCode AccountPermissionManager::VerifyPermission(
    const uid_t &uid, const std::string &permissionName, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("permissionName = %{public}s", permissionName.c_str());
    ACCOUNT_LOGI("bundleName = %{public}s", bundleName.c_str());

    if (permissionName.size() == 0) {
        ACCOUNT_LOGE("permissionName is empty");
        return ERR_APPACCOUNT_SERVICE_PERMISSION_NAME_IS_EMPTY;
    }

    if (bundleName.size() == 0) {
        ACCOUNT_LOGE("bundleName is empty");
        return ERR_APPACCOUNT_SERVICE_BUNDLE_NAME_IS_EMPTY;
    }

    std::int32_t uidToVerify = uid;

    auto deviceAccountId = OhosAccountKits::GetInstance().GetDeviceAccountIdByUID(uidToVerify);
    ACCOUNT_LOGI("deviceAccountId = %{public}d", deviceAccountId);

    int result = PermissionKit::VerifyPermission(bundleName, permissionName, deviceAccountId);
    ACCOUNT_LOGI("result = %{public}d", result);

    if (result != PermissionState::PERMISSION_GRANTED) {
        return ERR_APPACCOUNT_SERVICE_PERMISSION_DENIED;
    }

    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
