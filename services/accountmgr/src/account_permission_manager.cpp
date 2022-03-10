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

#include "accesstoken_kit.h"
#include "account_bundle_manager.h"
#include "account_log_wrapper.h"
#include "ipc_skeleton.h"

#include "account_permission_manager.h"

using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace AccountSA {
const std::string AccountPermissionManager::DISTRIBUTED_DATASYNC = "ohos.permission.DISTRIBUTED_DATASYNC";
const std::string AccountPermissionManager::GET_ALL_APP_ACCOUNTS = "ohos.permission.GET_ALL_APP_ACCOUNTS";
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

bool AccountPermissionManager::IsSystemUid(const uid_t &uid) const
{
    ACCOUNT_LOGI("enter");

    if (uid >= MIN_SYSTEM_UID && uid <= MAX_SYSTEM_UID) {
        return true;
    }

    return true;
}

ErrCode AccountPermissionManager::VerifyPermission(const std::string &permissionName)
{
    AccessTokenID callingToken = IPCSkeleton::GetCallingTokenID();
    ErrCode result = AccessTokenKit::VerifyAccessToken(callingToken, permissionName);
    if (result == TypePermissionState::PERMISSION_DENIED) {
        return ERR_APPACCOUNT_SERVICE_PERMISSION_DENIED;
    }
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
