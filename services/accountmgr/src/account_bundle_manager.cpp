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
#include "bundle_mgr_client.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

#include "account_bundle_manager.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AccountSA {
AccountBundleManager::AccountBundleManager()
{
    ACCOUNT_LOGI("enter");
}

AccountBundleManager::~AccountBundleManager()
{}

ErrCode AccountBundleManager::GetBundleName(const uid_t &uid, std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("uid = %{public}d", uid);

    bool result = DelayedSingleton<BundleMgrClient>::GetInstance()->GetBundleNameForUid(uid, bundleName);
    ACCOUNT_LOGI("result = %{public}d", result);
    ACCOUNT_LOGI("bundleName = %{public}s", bundleName.c_str());

    if (result == false) {
        return ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME;
    }

    return ERR_OK;
}

ErrCode AccountBundleManager::GetBundleInfo(const std::string &bundleName, BundleInfo &bundleInfo)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("bundleName = %{public}s", bundleName.c_str());

    bool result = DelayedSingleton<BundleMgrClient>::GetInstance()->GetBundleInfo(
        bundleName, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo);
    ACCOUNT_LOGI("result = %{public}d", result);

    if (result == false) {
        return ERR_APPACCOUNT_SERVICE_GET_BUNDLE_INFO;
    }

    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
