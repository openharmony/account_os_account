/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "bundle_manager_adapter.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
namespace {
const std::string STRING_BUNDLE_NAME_NOT_INSTALLED = "com.example.not_installed";
const std::string STRING_OWNER = "com.example.owner";
}  // namespace

std::shared_ptr<BundleManagerAdapter> BundleManagerAdapter::instance_ = nullptr;
std::mutex BundleManagerAdapter::mockInstanceMutex_;

std::shared_ptr<BundleManagerAdapter> BundleManagerAdapter::GetInstance()
{
    std::lock_guard<std::mutex> lock(mockInstanceMutex_);
    if (instance_ == nullptr) {
        instance_ = std::make_shared<BundleManagerAdapter>();
    }
    return instance_;
}

BundleManagerAdapter::BundleManagerAdapter()
{
    ACCOUNT_LOGI("create BundleManagerAdapter mock");
}

BundleManagerAdapter::~BundleManagerAdapter()
{
    ACCOUNT_LOGI("destroy BundleManagerAdapter mock");
}

bool BundleManagerAdapter::GetBundleNameForUid(const int uid, std::string &bundleName)
{
    ACCOUNT_LOGI("mock enter, uid = %{public}d", uid);
    bundleName = STRING_OWNER;
    ACCOUNT_LOGI("mock bundleName = %{public}s", bundleName.c_str());
    return true;
}

bool BundleManagerAdapter::GetBundleInfo(const std::string &bundleName, const AppExecFwk::BundleFlag flag,
    AppExecFwk::BundleInfo &bundleInfo, int32_t userId)
{
    ACCOUNT_LOGI("mock enter, bundleName = %{public}s", bundleName.c_str());
    if (bundleName == STRING_BUNDLE_NAME_NOT_INSTALLED) {
        return false;
    }
    return true;
}

bool BundleManagerAdapter::QueryAbilityInfos(const AAFwk::Want &want, int32_t flags, int32_t userId,
    std::vector<AppExecFwk::AbilityInfo> &abilityInfos)
{
    ACCOUNT_LOGI("mock enter, userId = %{public}d", userId);
    return false;
}

bool BundleManagerAdapter::QueryExtensionAbilityInfos(const AAFwk::Want &want, const int32_t &flag,
    const int32_t &userId, std::vector<AppExecFwk::ExtensionAbilityInfo> &extensionInfos)
{
    ACCOUNT_LOGI("mock enter, userId = %{public}d", userId);
    return false;
}

int BundleManagerAdapter::GetUidByBundleName(const std::string &bundleName, const int userId)
{
    ACCOUNT_LOGI("mock enter, bundleName = %{public}s, userId = %{public}d.", bundleName.c_str(), userId);
    return -1;
}
}  // namespace AccountSA
}  // namespace OHOS