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

#ifndef OS_ACCOUNT_SERVICE_BUNDLE_MANAGER_ADAPTER_H
#define OS_ACCOUNT_SERVICE_BUNDLE_MANAGER_ADAPTER_H

#include <mutex>
#include <string>
#include "ability_info.h"
#include "bundle_info.h"
#include "want.h"

namespace OHOS {
namespace AccountSA {
class BundleManagerAdapter {
public:
    BundleManagerAdapter();
    virtual ~BundleManagerAdapter();
    static std::shared_ptr<BundleManagerAdapter> GetInstance();

    bool GetBundleNameForUid(const int uid, std::string &bundleName);
    bool GetBundleInfo(const std::string &bundleName, const AppExecFwk::BundleFlag flag,
        AppExecFwk::BundleInfo &bundleInfo, int32_t userId);
    int GetUidByBundleName(const std::string &bundleName, const int userId);
    bool QueryAbilityInfos(const AAFwk::Want &want, int32_t flags, int32_t userId,
        std::vector<AppExecFwk::AbilityInfo> &abilityInfos);
    bool QueryExtensionAbilityInfos(const AAFwk::Want &want, const int32_t &flag,
    const int32_t &userId, std::vector<AppExecFwk::ExtensionAbilityInfo> &extensionInfos);

private:
    static std::mutex mockInstanceMutex_;
    static std::shared_ptr<BundleManagerAdapter> instance_;
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_SERVICE_BUNDLE_MANAGER_ADAPTER_H
