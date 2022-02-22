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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_BUNDLE_MANAGER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_BUNDLE_MANAGER_H

#include "account_error_no.h"
#include "bundle_info.h"
#include "singleton.h"

namespace OHOS {
namespace AccountSA {
class AccountBundleManager : public DelayedSingleton<AccountBundleManager> {
public:
    AccountBundleManager();
    ~AccountBundleManager();

    ErrCode GetBundleName(const uid_t &uid, std::string &bundleName);
    ErrCode GetBundleInfo(const uid_t &uid, const std::string &bundleName, AppExecFwk::BundleInfo &bundleInfo);
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_BUNDLE_MANAGER_H
