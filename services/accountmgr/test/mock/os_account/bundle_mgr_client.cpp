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
#include "bundle_info.h"

#include "bundle_mgr_client.h"

using namespace OHOS::AccountSA;

namespace OHOS {
namespace AppExecFwk {
BundleMgrClient::BundleMgrClient()
{
    ACCOUNT_LOGI("enter");
}

BundleMgrClient::~BundleMgrClient()
{
    ACCOUNT_LOGI("enter");
}

bool BundleMgrClient::GetBundleNameForUid(const int uid, std::string &bundleName) const
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("uid = %{public}d", uid);

    bundleName = "com.example.owner";
    ACCOUNT_LOGI("bundleName = %{public}s", bundleName.c_str());

    return true;
}

bool BundleMgrClient::GetBundleInfo(const std::string &bundleName, const BundleFlag flag, BundleInfo &bundleInfo) const
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("bundleName = %{public}s", bundleName.c_str());

    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS
