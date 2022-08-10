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

#include "mock_app_account_subscribe_manager.h"

#include "account_log_wrapper.h"

namespace {
const std::string STRING_OWNER = "com.example.owner";
}  // namespace

namespace OHOS {
namespace AccountSA {
MockAppAccountSubscribeManager::MockAppAccountSubscribeManager()
{
    ACCOUNT_LOGI("mock enter");
}

MockAppAccountSubscribeManager::~MockAppAccountSubscribeManager()
{
    ACCOUNT_LOGI("mock enter");
}

ErrCode MockAppAccountSubscribeManager::SubscribeAppAccount(
    const std::shared_ptr<AppAccountSubscribeInfo> &subscribeInfoPtr, const sptr<IRemoteObject> &eventListener,
    const std::string &bundleName, const uint32_t &appIndex)
{
    ACCOUNT_LOGI("mock enter");

    std::vector<std::string> owners;
    if (subscribeInfoPtr->GetOwners(owners) != ERR_OK) {
        ACCOUNT_LOGE("mock failed to get owners");
        return ERR_APPACCOUNT_SERVICE_OTHER;
    }

    if (owners.size() == 0) {
        ACCOUNT_LOGE("mock owners.size() = %{public}zu", owners.size());
        return ERR_APPACCOUNT_SERVICE_OTHER;
    }

    auto owner = owners.front();
    if (owner != STRING_OWNER) {
        ACCOUNT_LOGE("mock owner %{public}s != STRING_OWNER %{public}s.",
            owner.c_str(), STRING_OWNER.c_str());
        return ERR_APPACCOUNT_SERVICE_OTHER;
    }

    return ERR_OK;
}

ErrCode MockAppAccountSubscribeManager::UnsubscribeAppAccount(const sptr<IRemoteObject> &eventListener)
{
    ACCOUNT_LOGI("mock enter");

    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
