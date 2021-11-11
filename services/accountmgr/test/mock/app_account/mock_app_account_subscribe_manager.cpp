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
#include "mock_app_account_subscribe_manager.h"

namespace {
const std::string STRING_OWNER = "com.example.owner";
}  // namespace

namespace OHOS {
namespace AccountSA {
MockAppAccountSubscribeManager::MockAppAccountSubscribeManager()
{
    ACCOUNT_LOGI("enter");
}

MockAppAccountSubscribeManager::~MockAppAccountSubscribeManager()
{
    ACCOUNT_LOGI("enter");
}

ErrCode MockAppAccountSubscribeManager::SubscribeAppAccount(
    const std::shared_ptr<AppAccountSubscribeInfo> &subscribeInfoPtr, const sptr<IRemoteObject> &eventListener,
    const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    std::vector<std::string> owners;
    if (subscribeInfoPtr->GetOwners(owners) != ERR_OK) {
        ACCOUNT_LOGE("failed to get owners");
        return ERR_APPACCOUNT_SERVICE_OTHER;
    }

    if (owners.size() == 0) {
        ACCOUNT_LOGE("owners.size() = %{public}zu", owners.size());
        return ERR_APPACCOUNT_SERVICE_OTHER;
    }

    auto owner = owners.front();
    if (owner != STRING_OWNER) {
        return ERR_APPACCOUNT_SERVICE_OTHER;
    }

    return ERR_OK;
}

ErrCode MockAppAccountSubscribeManager::UnsubscribeAppAccount(const sptr<IRemoteObject> &eventListener)
{
    ACCOUNT_LOGI("enter");

    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
