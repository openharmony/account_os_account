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

#include "mock_inner_app_account_manager.h"

#include "account_log_wrapper.h"

namespace {
const std::string STRING_NAME = "name";
const std::string STRING_EXTRA_INFO = "extra_info";
const std::string STRING_OWNER = "com.example.owner";
}  // namespace

namespace OHOS {
namespace AccountSA {
MockInnerAppAccountManager::MockInnerAppAccountManager()
{
    ACCOUNT_LOGI("mock enter");
}

MockInnerAppAccountManager::~MockInnerAppAccountManager()
{
    ACCOUNT_LOGI("mock enter");
}

ErrCode MockInnerAppAccountManager::AddAccount(
    const std::string &name, const std::string &extraInfo, const std::string &bundleName, const uint32_t &appIndex)
{
    ACCOUNT_LOGI("mock enter");

    ACCOUNT_LOGI("mock name = %{public}s", name.c_str());
    ACCOUNT_LOGI("mock extraInfo = %{public}s", extraInfo.c_str());

    if (name != STRING_NAME) {
        return ERR_APPACCOUNT_SERVICE_OTHER;
    }

    if (extraInfo != STRING_EXTRA_INFO) {
        return ERR_APPACCOUNT_SERVICE_OTHER;
    }

    return ERR_OK;
}

ErrCode MockInnerAppAccountManager::DeleteAccount(
    const std::string &name, const std::string &bundleName, const uint32_t &appIndex)
{
    ACCOUNT_LOGI("mock enter");

    ACCOUNT_LOGI("mock name = %{public}s", name.c_str());

    if (name != STRING_NAME) {
        return ERR_APPACCOUNT_SERVICE_OTHER;
    }

    return ERR_OK;
}

ErrCode MockInnerAppAccountManager::SubscribeAppAccount(const AppAccountSubscribeInfo &subscribeInfo,
    const sptr<IRemoteObject> &eventListener, const std::string &bundleName, const uint32_t &appIndex)
{
    ACCOUNT_LOGI("mock enter");

    std::vector<std::string> owners;
    if (subscribeInfo.GetOwners(owners) != ERR_OK) {
        ACCOUNT_LOGE("mock failed to get owners");
        return ERR_APPACCOUNT_SERVICE_OTHER;
    }

    if (owners.size() == 0) {
        ACCOUNT_LOGE("mock owners.size() = %{public}zu", owners.size());
        return ERR_APPACCOUNT_SERVICE_OTHER;
    }

    auto owner = owners.front();
    if (owner != STRING_OWNER) {
        return ERR_APPACCOUNT_SERVICE_OTHER;
    }

    return ERR_OK;
}

ErrCode MockInnerAppAccountManager::UnsubscribeAppAccount(const sptr<IRemoteObject> &eventListener)
{
    ACCOUNT_LOGI("mock enter");

    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
