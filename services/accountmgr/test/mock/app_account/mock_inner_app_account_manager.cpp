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
#include "mock_inner_app_account_manager.h"

namespace {
const std::string STRING_NAME = "name";
const std::string STRING_EXTRA_INFO = "extra_info";
const std::string STRING_OWNER = "com.example.owner";
}  // namespace

namespace OHOS {
namespace AccountSA {
MockInnerAppAccountManager::MockInnerAppAccountManager()
{
    ACCOUNT_LOGI("enter");
}

MockInnerAppAccountManager::~MockInnerAppAccountManager()
{
    ACCOUNT_LOGI("enter");
}

ErrCode MockInnerAppAccountManager::AddAccount(
    const std::string &name, const std::string &extraInfo, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());
    ACCOUNT_LOGI("extraInfo = %{public}s", extraInfo.c_str());

    if (name != STRING_NAME) {
        return ERR_APPACCOUNT_SERVICE_OTHER;
    }

    if (extraInfo != STRING_EXTRA_INFO) {
        return ERR_APPACCOUNT_SERVICE_OTHER;
    }

    return ERR_OK;
}

ErrCode MockInnerAppAccountManager::DeleteAccount(const std::string &name, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name = %{public}s", name.c_str());

    if (name != STRING_NAME) {
        return ERR_APPACCOUNT_SERVICE_OTHER;
    }

    return ERR_OK;
}

ErrCode MockInnerAppAccountManager::SubscribeAppAccount(const AppAccountSubscribeInfo &subscribeInfo,
    const sptr<IRemoteObject> &eventListener, const std::string &bundleName)
{
    ACCOUNT_LOGI("enter");

    std::vector<std::string> owners;
    if (subscribeInfo.GetOwners(owners) != ERR_OK) {
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

ErrCode MockInnerAppAccountManager::UnsubscribeAppAccount(const sptr<IRemoteObject> &eventListener)
{
    ACCOUNT_LOGI("enter");

    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
