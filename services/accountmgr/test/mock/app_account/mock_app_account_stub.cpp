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

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "mock_app_account_stub.h"

namespace OHOS {
namespace AccountSA {
namespace {
const std::string STRING_EMPTY = "";
const std::string STRING_NAME = "name";
const std::string STRING_EXTRA_INFO = "extra_info";
const std::string STRING_NAME_EMPTY = STRING_EMPTY;
const std::string STRING_EXTRA_INFO_EMPTY = STRING_EMPTY;
const std::string STRING_OWNER = "com.example.owner";

constexpr std::int32_t NAME_MAX_SIZE = 512;
constexpr std::int32_t EXTRA_INFO_MAX_SIZE = 1024;
}  // namespace

ErrCode MockAppAccountStub::AddAccount(const std::string &name, const std::string &extraInfo)
{
    ACCOUNT_LOGI("enter");
    ACCOUNT_LOGI("name.size() = %{public}zu", name.size());
    ACCOUNT_LOGI("extraInfo.size() = %{public}zu", extraInfo.size());

    if (name.size() == 0) {
        ACCOUNT_LOGE("name is empty");
        return ERR_APPACCOUNT_SERVICE_NAME_IS_EMPTY;
    }

    if (name.size() > NAME_MAX_SIZE) {
        ACCOUNT_LOGE("name is out of range");
        return ERR_APPACCOUNT_SERVICE_NAME_OUT_OF_RANGE;
    }

    if (extraInfo.size() > EXTRA_INFO_MAX_SIZE) {
        ACCOUNT_LOGE("extra info is out of range");
        return ERR_APPACCOUNT_SERVICE_EXTRA_INFO_OUT_OF_RANGE;
    }

    return ERR_OK;
}

ErrCode MockAppAccountStub::DeleteAccount(const std::string &name)
{
    ACCOUNT_LOGI("enter");
    ACCOUNT_LOGI("name.size() = %{public}zu", name.size());

    if (name.size() == 0) {
        ACCOUNT_LOGE("name is empty");
        return ERR_APPACCOUNT_SERVICE_NAME_IS_EMPTY;
    }

    if (name.size() > NAME_MAX_SIZE) {
        ACCOUNT_LOGE("name is out of range");
        return ERR_APPACCOUNT_SERVICE_NAME_OUT_OF_RANGE;
    }

    return ERR_OK;
}

ErrCode MockAppAccountStub::GetAccountExtraInfo(const std::string &name, std::string &extraInfo)
{
    ACCOUNT_LOGI("enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::SetAccountExtraInfo(const std::string &name, const std::string &extraInfo)
{
    ACCOUNT_LOGI("enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::EnableAppAccess(const std::string &name, const std::string &authorizedApp)
{
    ACCOUNT_LOGI("enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::DisableAppAccess(const std::string &name, const std::string &authorizedApp)
{
    ACCOUNT_LOGI("enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::CheckAppAccountSyncEnable(const std::string &name, bool &syncEnable)
{
    ACCOUNT_LOGI("enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::SetAppAccountSyncEnable(const std::string &name, const bool &syncEnable)
{
    ACCOUNT_LOGI("enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::GetAssociatedData(const std::string &name, const std::string &key, std::string &value)
{
    ACCOUNT_LOGI("enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::SetAssociatedData(const std::string &name, const std::string &key, const std::string &value)
{
    ACCOUNT_LOGI("enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::GetAccountCredential(
    const std::string &name, const std::string &credentialType, std::string &credential)
{
    ACCOUNT_LOGI("enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::SetAccountCredential(
    const std::string &name, const std::string &credentialType, const std::string &credential)
{
    ACCOUNT_LOGI("enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::GetOAuthToken(const std::string &name, std::string &token)
{
    ACCOUNT_LOGI("enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::SetOAuthToken(const std::string &name, const std::string &token)
{
    ACCOUNT_LOGI("enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::ClearOAuthToken(const std::string &name)
{
    ACCOUNT_LOGI("enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::GetAllAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts)
{
    ACCOUNT_LOGI("enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::GetAllAccessibleAccounts(std::vector<AppAccountInfo> &appAccounts)
{
    ACCOUNT_LOGI("enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::SubscribeAppAccount(
    const AppAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener)
{
    ACCOUNT_LOGI("enter");

    std::vector<std::string> owners;
    ErrCode result = subscribeInfo.GetOwners(owners);

    ACCOUNT_LOGI("result = %{public}d", result);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get owners");
        return ERR_APPACCOUNT_SERVICE_GET_OWNERS;
    }

    ACCOUNT_LOGI("owners.size() = %{public}zu", owners.size());
    if (owners.size() == 0) {
        ACCOUNT_LOGE("owners are empty");
        return ERR_APPACCOUNT_SERVICE_OWNERS_ARE_EMPTY;
    }

    return ERR_OK;
}

ErrCode MockAppAccountStub::UnsubscribeAppAccount(const sptr<IRemoteObject> &eventListener)
{
    ACCOUNT_LOGI("enter");

    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
