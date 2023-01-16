/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "mock_app_account_stub.h"

#include "account_error_no.h"
#include "account_log_wrapper.h"

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
    ACCOUNT_LOGI("mock enter");
    ACCOUNT_LOGI("mock name.size() = %{public}zu", name.size());
    ACCOUNT_LOGI("mock extraInfo.size() = %{public}zu", extraInfo.size());

    if (name.size() == 0) {
        ACCOUNT_LOGE("mock name is empty");
        return ERR_APPACCOUNT_SERVICE_NAME_IS_EMPTY;
    }

    if (name.size() > NAME_MAX_SIZE) {
        ACCOUNT_LOGE("mock name is out of range, name.size() = %{public}zu", name.size());
        return ERR_APPACCOUNT_SERVICE_NAME_OUT_OF_RANGE;
    }

    if (extraInfo.size() > EXTRA_INFO_MAX_SIZE) {
        ACCOUNT_LOGE("mock extra info is out of range, extraInfo.size() = %{public}zu", extraInfo.size());
        return ERR_APPACCOUNT_SERVICE_EXTRA_INFO_OUT_OF_RANGE;
    }

    return ERR_OK;
}

ErrCode MockAppAccountStub::AddAccountImplicitly(const std::string &owner, const std::string &authType,
    const AAFwk::Want &options, const sptr<IRemoteObject> &callback)
{
    ACCOUNT_LOGI("mock enter");
    return ERR_OK;
}

ErrCode MockAppAccountStub::CreateAccount(const std::string &name, const CreateAccountOptions &options)
{
    ACCOUNT_LOGI("mock enter");
    return ERR_OK;
}

ErrCode MockAppAccountStub::CreateAccountImplicitly(
    const std::string &owner, const CreateAccountImplicitlyOptions &options, const sptr<IRemoteObject> &callback)
{
    ACCOUNT_LOGI("mock enter");
    return ERR_OK;
}

ErrCode MockAppAccountStub::DeleteAccount(const std::string &name)
{
    ACCOUNT_LOGI("mock enter");
    ACCOUNT_LOGI("mock name.size() = %{public}zu", name.size());

    if (name.size() == 0) {
        ACCOUNT_LOGE("mock name is empty");
        return ERR_APPACCOUNT_SERVICE_NAME_IS_EMPTY;
    }

    if (name.size() > NAME_MAX_SIZE) {
        ACCOUNT_LOGE("mock name is out of range, name.size() = %{public}zu", name.size());
        return ERR_APPACCOUNT_SERVICE_NAME_OUT_OF_RANGE;
    }

    return ERR_OK;
}

ErrCode MockAppAccountStub::GetAccountExtraInfo(const std::string &name, std::string &extraInfo)
{
    ACCOUNT_LOGI("mock enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::SetAccountExtraInfo(const std::string &name, const std::string &extraInfo)
{
    ACCOUNT_LOGI("mock enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::EnableAppAccess(const std::string &name, const std::string &authorizedApp)
{
    ACCOUNT_LOGI("mock enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::DisableAppAccess(const std::string &name, const std::string &authorizedApp)
{
    ACCOUNT_LOGI("mock enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::SetAppAccess(const std::string &name, const std::string &authorizedApp, bool isAccessible)
{
    ACCOUNT_LOGI("mock enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::CheckAppAccountSyncEnable(const std::string &name, bool &syncEnable)
{
    ACCOUNT_LOGI("mock enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::SetAppAccountSyncEnable(const std::string &name, const bool &syncEnable)
{
    ACCOUNT_LOGI("mock enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::GetAssociatedData(const std::string &name, const std::string &key, std::string &value)
{
    ACCOUNT_LOGI("mock enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::SetAssociatedData(
    const std::string &name, const std::string &key, const std::string &value)
{
    ACCOUNT_LOGI("mock enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::GetAccountCredential(
    const std::string &name, const std::string &credentialType, std::string &credential)
{
    ACCOUNT_LOGI("mock enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::SetAccountCredential(
    const std::string &name, const std::string &credentialType, const std::string &credential)
{
    ACCOUNT_LOGI("mock enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::Authenticate(const std::string &name, const std::string &owner,
    const std::string &authType, const AAFwk::Want &options, const sptr<IRemoteObject> &callback)
{
    ACCOUNT_LOGI("mock enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::GetOAuthToken(
    const std::string &name, const std::string &owner, const std::string &authType, std::string &token)
{
    ACCOUNT_LOGI("mock enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::GetAuthToken(
    const std::string &name, const std::string &owner, const std::string &authType, std::string &token)
{
    ACCOUNT_LOGI("mock enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::SetOAuthToken(
    const std::string &name, const std::string &authType, const std::string &token)
{
    ACCOUNT_LOGI("mock enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::DeleteOAuthToken(const std::string &name, const std::string &owner,
    const std::string &authType, const std::string &token)
{
    ACCOUNT_LOGI("mock enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::DeleteAuthToken(const std::string &name, const std::string &owner,
    const std::string &authType, const std::string &token)
{
    ACCOUNT_LOGI("mock enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::SetOAuthTokenVisibility(const std::string &name, const std::string &authType,
    const std::string &bundleName, bool isVisible)
{
    ACCOUNT_LOGI("mock enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::SetAuthTokenVisibility(const std::string &name, const std::string &authType,
    const std::string &bundleName, bool isVisible)
{
    ACCOUNT_LOGI("mock enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::CheckOAuthTokenVisibility(const std::string &name, const std::string &authType,
    const std::string &bundleName, bool &isVisible)
{
    ACCOUNT_LOGI("mock enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::CheckAuthTokenVisibility(const std::string &name, const std::string &authType,
    const std::string &bundleName, bool &isVisible)
{
    ACCOUNT_LOGI("mock enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::GetAuthenticatorInfo(const std::string &owner, AuthenticatorInfo &authenticator)
{
    ACCOUNT_LOGI("mock enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::GetAllOAuthTokens(const std::string &name, const std::string &owner,
    std::vector<OAuthTokenInfo> &tokenInfos)
{
    ACCOUNT_LOGI("mock enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::GetOAuthList(const std::string &name, const std::string &authType,
    std::set<std::string> &oauthList)
{
    ACCOUNT_LOGI("mock enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::GetAuthList(const std::string &name, const std::string &authType,
    std::set<std::string> &oauthList)
{
    ACCOUNT_LOGI("mock enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::GetAuthenticatorCallback(const std::string &sessionId, sptr<IRemoteObject> &callback)
{
    ACCOUNT_LOGI("mock enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::GetAllAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts)
{
    ACCOUNT_LOGI("mock enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::GetAllAccessibleAccounts(std::vector<AppAccountInfo> &appAccounts)
{
    ACCOUNT_LOGI("mock enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::QueryAllAccessibleAccounts(
    const std::string &owner, std::vector<AppAccountInfo> &appAccounts)
{
    ACCOUNT_LOGI("mock enter");
    return ERR_OK;
}

ErrCode MockAppAccountStub::CheckAppAccess(
    const std::string &name, const std::string &authorizedApp, bool &isAccessible)
{
    ACCOUNT_LOGD("mock enter");
    (void) name;
    (void) authorizedApp;
    (void) isAccessible;
    return ERR_OK;
}

ErrCode MockAppAccountStub::DeleteAccountCredential(const std::string &name, const std::string &credentialType)
{
    ACCOUNT_LOGD("mock enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::SelectAccountsByOptions(
    const SelectAccountsOptions &options, const sptr<IRemoteObject> &callback)
{
    ACCOUNT_LOGD("mock enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::VerifyCredential(const std::string &name, const std::string &owner,
    const VerifyCredentialOptions &options, const sptr<IRemoteObject> &callback)
{
    ACCOUNT_LOGD("mock enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::CheckAccountLabels(const std::string &name, const std::string &owner,
    const std::vector<std::string> &labels, const sptr<IRemoteObject> &callback)
{
    ACCOUNT_LOGD("mock enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::SetAuthenticatorProperties(
    const std::string &owner, const SetPropertiesOptions &options, const sptr<IRemoteObject> &callback)
{
    ACCOUNT_LOGD("mock enter");

    return ERR_OK;
}

ErrCode MockAppAccountStub::SubscribeAppAccount(
    const AppAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener)
{
    ACCOUNT_LOGI("mock enter");

    std::vector<std::string> owners;
    ErrCode result = subscribeInfo.GetOwners(owners);

    ACCOUNT_LOGI("mock result = %{public}d", result);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("mock failed to get owners");
        return ERR_APPACCOUNT_SERVICE_GET_OWNERS;
    }

    ACCOUNT_LOGI("mock owners.size() = %{public}zu", owners.size());
    if (owners.size() == 0) {
        ACCOUNT_LOGE("mock owners are empty");
        return ERR_APPACCOUNT_SERVICE_OWNERS_ARE_EMPTY;
    }

    return ERR_OK;
}

ErrCode MockAppAccountStub::UnsubscribeAppAccount(const sptr<IRemoteObject> &eventListener)
{
    ACCOUNT_LOGI("mock enter");

    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
