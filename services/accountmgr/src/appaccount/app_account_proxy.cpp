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

#include "app_account_proxy.h"

namespace OHOS {
namespace AccountSA {
AppAccountProxy::AppAccountProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IAppAccount>(object)
{
    ACCOUNT_LOGI("enter");
}

AppAccountProxy::~AppAccountProxy()
{}

ErrCode AppAccountProxy::AddAccount(const std::string &name, const std::string &extraInfo)
{
    ACCOUNT_LOGI("enter");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_NAME;
    }

    if (!data.WriteString(extraInfo)) {
        ACCOUNT_LOGE("failed to write string for extraInfo");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_EXTRA_INFO;
    }

    ErrCode result = SendRequest(IAppAccount::Message::ADD_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();
    ACCOUNT_LOGI("result = %{public}d", result);

    return result;
}

ErrCode AppAccountProxy::DeleteAccount(const std::string &name)
{
    ACCOUNT_LOGI("enter");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_NAME;
    }

    ErrCode result = SendRequest(IAppAccount::Message::DELETE_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();

    ACCOUNT_LOGI("result = %{public}d", result);

    return result;
}

ErrCode AppAccountProxy::GetAccountExtraInfo(const std::string &name, std::string &extraInfo)
{
    ACCOUNT_LOGI("enter");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_NAME;
    }

    ErrCode result = SendRequest(IAppAccount::Message::GET_ACCOUNT_EXTRA_INFO, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();
    extraInfo = reply.ReadString();
    ACCOUNT_LOGI("result = %{public}d, extraInfo = %{public}s", result, extraInfo.c_str());

    return result;
}

ErrCode AppAccountProxy::SetAccountExtraInfo(const std::string &name, const std::string &extraInfo)
{
    ACCOUNT_LOGI("enter");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_NAME;
    }

    if (!data.WriteString(extraInfo)) {
        ACCOUNT_LOGE("failed to write string for extraInfo");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_EXTRA_INFO;
    }

    ErrCode result = SendRequest(IAppAccount::Message::SET_ACCOUNT_EXTRA_INFO, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();
    ACCOUNT_LOGI("result = %{public}d", result);

    return result;
}

ErrCode AppAccountProxy::EnableAppAccess(const std::string &name, const std::string &authorizedApp)
{
    ACCOUNT_LOGI("enter");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_NAME;
    }

    if (!data.WriteString(authorizedApp)) {
        ACCOUNT_LOGE("failed to write string for authorizedApp");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_AUTHORIZED_APP;
    }

    ErrCode result = SendRequest(IAppAccount::Message::ENABLE_APP_ACCESS, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();
    ACCOUNT_LOGI("result = %{public}d", result);

    return result;
}

ErrCode AppAccountProxy::DisableAppAccess(const std::string &name, const std::string &authorizedApp)
{
    ACCOUNT_LOGI("enter");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_NAME;
    }

    if (!data.WriteString(authorizedApp)) {
        ACCOUNT_LOGE("failed to write string for authorizedApp");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_AUTHORIZED_APP;
    }

    ErrCode result = SendRequest(IAppAccount::Message::DISABLE_APP_ACCESS, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();
    ACCOUNT_LOGI("result = %{public}d", result);

    return result;
}

ErrCode AppAccountProxy::CheckAppAccountSyncEnable(const std::string &name, bool &syncEnable)
{
    ACCOUNT_LOGI("enter");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_NAME;
    }

    ErrCode result = SendRequest(IAppAccount::Message::CHECK_APP_ACCOUNT_SYNC_ENABLE, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();
    syncEnable = reply.ReadBool();
    ACCOUNT_LOGI("result = %{public}d, syncEnable = %{public}d", result, syncEnable);

    return result;
}

ErrCode AppAccountProxy::SetAppAccountSyncEnable(const std::string &name, const bool &syncEnable)
{
    ACCOUNT_LOGI("enter");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_NAME;
    }

    if (!data.WriteBool(syncEnable)) {
        ACCOUNT_LOGE("failed to write bool for syncEnable");
        return ERR_APPACCOUNT_KIT_WRITE_BOOL_SYNC_ENABLE;
    }

    ErrCode result = SendRequest(IAppAccount::Message::SET_APP_ACCOUNT_SYNC_ENABLE, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();
    ACCOUNT_LOGI("result = %{public}d", result);

    return result;
}

ErrCode AppAccountProxy::GetAssociatedData(const std::string &name, const std::string &key, std::string &value)
{
    ACCOUNT_LOGI("enter");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_NAME;
    }

    if (!data.WriteString(key)) {
        ACCOUNT_LOGE("failed to write string for key");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_ASSOCIATEKEY;
    }

    ErrCode result = SendRequest(IAppAccount::Message::GET_ASSOCIATED_DATA, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();
    value = reply.ReadString();
    ACCOUNT_LOGI("result = %{public}d, value = %{public}s", result, value.c_str());

    return result;
}

ErrCode AppAccountProxy::SetAssociatedData(const std::string &name, const std::string &key, const std::string &value)
{
    ACCOUNT_LOGI("enter");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_NAME;
    }

    if (!data.WriteString(key)) {
        ACCOUNT_LOGE("failed to write string for key");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_KEY;
    }

    if (!data.WriteString(value)) {
        ACCOUNT_LOGE("failed to write string for value");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_VALUE;
    }

    ErrCode result = SendRequest(IAppAccount::Message::SET_ASSOCIATED_DATA, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();
    ACCOUNT_LOGI("result = %{public}d", result);

    return result;
}

ErrCode AppAccountProxy::GetAccountCredential(
    const std::string &name, const std::string &credentialType, std::string &credential)
{
    ACCOUNT_LOGI("enter");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_NAME;
    }

    if (!data.WriteString(credentialType)) {
        ACCOUNT_LOGE("failed to write string for credentialType");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_CREDENTIAL_TYPE;
    }

    ErrCode result = SendRequest(IAppAccount::Message::GET_ACCOUNT_CREDENTIAL, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();
    credential = reply.ReadString();
    ACCOUNT_LOGI("result = %{public}d, credential = %{public}s", result, credential.c_str());

    return result;
}

ErrCode AppAccountProxy::SetAccountCredential(
    const std::string &name, const std::string &credentialType, const std::string &credential)
{
    ACCOUNT_LOGI("enter");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_NAME;
    }

    if (!data.WriteString(credentialType)) {
        ACCOUNT_LOGE("failed to write string for credentialType");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_CREDENTIAL_TYPE;
    }

    if (!data.WriteString(credential)) {
        ACCOUNT_LOGE("failed to write string for credential");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_CREDENTIAL;
    }

    ErrCode result = SendRequest(IAppAccount::Message::SET_ACCOUNT_CREDENTIAL, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();
    ACCOUNT_LOGI("result = %{public}d", result);

    return result;
}

ErrCode AppAccountProxy::GetOAuthToken(const std::string &name, std::string &token)
{
    ACCOUNT_LOGI("enter");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_NAME;
    }

    if (!data.WriteString(token)) {
        ACCOUNT_LOGE("failed to write string for token");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_TOKEN;
    }

    ErrCode result = SendRequest(IAppAccount::Message::GET_OAUTH_TOKEN, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();
    token = reply.ReadString();
    ACCOUNT_LOGI("result = %{public}d, token = %{public}s", result, token.c_str());

    return result;
}

ErrCode AppAccountProxy::SetOAuthToken(const std::string &name, const std::string &token)
{
    ACCOUNT_LOGI("enter");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_NAME;
    }

    if (!data.WriteString(token)) {
        ACCOUNT_LOGE("failed to write string for token");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_TOKEN;
    }

    ErrCode result = SendRequest(IAppAccount::Message::SET_OAUTH_TOKEN, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();
    ACCOUNT_LOGI("result = %{public}d", result);

    return result;
}

ErrCode AppAccountProxy::ClearOAuthToken(const std::string &name)
{
    ACCOUNT_LOGI("enter");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_NAME;
    }

    ErrCode result = SendRequest(IAppAccount::Message::CLEAR_OAUTH_TOKEN, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();
    ACCOUNT_LOGI("result = %{public}d", result);

    return result;
}

ErrCode AppAccountProxy::GetAllAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts)
{
    ACCOUNT_LOGI("enter");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteString(owner)) {
        ACCOUNT_LOGE("failed to write string for owner");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_OWNER;
    }

    ErrCode result = SendRequest(IAppAccount::Message::GET_ALL_ACCOUNTS, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();

    if (!ReadParcelableVector(appAccounts, reply)) {
        ACCOUNT_LOGE("failed to read parcelable for AppAccountInfo");
        return ERR_APPACCOUNT_KIT_READ_PARCELABLE_APP_ACCOUNT_INFO;
    }

    ACCOUNT_LOGI("result = %{public}d", result);

    return result;
}

ErrCode AppAccountProxy::GetAllAccessibleAccounts(std::vector<AppAccountInfo> &appAccounts)
{
    ACCOUNT_LOGI("enter");

    MessageParcel data;
    MessageParcel reply;

    ErrCode result = SendRequest(IAppAccount::Message::GET_ALL_ACCESSIBLE_ACCOUNTS, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();

    if (!ReadParcelableVector(appAccounts, reply)) {
        ACCOUNT_LOGE("failed to read parcelable for AppAccountInfo");
        return ERR_APPACCOUNT_KIT_READ_PARCELABLE_APP_ACCOUNT_INFO;
    }

    ACCOUNT_LOGI("result = %{public}d", result);

    return result;
}

ErrCode AppAccountProxy::SubscribeAppAccount(
    const AppAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener)
{
    ACCOUNT_LOGI("enter");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteParcelable(&subscribeInfo)) {
        ACCOUNT_LOGE("failed to write parcelable for subscribeInfo");
        return ERR_APPACCOUNT_KIT_WRITE_PARCELABLE_SUBSCRIBE_INFO;
    }

    if (!data.WriteParcelable(eventListener)) {
        ACCOUNT_LOGE("failed to write parcelable for eventListener");
        return ERR_APPACCOUNT_KIT_WRITE_PARCELABLE_EVENT_LISTENER;
    }

    ErrCode result = SendRequest(IAppAccount::Message::SUBSCRIBE_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();
    ACCOUNT_LOGI("result = %{public}d", result);

    return result;
}

ErrCode AppAccountProxy::UnsubscribeAppAccount(const sptr<IRemoteObject> &eventListener)
{
    ACCOUNT_LOGI("enter");

    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteParcelable(eventListener)) {
        ACCOUNT_LOGE("failed to write parcelable for eventListener");
        return ERR_APPACCOUNT_KIT_WRITE_PARCELABLE_EVENT_LISTENER;
    }

    ErrCode result = SendRequest(IAppAccount::Message::UNSUBSCRIBE_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();
    ACCOUNT_LOGI("result = %{public}d", result);

    return result;
}

ErrCode AppAccountProxy::SendRequest(IAppAccount::Message code, MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGI("enter");

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCOUNT_LOGE("remote is nullptr, code = %{public}d", code);
        return ERR_APPACCOUNT_KIT_REMOTE_IS_NULLPTR;
    }

    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to SendRequest, code = %{public}d, result = %{public}d", code, result);
        return ERR_APPACCOUNT_KIT_SEND_REQUEST;
    }

    return ERR_OK;
}

template<typename T>
bool AppAccountProxy::WriteParcelableVector(const std::vector<T> &parcelableVector, MessageParcel &data)
{
    if (!data.WriteUint32(parcelableVector.size())) {
        ACCOUNT_LOGE("failed to WriteInt32 for parcelableVector.size()");
        return false;
    }

    for (const auto &parcelable : parcelableVector) {
        if (!data.WriteParcelable(&parcelable)) {
            ACCOUNT_LOGE("failed to WriteParcelable for parcelable");
            return false;
        }
    }

    return true;
}

template<typename T>
bool AppAccountProxy::ReadParcelableVector(std::vector<T> &parcelableVector, MessageParcel &data)
{
    ACCOUNT_LOGI("enter");

    uint32_t size = 0;
    if (!data.ReadUint32(size)) {
        ACCOUNT_LOGE("failed to ReadInt32 for size");
        return false;
    }

    parcelableVector.clear();
    for (uint32_t index = 0; index < size; index += 1) {
        T *parcelable = data.ReadParcelable<T>();
        if (parcelable == nullptr) {
            ACCOUNT_LOGE("failed to ReadParcelable for T");
            return false;
        }
        parcelableVector.emplace_back(*parcelable);
    }

    return true;
}
}  // namespace AccountSA
}  // namespace OHOS
