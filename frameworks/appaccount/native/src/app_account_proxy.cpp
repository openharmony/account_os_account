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

#include "app_account_proxy.h"

#include "account_error_no.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
AppAccountProxy::AppAccountProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IAppAccount>(object)
{}

AppAccountProxy::~AppAccountProxy()
{}

ErrCode AppAccountProxy::AddAccount(const std::string &name, const std::string &extraInfo)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

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

    return result;
}

ErrCode AppAccountProxy::AddAccountImplicitly(const std::string &owner, const std::string &authType,
    const AAFwk::Want &options, const sptr<IRemoteObject> &callback)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteString(owner)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_NAME;
    }
    if (!data.WriteString(authType)) {
        ACCOUNT_LOGE("failed to write string for authType");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_AUTH_TYPE;
    }
    if (!data.WriteParcelable(&options)) {
        ACCOUNT_LOGE("failed to write parcelable for options");
        return ERR_APPACCOUNT_KIT_WRITE_PARCELABLE_OPTIONS;
    }
    if (!data.WriteRemoteObject(callback)) {
        ACCOUNT_LOGE("failed to write remote object for callback");
        return ERR_APPACCOUNT_KIT_WRITE_PARCELABLE_CALLBACK;
    }
    ErrCode result = SendRequest(IAppAccount::Message::ADD_ACCOUNT_IMPLICITLY, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to send request, errCode: %{public}d", result);
        return result;
    }
    result = reply.ReadInt32();
    return result;
}


ErrCode AppAccountProxy::CreateAccount(const std::string &name, const CreateAccountOptions &options)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write name");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_NAME;
    }
    if (!data.WriteParcelable(&options)) {
        ACCOUNT_LOGE("failed to write options");
        return ERR_APPACCOUNT_KIT_WRITE_PARCELABLE_OPTIONS;
    }
    MessageParcel reply;
    ErrCode result = SendRequest(IAppAccount::Message::CREATE_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        return result;
    }
    return reply.ReadInt32();
}

ErrCode AppAccountProxy::CreateAccountImplicitly(
    const std::string &owner, const CreateAccountImplicitlyOptions &options, const sptr<IRemoteObject> &callback)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteString(owner)) {
        ACCOUNT_LOGE("failed to write owner");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_OWNER;
    }
    if (!data.WriteParcelable(&options)) {
        ACCOUNT_LOGE("failed to write options");
        return ERR_APPACCOUNT_KIT_WRITE_PARCELABLE_OPTIONS;
    }
    if (!data.WriteRemoteObject(callback)) {
        ACCOUNT_LOGE("failed to write remote object for callback");
        return ERR_APPACCOUNT_KIT_WRITE_PARCELABLE_CALLBACK;
    }
    MessageParcel reply;
    ErrCode result = SendRequest(IAppAccount::Message::CREATE_ACCOUNT_IMPLICITLY, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to send request, errCode: %{public}d", result);
        return result;
    }
    return reply.ReadInt32();
}

ErrCode AppAccountProxy::DeleteAccount(const std::string &name)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_NAME;
    }

    ErrCode result = SendRequest(IAppAccount::Message::DELETE_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();

    return result;
}

ErrCode AppAccountProxy::GetAccountExtraInfo(const std::string &name, std::string &extraInfo)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

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

    return result;
}

ErrCode AppAccountProxy::SetAccountExtraInfo(const std::string &name, const std::string &extraInfo)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

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

    return result;
}

ErrCode AppAccountProxy::EnableAppAccess(const std::string &name, const std::string &authorizedApp)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

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

    return result;
}

ErrCode AppAccountProxy::DisableAppAccess(const std::string &name, const std::string &authorizedApp)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

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

    return result;
}

ErrCode AppAccountProxy::SetAppAccess(const std::string &name, const std::string &authorizedApp, bool isAccessible)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    if (!data.WriteString(authorizedApp)) {
        ACCOUNT_LOGE("failed to write string for authorizedApp");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    if (!data.WriteBool(isAccessible)) {
        ACCOUNT_LOGE("failed to write string for isVisible");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    ErrCode result = SendRequest(IAppAccount::Message::SET_APP_ACCESS, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    return reply.ReadInt32();
}

ErrCode AppAccountProxy::CheckAppAccountSyncEnable(const std::string &name, bool &syncEnable)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

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

    return result;
}

ErrCode AppAccountProxy::SetAppAccountSyncEnable(const std::string &name, const bool &syncEnable)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

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

    return result;
}

ErrCode AppAccountProxy::GetAssociatedData(const std::string &name, const std::string &key, std::string &value)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_NAME;
    }

    if (!data.WriteString(key)) {
        ACCOUNT_LOGE("failed to write string for key");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_ASSOCIATED_KEY;
    }

    ErrCode result = SendRequest(IAppAccount::Message::GET_ASSOCIATED_DATA, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();
    value = reply.ReadString();

    return result;
}

ErrCode AppAccountProxy::SetAssociatedData(const std::string &name, const std::string &key, const std::string &value)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

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

    return result;
}

ErrCode AppAccountProxy::GetAccountCredential(
    const std::string &name, const std::string &credentialType, std::string &credential)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

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

    return result;
}

ErrCode AppAccountProxy::SetAccountCredential(
    const std::string &name, const std::string &credentialType, const std::string &credential)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

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

    return result;
}

ErrCode AppAccountProxy::Authenticate(const std::string &name, const std::string &owner, const std::string &authType,
    const AAFwk::Want &options, const sptr<IRemoteObject> &callback)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_NAME;
    }
    if (!data.WriteString(owner)) {
        ACCOUNT_LOGE("failed to write string for owner");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_OWNER;
    }
    if (!data.WriteString(authType)) {
        ACCOUNT_LOGE("failed to write string for authType");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_AUTH_TYPE;
    }
    if (!data.WriteParcelable(&options)) {
        ACCOUNT_LOGE("failed to write parcelable for options");
        return ERR_APPACCOUNT_KIT_WRITE_PARCELABLE_OPTIONS;
    }
    if (!data.WriteRemoteObject(callback)) {
        ACCOUNT_LOGE("failed to write remote object for callback");
        return ERR_APPACCOUNT_KIT_WRITE_PARCELABLE_CALLBACK;
    }
    ErrCode result = SendRequest(IAppAccount::Message::AUTHENTICATE, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to send request, errCode: %{public}d", result);
        return result;
    }
    result = reply.ReadInt32();
    return result;
}

ErrCode AppAccountProxy::WriteGetAuthTokenParam(
    const std::string &name, const std::string &owner, const std::string &authType, MessageParcel &data)
{
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString(owner)) {
        ACCOUNT_LOGE("failed to write string for owner");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString(authType)) {
        ACCOUNT_LOGE("failed to write string for authType");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode AppAccountProxy::GetOAuthToken(
    const std::string &name, const std::string &owner, const std::string &authType, std::string &token)
{
    MessageParcel data;
    MessageParcel reply;

    ErrCode result = WriteGetAuthTokenParam(name, owner, authType, data);
    if (result != ERR_OK) {
        return result;
    }

    result = SendRequest(IAppAccount::Message::GET_OAUTH_TOKEN, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to send request, errCode: %{public}d", result);
        return result;
    }
    result = reply.ReadInt32();
    token = reply.ReadString();
    return result;
}

ErrCode AppAccountProxy::GetAuthToken(
    const std::string &name, const std::string &owner, const std::string &authType, std::string &token)
{
    MessageParcel data;
    MessageParcel reply;

    ErrCode result = WriteGetAuthTokenParam(name, owner, authType, data);
    if (result != ERR_OK) {
        return result;
    }

    result = SendRequest(IAppAccount::Message::GET_AUTH_TOKEN, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to send request, errCode: %{public}d", result);
        return result;
    }
    result = reply.ReadInt32();
    token = reply.ReadString();
    return result;
}

ErrCode AppAccountProxy::SetOAuthToken(
    const std::string &name, const std::string &authType, const std::string &token)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_NAME;
    }
    if (!data.WriteString(authType)) {
        ACCOUNT_LOGE("failed to write string for authType");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_AUTH_TYPE;
    }
    if (!data.WriteString(token)) {
        ACCOUNT_LOGE("failed to write string for token");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_TOKEN;
    }
    ErrCode result = SendRequest(IAppAccount::Message::SET_OAUTH_TOKEN, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to send request, errCode: %{public}d", result);
        return result;
    }
    result = reply.ReadInt32();
    return result;
}

ErrCode AppAccountProxy::WriteDeleteAuthTokenParam(const std::string &name, const std::string &owner,
    const std::string &authType, const std::string &token, MessageParcel &data)
{
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write string for token");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString(owner)) {
        ACCOUNT_LOGE("failed to write string for owner");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString(authType)) {
        ACCOUNT_LOGE("failed to write string for authType");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString(token)) {
        ACCOUNT_LOGE("failed to write string for token");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode AppAccountProxy::DeleteOAuthToken(
    const std::string &name, const std::string &owner, const std::string &authType, const std::string &token)
{
    MessageParcel data;
    MessageParcel reply;

    ErrCode result = WriteDeleteAuthTokenParam(name, owner, authType, token, data);
    if (result != ERR_OK) {
        return result;
    }
    
    result = SendRequest(IAppAccount::Message::DELETE_OAUTH_TOKEN, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to send request, errCode: %{public}d", result);
        return result;
    }
    return reply.ReadInt32();
}

ErrCode AppAccountProxy::DeleteAuthToken(
    const std::string &name, const std::string &owner, const std::string &authType, const std::string &token)
{
    MessageParcel data;
    MessageParcel reply;

    ErrCode result = WriteDeleteAuthTokenParam(name, owner, authType, token, data);
    if (result != ERR_OK) {
        return result;
    }
    result = SendRequest(IAppAccount::Message::DELETE_AUTH_TOKEN, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to send request, errCode: %{public}d", result);
        return result;
    }
    return reply.ReadInt32();
}

ErrCode AppAccountProxy::WriteTokenVisibilityParam(
    const std::string &name, const std::string &authType, const std::string &bundleName, MessageParcel &data)
{
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString(authType)) {
        ACCOUNT_LOGE("failed to write string for authType");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        ACCOUNT_LOGE("failed to write string for bundleName");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode AppAccountProxy::SetAuthTokenVisibility(
    const std::string &name, const std::string &authType, const std::string &bundleName, bool isVisible)
{
    MessageParcel data;
    MessageParcel reply;

    ErrCode result = WriteTokenVisibilityParam(name, authType, bundleName, data);
    if (result != ERR_OK) {
        return result;
    }

    if (!data.WriteBool(isVisible)) {
        ACCOUNT_LOGE("failed to write string for isVisible");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    result = SendRequest(IAppAccount::Message::SET_AUTH_TOKEN_VISIBILITY, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to send request, errCode: %{public}d", result);
        return result;
    }
    return reply.ReadInt32();
}

ErrCode AppAccountProxy::SetOAuthTokenVisibility(
    const std::string &name, const std::string &authType, const std::string &bundleName, bool isVisible)
{
    MessageParcel data;
    MessageParcel reply;

    ErrCode result = WriteTokenVisibilityParam(name, authType, bundleName, data);
    if (result != ERR_OK) {
        return result;
    }

    if (!data.WriteBool(isVisible)) {
        ACCOUNT_LOGE("failed to write string for isVisible");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    result = SendRequest(IAppAccount::Message::SET_OAUTH_TOKEN_VISIBILITY, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to send request, errCode: %{public}d", result);
        return result;
    }
    return reply.ReadInt32();
}

ErrCode AppAccountProxy::CheckAuthTokenVisibility(
    const std::string &name, const std::string &authType, const std::string &bundleName, bool &isVisible)
{
    MessageParcel data;
    MessageParcel reply;

    ErrCode result = WriteTokenVisibilityParam(name, authType, bundleName, data);
    if (result != ERR_OK) {
        return result;
    }

    result = SendRequest(IAppAccount::Message::CHECK_AUTH_TOKEN_VISIBILITY, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to send request, errCode: %{public}d", result);
        return result;
    }
    result = reply.ReadInt32();
    isVisible = reply.ReadBool();
    return result;
}

ErrCode AppAccountProxy::CheckOAuthTokenVisibility(
    const std::string &name, const std::string &authType, const std::string &bundleName, bool &isVisible)
{
    MessageParcel data;
    MessageParcel reply;

    ErrCode result = WriteTokenVisibilityParam(name, authType, bundleName, data);
    if (result != ERR_OK) {
        return result;
    }

    result = SendRequest(IAppAccount::Message::CHECK_OAUTH_TOKEN_VISIBILITY, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to send request, errCode: %{public}d", result);
        return result;
    }
    result = reply.ReadInt32();
    isVisible = reply.ReadBool();
    return result;
}

ErrCode AppAccountProxy::GetAuthenticatorInfo(const std::string &owner, AuthenticatorInfo &info)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteString(owner)) {
        ACCOUNT_LOGE("failed to write string for owner");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_OWNER;
    }
    ErrCode result = SendRequest(IAppAccount::Message::GET_AUTHENTICATOR_INFO, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to send request, errCode: %{public}d", result);
        return result;
    }
    result = reply.ReadInt32();
    info.owner = reply.ReadString();
    info.iconId = reply.ReadInt32();
    info.labelId = reply.ReadInt32();
    return result;
}

ErrCode AppAccountProxy::GetAllOAuthTokens(
    const std::string &name, const std::string &owner, std::vector<OAuthTokenInfo> &tokenInfos)
{
    tokenInfos.clear();
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_NAME;
    }
    if (!data.WriteString(owner)) {
        ACCOUNT_LOGE("failed to write string for owner");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_OWNER;
    }
    ErrCode result = SendRequest(IAppAccount::Message::GET_ALL_OAUTH_TOKENS, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to send request, errCode: %{public}d", result);
        return result;
    }
    result = reply.ReadInt32();
    uint32_t size = reply.ReadUint32();
    for (uint32_t i = 0; i < size; ++i) {
        OAuthTokenInfo tokenInfo;
        tokenInfo.token = reply.ReadString();
        tokenInfo.authType = reply.ReadString();
        tokenInfos.push_back(tokenInfo);
    }
    return result;
}

ErrCode AppAccountProxy::WriteGetAuthListParam(
    const std::string &name, const std::string &authType, MessageParcel &data)
{
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString(authType)) {
        ACCOUNT_LOGE("failed to write string for authType");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode AppAccountProxy::GetOAuthList(
    const std::string &name, const std::string &authType, std::set<std::string> &oauthList)
{
    MessageParcel data;
    MessageParcel reply;

    ErrCode result = WriteGetAuthListParam(name, authType, data);
    if (result != ERR_OK) {
        return result;
    }
    
    result = SendRequest(IAppAccount::Message::GET_OAUTH_LIST, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to send request, errCode: %{public}d", result);
        return result;
    }
    result = reply.ReadInt32();
    uint32_t size = reply.ReadUint32();
    for (uint32_t i = 0; i < size; ++i) {
        oauthList.emplace(reply.ReadString());
    }
    return result;
}

ErrCode AppAccountProxy::GetAuthList(
    const std::string &name, const std::string &authType, std::set<std::string> &oauthList)
{
    MessageParcel data;
    MessageParcel reply;

    ErrCode result = WriteGetAuthListParam(name, authType, data);
    if (result != ERR_OK) {
        return result;
    }

    result = SendRequest(IAppAccount::Message::GET_AUTH_LIST, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to send request, errCode: %{public}d", result);
        return result;
    }
    result = reply.ReadInt32();
    uint32_t size = reply.ReadUint32();
    for (uint32_t i = 0; i < size; ++i) {
        oauthList.emplace(reply.ReadString());
    }
    return result;
}

ErrCode AppAccountProxy::GetAuthenticatorCallback(const std::string &sessionId, sptr<IRemoteObject> &callback)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteString(sessionId)) {
        ACCOUNT_LOGE("failed to write string for sessionId");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_SESSION_ID;
    }
    ErrCode result = SendRequest(IAppAccount::Message::GET_AUTHENTICATOR_CALLBACK, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to send request, errCode: %{public}d", result);
        return result;
    }
    result = reply.ReadInt32();
    callback = reply.ReadRemoteObject();
    return result;
}

ErrCode AppAccountProxy::GetAllAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

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

    return result;
}

ErrCode AppAccountProxy::GetAllAccessibleAccounts(std::vector<AppAccountInfo> &appAccounts)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    ErrCode result = SendRequest(IAppAccount::Message::GET_ALL_ACCESSIBLE_ACCOUNTS, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();

    if (!ReadParcelableVector(appAccounts, reply)) {
        ACCOUNT_LOGE("failed to read parcelable for AppAccountInfo");
        return ERR_APPACCOUNT_KIT_READ_PARCELABLE_APP_ACCOUNT_INFO;
    }

    return result;
}

ErrCode AppAccountProxy::QueryAllAccessibleAccounts(const std::string &owner, std::vector<AppAccountInfo> &appAccounts)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString(owner)) {
        ACCOUNT_LOGE("failed to write string for owner");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    MessageParcel reply;
    ErrCode result = SendRequest(IAppAccount::Message::QUERY_ALL_ACCESSIBLE_ACCOUNTS, data, reply);
    if (result != ERR_OK) {
        return result;
    }
    result = reply.ReadInt32();
    if (!ReadParcelableVector(appAccounts, reply)) {
        ACCOUNT_LOGE("failed to read parcelable for AppAccountInfo");
        return ERR_APPACCOUNT_KIT_READ_PARCELABLE_APP_ACCOUNT_INFO;
    }
    return result;
}

ErrCode AppAccountProxy::CheckAppAccess(
    const std::string &name, const std::string &authorizedApp, bool &isAccessible)
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_NAME;
    }
    if (!data.WriteString(authorizedApp)) {
        ACCOUNT_LOGE("failed to write string for authorizedApp");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_AUTHORIZED_APP;
    }
    ErrCode result = SendRequest(IAppAccount::Message::CHECK_APP_ACCESS, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to send request, errCode: %{public}d", result);
        return result;
    }
    result = reply.ReadInt32();
    isAccessible = reply.ReadBool();
    return result;
}

ErrCode AppAccountProxy::DeleteAccountCredential(
    const std::string &name, const std::string &credentialType)
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_NAME;
    }
    if (!data.WriteString(credentialType)) {
        ACCOUNT_LOGE("failed to write string for credentialType");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_CREDENTIAL_TYPE;
    }
    ErrCode result = SendRequest(IAppAccount::Message::DELETE_ACCOUNT_CREDENTIAL, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to send request, errCode: %{public}d", result);
        return result;
    }
    return reply.ReadInt32();
}

ErrCode AppAccountProxy::SelectAccountsByOptions(
    const SelectAccountsOptions &options, const sptr<IRemoteObject> &callback)
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteParcelable(&options)) {
        ACCOUNT_LOGE("failed to write parcelable for options");
        return ERR_APPACCOUNT_KIT_WRITE_PARCELABLE_OPTIONS;
    }
    if (!data.WriteRemoteObject(callback)) {
        ACCOUNT_LOGE("failed to write remote object for callback");
        return ERR_APPACCOUNT_KIT_WRITE_PARCELABLE_CALLBACK;
    }
    ErrCode result = SendRequest(IAppAccount::Message::SELECT_ACCOUNTS_BY_OPTIONS, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to send request, errCode: %{public}d", result);
        return result;
    }
    return reply.ReadInt32();
}

ErrCode AppAccountProxy::VerifyCredential(const std::string &name, const std::string &owner,
    const VerifyCredentialOptions &options, const sptr<IRemoteObject> &callback)
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_NAME;
    }
    if (!data.WriteString(owner)) {
        ACCOUNT_LOGE("failed to write string for owner");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_OWNER;
    }
    if (!data.WriteParcelable(&options)) {
        ACCOUNT_LOGE("failed to write string for options");
        return ERR_APPACCOUNT_KIT_WRITE_PARCELABLE_OPTIONS;
    }
    if (!data.WriteRemoteObject(callback)) {
        ACCOUNT_LOGE("failed to write string for callback");
        return ERR_APPACCOUNT_KIT_WRITE_PARCELABLE_CALLBACK;
    }
    ErrCode result = SendRequest(IAppAccount::Message::VERIFY_CREDENTIAL, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to send request, errCode: %{public}d", result);
        return result;
    }
    return reply.ReadInt32();
}

ErrCode AppAccountProxy::CheckAccountLabels(const std::string &name, const std::string &owner,
    const std::vector<std::string> &labels, const sptr<IRemoteObject> &callback)
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_NAME;
    }
    if (!data.WriteString(owner)) {
        ACCOUNT_LOGE("failed to write string for owner");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_OWNER;
    }
    if (!data.WriteStringVector(labels)) {
        ACCOUNT_LOGE("failed to write string vector for labels");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_VECTOR;
    }
    if (!data.WriteRemoteObject(callback)) {
        ACCOUNT_LOGE("failed to write string for callback");
        return ERR_APPACCOUNT_KIT_WRITE_PARCELABLE_CALLBACK;
    }
    ErrCode result = SendRequest(IAppAccount::Message::CHECK_ACCOUNT_LABELS, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to send request, errCode: %{public}d", result);
        return result;
    }
    return reply.ReadInt32();
}

ErrCode AppAccountProxy::SetAuthenticatorProperties(
    const std::string &owner, const SetPropertiesOptions &options, const sptr<IRemoteObject> &callback)
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteString(owner)) {
        ACCOUNT_LOGE("failed to write string for owner");
        return ERR_APPACCOUNT_KIT_WRITE_STRING_OWNER;
    }
    if (!data.WriteParcelable(&options)) {
        ACCOUNT_LOGE("failed to write string for options");
        return ERR_APPACCOUNT_KIT_WRITE_PARCELABLE_OPTIONS;
    }
    if (!data.WriteRemoteObject(callback)) {
        ACCOUNT_LOGE("failed to write remote object for callback");
        return ERR_APPACCOUNT_KIT_WRITE_PARCELABLE_CALLBACK;
    }
    ErrCode result = SendRequest(IAppAccount::Message::SET_AUTHENTICATOR_PROPERTIES, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to send request, errCode: %{public}d", result);
        return result;
    }
    return reply.ReadInt32();
}

ErrCode AppAccountProxy::SubscribeAppAccount(
    const AppAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteParcelable(&subscribeInfo)) {
        ACCOUNT_LOGE("failed to write parcelable for subscribeInfo");
        return ERR_APPACCOUNT_KIT_WRITE_PARCELABLE_SUBSCRIBE_INFO;
    }

    if (!data.WriteRemoteObject(eventListener)) {
        ACCOUNT_LOGE("failed to write remote object for eventListener");
        return ERR_APPACCOUNT_KIT_WRITE_PARCELABLE_EVENT_LISTENER;
    }

    ErrCode result = SendRequest(IAppAccount::Message::SUBSCRIBE_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();

    return result;
}

ErrCode AppAccountProxy::UnsubscribeAppAccount(const sptr<IRemoteObject> &eventListener)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteRemoteObject(eventListener)) {
        ACCOUNT_LOGE("failed to write remote object for eventListener");
        return ERR_APPACCOUNT_KIT_WRITE_PARCELABLE_EVENT_LISTENER;
    }

    ErrCode result = SendRequest(IAppAccount::Message::UNSUBSCRIBE_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();

    return result;
}

ErrCode AppAccountProxy::SendRequest(IAppAccount::Message code, MessageParcel &data, MessageParcel &reply)
{
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
    uint32_t size = 0;
    if (!data.ReadUint32(size)) {
        ACCOUNT_LOGE("failed to ReadInt32 for size");
        return false;
    }

    parcelableVector.clear();
    for (uint32_t index = 0; index < size; index += 1) {
        std::shared_ptr<T> parcelable(data.ReadParcelable<T>());
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
