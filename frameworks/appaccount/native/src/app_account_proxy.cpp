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

ErrCode AppAccountProxy::SendRequestWithTwoStr(MessageParcel &reply, AppAccountInterfaceCode code,
    const std::string &str1, const std::string &str2)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteString(str1)) {
        ACCOUNT_LOGE("failed to write string for str1 %{public}s", str1.c_str());
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    if (!data.WriteString(str2)) {
        ACCOUNT_LOGE("failed to write string for str2 %{public}s", str2.c_str());
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    ErrCode result = SendRequest(code, data, reply);
    if (result != ERR_OK) {
        return result;
    }
    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGE("failed to read result for code %{public}d.", code);
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (result != ERR_OK) {
        ACCOUNT_LOGE("result failed for code %{public}d, result %{public}d.", code, result);
    }
    return result;
}

ErrCode AppAccountProxy::AddAccount(const std::string &name, const std::string &extraInfo)
{
    MessageParcel reply;
    return SendRequestWithTwoStr(reply, AppAccountInterfaceCode::ADD_ACCOUNT, name, extraInfo);
}

ErrCode AppAccountProxy::AddAccountImplicitly(const std::string &owner, const std::string &authType,
    const AAFwk::Want &options, const sptr<IAppAccountAuthenticatorCallback> &callback)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteString(owner)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString(authType)) {
        ACCOUNT_LOGE("failed to write string for authType");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&options)) {
        ACCOUNT_LOGE("failed to write parcelable for options");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if ((callback != nullptr) && (!data.WriteRemoteObject(callback->AsObject()))) {
        ACCOUNT_LOGE("failed to write remote object for callback");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    ErrCode result = SendRequest(AppAccountInterfaceCode::ADD_ACCOUNT_IMPLICITLY, data, reply);
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
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&options)) {
        ACCOUNT_LOGE("failed to write options");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    MessageParcel reply;
    ErrCode result = SendRequest(AppAccountInterfaceCode::CREATE_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        return result;
    }
    return reply.ReadInt32();
}

ErrCode AppAccountProxy::CreateAccountImplicitly(const std::string &owner,
    const CreateAccountImplicitlyOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteString(owner)) {
        ACCOUNT_LOGE("failed to write owner");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&options)) {
        ACCOUNT_LOGE("failed to write options");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if ((callback != nullptr) && (!data.WriteRemoteObject(callback->AsObject()))) {
        ACCOUNT_LOGE("failed to write remote object for callback");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    MessageParcel reply;
    ErrCode result = SendRequest(AppAccountInterfaceCode::CREATE_ACCOUNT_IMPLICITLY, data, reply);
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
        ACCOUNT_LOGE("failed to write name for deleting account");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    ErrCode result = SendRequest(AppAccountInterfaceCode::DELETE_ACCOUNT, data, reply);
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
        ACCOUNT_LOGE("failed to write name for getting extra info");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    ErrCode result = SendRequest(AppAccountInterfaceCode::GET_ACCOUNT_EXTRA_INFO, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();
    extraInfo = reply.ReadString();

    return result;
}

ErrCode AppAccountProxy::SetAccountExtraInfo(const std::string &name, const std::string &extraInfo)
{
    MessageParcel reply;
    return SendRequestWithTwoStr(reply, AppAccountInterfaceCode::SET_ACCOUNT_EXTRA_INFO, name, extraInfo);
}

ErrCode AppAccountProxy::EnableAppAccess(const std::string &name, const std::string &authorizedApp)
{
    MessageParcel reply;
    return SendRequestWithTwoStr(reply, AppAccountInterfaceCode::ENABLE_APP_ACCESS, name, authorizedApp);
}

ErrCode AppAccountProxy::DisableAppAccess(const std::string &name, const std::string &authorizedApp)
{
    MessageParcel reply;
    return SendRequestWithTwoStr(reply, AppAccountInterfaceCode::DISABLE_APP_ACCESS, name, authorizedApp);
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

    ErrCode result = SendRequest(AppAccountInterfaceCode::SET_APP_ACCESS, data, reply);
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
        ACCOUNT_LOGE("failed to write name for checking account sync flag");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    ErrCode result = SendRequest(AppAccountInterfaceCode::CHECK_APP_ACCOUNT_SYNC_ENABLE, data, reply);
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
        ACCOUNT_LOGE("failed to write name for enabling account sync flag");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    if (!data.WriteBool(syncEnable)) {
        ACCOUNT_LOGE("failed to write bool for syncEnable");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    ErrCode result = SendRequest(AppAccountInterfaceCode::SET_APP_ACCOUNT_SYNC_ENABLE, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();

    return result;
}

ErrCode AppAccountProxy::GetAssociatedData(const std::string &name, const std::string &key, std::string &value)
{
    MessageParcel reply;
    ErrCode result = SendRequestWithTwoStr(reply, AppAccountInterfaceCode::GET_ASSOCIATED_DATA, name, key);
    if (result != ERR_OK) {
        return result;
    }
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
        ACCOUNT_LOGE("failed to write name for set associated data");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    if (!data.WriteString(key)) {
        ACCOUNT_LOGE("failed to write string for key");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    if (!data.WriteString(value)) {
        ACCOUNT_LOGE("failed to write string for value");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    ErrCode result = SendRequest(AppAccountInterfaceCode::SET_ASSOCIATED_DATA, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();

    return result;
}

ErrCode AppAccountProxy::GetAccountCredential(
    const std::string &name, const std::string &credentialType, std::string &credential)
{
    MessageParcel reply;
    ErrCode result = SendRequestWithTwoStr(
        reply, AppAccountInterfaceCode::GET_ACCOUNT_CREDENTIAL, name, credentialType);
    if (result == ERR_OK) {
        credential = reply.ReadString();
    }
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
        ACCOUNT_LOGE("failed to write name for setting account credential");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    if (!data.WriteString(credentialType)) {
        ACCOUNT_LOGE("failed to write string for credentialType");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    if (!data.WriteString(credential)) {
        ACCOUNT_LOGE("failed to write string for credential");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    ErrCode result = SendRequest(AppAccountInterfaceCode::SET_ACCOUNT_CREDENTIAL, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();

    return result;
}

ErrCode AppAccountProxy::Authenticate(const std::string &name, const std::string &owner, const std::string &authType,
    const AAFwk::Want &options, const sptr<IAppAccountAuthenticatorCallback> &callback)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write name");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString(owner)) {
        ACCOUNT_LOGE("failed to write owner");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString(authType)) {
        ACCOUNT_LOGE("failed to write authType");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&options)) {
        ACCOUNT_LOGE("failed to write parcelable for options");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if ((callback != nullptr) && (!data.WriteRemoteObject(callback->AsObject()))) {
        ACCOUNT_LOGE("failed to write remote object for callback");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    ErrCode result = SendRequest(AppAccountInterfaceCode::AUTHENTICATE, data, reply);
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

    result = SendRequest(AppAccountInterfaceCode::GET_OAUTH_TOKEN, data, reply);
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

    result = SendRequest(AppAccountInterfaceCode::GET_AUTH_TOKEN, data, reply);
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
        ACCOUNT_LOGE("failed to write name for setting oauth token");
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
    ErrCode result = SendRequest(AppAccountInterfaceCode::SET_OAUTH_TOKEN, data, reply);
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

    result = SendRequest(AppAccountInterfaceCode::DELETE_OAUTH_TOKEN, data, reply);
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
    result = SendRequest(AppAccountInterfaceCode::DELETE_AUTH_TOKEN, data, reply);
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
    result = SendRequest(AppAccountInterfaceCode::SET_AUTH_TOKEN_VISIBILITY, data, reply);
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
    result = SendRequest(AppAccountInterfaceCode::SET_OAUTH_TOKEN_VISIBILITY, data, reply);
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

    result = SendRequest(AppAccountInterfaceCode::CHECK_AUTH_TOKEN_VISIBILITY, data, reply);
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

    result = SendRequest(AppAccountInterfaceCode::CHECK_OAUTH_TOKEN_VISIBILITY, data, reply);
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
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    ErrCode result = SendRequest(AppAccountInterfaceCode::GET_AUTHENTICATOR_INFO, data, reply);
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
    MessageParcel reply;
    ErrCode result = SendRequestWithTwoStr(reply, AppAccountInterfaceCode::GET_ALL_OAUTH_TOKENS, name, owner);
    if (result != ERR_OK) {
        return result;
    }
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

    result = SendRequest(AppAccountInterfaceCode::GET_OAUTH_LIST, data, reply);
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

    result = SendRequest(AppAccountInterfaceCode::GET_AUTH_LIST, data, reply);
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
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    ErrCode result = SendRequest(AppAccountInterfaceCode::GET_AUTHENTICATOR_CALLBACK, data, reply);
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
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    ErrCode result = SendRequest(AppAccountInterfaceCode::GET_ALL_ACCOUNTS, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();

    if (!ReadAppAccountList(reply, appAccounts)) {
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

    ErrCode result = SendRequest(AppAccountInterfaceCode::GET_ALL_ACCESSIBLE_ACCOUNTS, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();

    if (!ReadAppAccountList(reply, appAccounts)) {
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
    ErrCode result = SendRequest(AppAccountInterfaceCode::QUERY_ALL_ACCESSIBLE_ACCOUNTS, data, reply);
    if (result != ERR_OK) {
        return result;
    }
    result = reply.ReadInt32();
    if (!ReadAppAccountList(reply, appAccounts)) {
        ACCOUNT_LOGE("failed to read parcelable for AppAccountInfo");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    return result;
}

ErrCode AppAccountProxy::CheckAppAccess(
    const std::string &name, const std::string &authorizedApp, bool &isAccessible)
{
    MessageParcel reply;
    ErrCode result = SendRequestWithTwoStr(reply, AppAccountInterfaceCode::CHECK_APP_ACCESS, name, authorizedApp);
    if (result == ERR_OK) {
        isAccessible = reply.ReadBool();
    }
    return result;
}

ErrCode AppAccountProxy::DeleteAccountCredential(
    const std::string &name, const std::string &credentialType)
{
    MessageParcel reply;
    return SendRequestWithTwoStr(reply, AppAccountInterfaceCode::DELETE_ACCOUNT_CREDENTIAL, name, credentialType);
}

ErrCode AppAccountProxy::SelectAccountsByOptions(
    const SelectAccountsOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteParcelable(&options)) {
        ACCOUNT_LOGE("failed to write parcelable for options");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if ((callback != nullptr) && (!data.WriteRemoteObject(callback->AsObject()))) {
        ACCOUNT_LOGE("failed to write remote object for callback");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    MessageParcel reply;
    ErrCode result = SendRequest(AppAccountInterfaceCode::SELECT_ACCOUNTS_BY_OPTIONS, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to send request, errCode: %{public}d", result);
        return result;
    }
    return reply.ReadInt32();
}

ErrCode AppAccountProxy::VerifyCredential(const std::string &name, const std::string &owner,
    const VerifyCredentialOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString(owner)) {
        ACCOUNT_LOGE("failed to write string for owner");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&options)) {
        ACCOUNT_LOGE("failed to write string for options");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if ((callback != nullptr) && (!data.WriteRemoteObject(callback->AsObject()))) {
        ACCOUNT_LOGE("failed to write string for callback");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    MessageParcel reply;
    ErrCode result = SendRequest(AppAccountInterfaceCode::VERIFY_CREDENTIAL, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to send request, errCode: %{public}d", result);
        return result;
    }
    return reply.ReadInt32();
}

ErrCode AppAccountProxy::CheckAccountLabels(const std::string &name, const std::string &owner,
    const std::vector<std::string> &labels, const sptr<IAppAccountAuthenticatorCallback> &callback)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString(owner)) {
        ACCOUNT_LOGE("failed to write string for owner");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteStringVector(labels)) {
        ACCOUNT_LOGE("failed to write string vector for labels");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if ((callback != nullptr) && (!data.WriteRemoteObject(callback->AsObject()))) {
        ACCOUNT_LOGE("failed to write string for callback");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    MessageParcel reply;
    ErrCode result = SendRequest(AppAccountInterfaceCode::CHECK_ACCOUNT_LABELS, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to send request, errCode: %{public}d", result);
        return result;
    }
    return reply.ReadInt32();
}

ErrCode AppAccountProxy::SetAuthenticatorProperties(const std::string &owner,
    const SetPropertiesOptions &options, const sptr<IAppAccountAuthenticatorCallback> &callback)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteString(owner)) {
        ACCOUNT_LOGE("failed to write authenticator owner");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&options)) {
        ACCOUNT_LOGE("failed to write options");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if ((callback != nullptr) && (!data.WriteRemoteObject(callback->AsObject()))) {
        ACCOUNT_LOGE("failed to write remote object for callback");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    MessageParcel reply;
    ErrCode result = SendRequest(AppAccountInterfaceCode::SET_AUTHENTICATOR_PROPERTIES, data, reply);
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
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    if (!data.WriteRemoteObject(eventListener)) {
        ACCOUNT_LOGE("failed to write remote object for eventListener");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    ErrCode result = SendRequest(AppAccountInterfaceCode::SUBSCRIBE_ACCOUNT, data, reply);
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
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    ErrCode result = SendRequest(AppAccountInterfaceCode::UNSUBSCRIBE_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();

    return result;
}

ErrCode AppAccountProxy::SendRequest(AppAccountInterfaceCode code, MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCOUNT_LOGE("remote is nullptr, code = %{public}d", code);
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }

    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to send app account request, code = %{public}d, result = %{public}d", code, result);
        return ERR_APPACCOUNT_KIT_SEND_REQUEST;
    }

    return ERR_OK;
}

bool AppAccountProxy::ReadAppAccountList(MessageParcel &parcel, std::vector<AppAccountInfo> &accountList)
{
    accountList.clear();
    uint32_t size = 0;
    if (!parcel.ReadUint32(size)) {
        ACCOUNT_LOGE("fail to read the account list size");
        return false;
    }
    if (size > Constants::MAX_ALLOWED_ARRAY_SIZE_INPUT) {
        ACCOUNT_LOGE("the account list size is invalid");
        return false;
    }
    for (uint32_t index = 0; index < size; index++) {
        std::shared_ptr<AppAccountInfo> account(parcel.ReadParcelable<AppAccountInfo>());
        if (account == nullptr) {
            ACCOUNT_LOGE("failed to read app account info");
            return false;
        }
        accountList.emplace_back(*account);
    }

    return true;
}
}  // namespace AccountSA
}  // namespace OHOS
