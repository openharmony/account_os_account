/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "app_account_authenticator_proxy.h"

#include "account_error_no.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
AppAccountAuthenticatorProxy::AppAccountAuthenticatorProxy(const sptr<IRemoteObject> &object)
    : IRemoteProxy<IAppAccountAuthenticator>(object)
{}

AppAccountAuthenticatorProxy::~AppAccountAuthenticatorProxy()
{}

ErrCode AppAccountAuthenticatorProxy::AddAccountImplicitly(const std::string &authType,
    const std::string &callerBundleName, const AAFwk::WantParams &options, const sptr<IRemoteObject> &callback)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteString(authType)) {
        ACCOUNT_LOGE("failed to write authType");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString(callerBundleName)) {
        ACCOUNT_LOGE("failed to write callerBundleName");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&options)) {
        ACCOUNT_LOGE("failed to write options");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callback)) {
        ACCOUNT_LOGE("failed to write callback");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    ErrCode result = SendRequest(AppAccountAuthenticatorInterfaceCode::ADD_ACCOUNT_IMPLICITLY, data, reply);
    if (result != ERR_OK) {
        return result;
    }
    return reply.ReadInt32();
}

ErrCode AppAccountAuthenticatorProxy::Authenticate(const std::string &name, const std::string &authType,
    const std::string &callerBundleName, const AAFwk::WantParams &options, const sptr<IRemoteObject> &callback)
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
    if (!data.WriteString(authType)) {
        ACCOUNT_LOGE("failed to write authType for authentication");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString(callerBundleName)) {
        ACCOUNT_LOGE("failed to write callerBundleName for authentication");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&options)) {
        ACCOUNT_LOGE("failed to write options for authentication");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callback)) {
        ACCOUNT_LOGE("failed to write callback for authentication");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    ErrCode result = SendRequest(AppAccountAuthenticatorInterfaceCode::AUTHENTICATE, data, reply);
    if (result != ERR_OK) {
        return result;
    }
    return reply.ReadInt32();
}

ErrCode AppAccountAuthenticatorProxy::CreateAccountImplicitly(
    const CreateAccountImplicitlyOptions &options, const sptr<IRemoteObject> &callback)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteParcelable(&options)) {
        ACCOUNT_LOGE("failed to write options");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callback)) {
        ACCOUNT_LOGE("failed to write callback");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    MessageParcel reply;
    ErrCode result = SendRequest(AppAccountAuthenticatorInterfaceCode::CREATE_ACCOUNT_IMPLICITLY, data, reply);
    if (result != ERR_OK) {
        return result;
    }
    return reply.ReadInt32();
}

ErrCode AppAccountAuthenticatorProxy::Auth(const std::string &name, const std::string &authType,
    const AAFwk::WantParams &options, const sptr<IRemoteObject> &callback)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write name");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString(authType)) {
        ACCOUNT_LOGE("failed to write authType");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&options)) {
        ACCOUNT_LOGE("failed to write options");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callback)) {
        ACCOUNT_LOGE("failed to write callback");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    MessageParcel reply;
    ErrCode result = SendRequest(AppAccountAuthenticatorInterfaceCode::AUTH, data, reply);
    if (result != ERR_OK) {
        return result;
    }
    return reply.ReadInt32();
}

ErrCode AppAccountAuthenticatorProxy::VerifyCredential(
    const std::string &name, const VerifyCredentialOptions &options, const sptr<IRemoteObject> &callback)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write WriteString name");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&options)) {
        ACCOUNT_LOGE("failed to write WriteParcelable options");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callback)) {
        ACCOUNT_LOGE("failed to write WriteString callback");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    ErrCode result = SendRequest(AppAccountAuthenticatorInterfaceCode::VERIFY_CREDENTIAL, data, reply);
    if (result != ERR_OK) {
        return result;
    }
    return reply.ReadInt32();
}

ErrCode AppAccountAuthenticatorProxy::CheckAccountLabels(
    const std::string &name, const std::vector<std::string> &labels, const sptr<IRemoteObject> &callback)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write WriteString name");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteStringVector(labels)) {
        ACCOUNT_LOGE("failed to write WriteStringVector labels");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callback)) {
        ACCOUNT_LOGE("failed to write WriteRemoteObject callback");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    ErrCode result = SendRequest(AppAccountAuthenticatorInterfaceCode::CHECK_ACCOUNT_LABELS, data, reply);
    if (result != ERR_OK) {
        return result;
    }
    return reply.ReadInt32();
}

ErrCode AppAccountAuthenticatorProxy::SetProperties(
    const SetPropertiesOptions &options, const sptr<IRemoteObject> &callback)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteParcelable(&options)) {
        ACCOUNT_LOGE("failed to write WriteParcelable options");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callback)) {
        ACCOUNT_LOGE("failed to write WriteString callback");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    ErrCode result = SendRequest(AppAccountAuthenticatorInterfaceCode::SET_PROPERTIES, data, reply);
    if (result != ERR_OK) {
        return result;
    }
    return reply.ReadInt32();
}

ErrCode AppAccountAuthenticatorProxy::IsAccountRemovable(const std::string &name, const sptr<IRemoteObject> &callback)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write WriteString name");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callback)) {
        ACCOUNT_LOGE("failed to write WriteRemoteObject callback");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    ErrCode result = SendRequest(AppAccountAuthenticatorInterfaceCode::IS_ACCOUNT_REMOVABLE, data, reply);
    if (result != ERR_OK) {
        return result;
    }
    return reply.ReadInt32();
}

ErrCode AppAccountAuthenticatorProxy::SendRequest(
    AppAccountAuthenticatorInterfaceCode code, MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> remoteAuthenticator = Remote();
    if (remoteAuthenticator == nullptr) {
        ACCOUNT_LOGE("remote is nullptr, code = %{public}d", code);
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = remoteAuthenticator->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to SendRequest, code = %{public}d, result = %{public}d", code, result);
        return ERR_APPACCOUNT_KIT_SEND_REQUEST;
    }
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS

