/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "domain_account_proxy.h"

#include "account_error_no.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
DomainAccountProxy::DomainAccountProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IDomainAccount>(object)
{}

DomainAccountProxy::~DomainAccountProxy()
{}

ErrCode DomainAccountProxy::SendRequest(DomainAccountInterfaceCode code, MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCOUNT_LOGE("remote is nullptr, code = %{public}d", code);
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    MessageOption option(MessageOption::TF_SYNC);
    ErrCode result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to send domain account request, error code: %{public}d.", result);
        return result;
    }
    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGE("fail to read result");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    return result;
}

ErrCode DomainAccountProxy::HasDomainAccount(
    const DomainAccountInfo &info, const sptr<IDomainAccountCallback> &callback)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteParcelable(&info)) {
        ACCOUNT_LOGE("fail to write parcelable");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if ((callback == nullptr) || (!data.WriteRemoteObject(callback->AsObject()))) {
        ACCOUNT_LOGE("fail to write callback");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    MessageParcel reply;
    return SendRequest(DomainAccountInterfaceCode::DOMAIN_HAS_DOMAIN_ACCOUNT, data, reply);
}

ErrCode DomainAccountProxy::RegisterPlugin(const sptr<IDomainAccountPlugin> &plugin)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("fail to write descriptor");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if ((plugin == nullptr) || (!data.WriteRemoteObject(plugin->AsObject()))) {
        ACCOUNT_LOGE("fail to write plugin");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    MessageParcel reply;
    return SendRequest(DomainAccountInterfaceCode::REGISTER_PLUGIN, data, reply);
}

ErrCode DomainAccountProxy::UnregisterPlugin()
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("fail to write descriptor");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    MessageParcel reply;
    return SendRequest(DomainAccountInterfaceCode::UNREGISTER_PLUGIN, data, reply);
}

ErrCode DomainAccountProxy::GetAccountStatus(const DomainAccountInfo &info, DomainAccountStatus &status)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("fail to write descriptor");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&info)) {
        ACCOUNT_LOGE("fail to write parcelable");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    MessageParcel reply;
    ErrCode result = SendRequest(DomainAccountInterfaceCode::DOMAIN_ACCOUNT_STATUS_ENQUIRY, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("fail to read result");
        return result;
    }
    int replyStatus;
    if (!reply.ReadInt32(replyStatus)) {
        ACCOUNT_LOGE("fail to read result");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    status = static_cast<DomainAccountStatus>(replyStatus);
    return ERR_OK;
}

ErrCode DomainAccountProxy::RegisterAccountStatusListener(const sptr<IDomainAccountCallback> &listener)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if ((listener == nullptr) || (!data.WriteRemoteObject(listener->AsObject()))) {
        ACCOUNT_LOGE("fail to write callback");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    MessageParcel reply;
    return SendRequest(DomainAccountInterfaceCode::DOMAIN_ACCOUNT_STATUS_LISTENER_REGISTER, data, reply);
}

ErrCode DomainAccountProxy::UnregisterAccountStatusListener(const sptr<IDomainAccountCallback> &listener)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if ((listener == nullptr) || (!data.WriteRemoteObject(listener->AsObject()))) {
        ACCOUNT_LOGE("fail to write callback");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    MessageParcel reply;
    return SendRequest(DomainAccountInterfaceCode::DOMAIN_ACCOUNT_STATUS_LISTENER_UNREGISTER, data, reply);
}

ErrCode DomainAccountProxy::Auth(
    const DomainAccountInfo &info, const std::vector<uint8_t> &password, const sptr<IDomainAccountCallback> &callback)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("fail to write descriptor");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString(info.accountName_)) {
        ACCOUNT_LOGE("fail to write name");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString(info.domain_)) {
        ACCOUNT_LOGE("fail to write domain");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteUInt8Vector(password)) {
        ACCOUNT_LOGE("fail to write password");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString(info.serverConfigId_)) {
        ACCOUNT_LOGE("Fail to write serverConfigId");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if ((callback == nullptr) || (!data.WriteRemoteObject(callback->AsObject()))) {
        ACCOUNT_LOGE("fail to write callback");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    MessageParcel reply;
    return SendRequest(DomainAccountInterfaceCode::DOMAIN_AUTH, data, reply);
}

ErrCode DomainAccountProxy::AuthUser(
    int32_t userId, const std::vector<uint8_t> &password, const sptr<IDomainAccountCallback> &callback)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("fail to write descriptor");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        ACCOUNT_LOGE("fail to write userId for authUser");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteUInt8Vector(password)) {
        ACCOUNT_LOGE("fail to write password");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if ((callback == nullptr) || (!data.WriteRemoteObject(callback->AsObject()))) {
        ACCOUNT_LOGE("fail to write callback");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    MessageParcel reply;
    return SendRequest(DomainAccountInterfaceCode::DOMAIN_AUTH_USER, data, reply);
}

ErrCode DomainAccountProxy::AuthWithPopup(int32_t userId, const sptr<IDomainAccountCallback> &callback)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("fail to write descriptor");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        ACCOUNT_LOGE("fail to write userId for authWithPopup");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if ((callback == nullptr) || (!data.WriteRemoteObject(callback->AsObject()))) {
        ACCOUNT_LOGE("fail to write callback");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    MessageParcel reply;
    return SendRequest(DomainAccountInterfaceCode::DOMAIN_AUTH_WITH_POPUP, data, reply);
}

ErrCode DomainAccountProxy::UpdateAccountToken(const DomainAccountInfo &info, const std::vector<uint8_t> &token)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("fail to write descriptor");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&info)) {
        ACCOUNT_LOGE("fail to write parcelable");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteUInt8Vector(token)) {
        ACCOUNT_LOGE("fail to write token");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    MessageParcel reply;
    return SendRequest(DomainAccountInterfaceCode::DOMAIN_UPDATE_ACCOUNT_TOKEN, data, reply);
}

ErrCode DomainAccountProxy::IsAuthenticationExpired(const DomainAccountInfo &info, bool &isExpired)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&info)) {
        ACCOUNT_LOGE("Write domainAccountInfo failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    MessageParcel reply;
    ErrCode result = SendRequest(DomainAccountInterfaceCode::DOMAIN_IS_AUTHENTICATION_EXPIRED, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    if (!reply.ReadBool(isExpired)) {
        ACCOUNT_LOGE("Read isExpired failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode DomainAccountProxy::SetAccountPolicy(const DomainAccountPolicy &policy)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    if (!data.WriteInt32(policy.authenicationValidityPeriod)) {
        ACCOUNT_LOGE("Write threshold failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    MessageParcel reply;
    return SendRequest(DomainAccountInterfaceCode::DOMAIN_SET_ACCOUNT_POLICY, data, reply);
}

ErrCode DomainAccountProxy::GetAccessToken(
    const DomainAccountInfo &info, const AAFwk::WantParams &parameters, const sptr<IDomainAccountCallback> &callback)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("fail to write descriptor");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&info)) {
        ACCOUNT_LOGE("fail to write info");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&parameters)) {
        ACCOUNT_LOGE("failed to write write parameters");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if ((callback == nullptr) || (!data.WriteRemoteObject(callback->AsObject()))) {
        ACCOUNT_LOGE("fail to write callback");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    MessageParcel reply;
    return SendRequest(DomainAccountInterfaceCode::DOMAIN_GET_ACCESS_TOKEN, data, reply);
}

ErrCode DomainAccountProxy::GetDomainAccountInfo(
    const DomainAccountInfo &info, const sptr<IDomainAccountCallback> &callback)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("fail to write descriptor");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&info)) {
        ACCOUNT_LOGE("fail to write accountInfo");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if ((callback == nullptr) || (!data.WriteRemoteObject(callback->AsObject()))) {
        ACCOUNT_LOGE("fail to write callback");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    MessageParcel reply;
    return SendRequest(DomainAccountInterfaceCode::DOMAIN_GET_ACCOUNT_INFO, data, reply);
}

ErrCode DomainAccountProxy::AddServerConfig(const std::string &parameters, DomainServerConfig &config)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Fail to write descriptor.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString(parameters)) {
        ACCOUNT_LOGE("Fail to write config.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    MessageParcel reply;
    ErrCode result = SendRequest(DomainAccountInterfaceCode::ADD_SERVER_CONFIG, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Result is error=%{public}d.", result);
        return result;
    }
    std::unique_ptr<DomainServerConfig> serverConfig(reply.ReadParcelable<DomainServerConfig>());
    if (serverConfig == nullptr) {
        ACCOUNT_LOGE("ReadParcelable domainServerConfig fail");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    config = *serverConfig;
    return ERR_OK;
}

ErrCode DomainAccountProxy::RemoveServerConfig(const std::string &configId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Fail to write descriptor.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString(configId)) {
        ACCOUNT_LOGE("Fail to write config.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    MessageParcel reply;
    ErrCode result = SendRequest(DomainAccountInterfaceCode::REMOVE_SERVER_CONFIG, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Result is error=%{public}d.", result);
    }
    return result;
}

ErrCode DomainAccountProxy::GetAccountServerConfig(const DomainAccountInfo &info, DomainServerConfig &config)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Fail to write descriptor.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&info)) {
        ACCOUNT_LOGE("Fail to write info.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    MessageParcel reply;
    ErrCode result = SendRequest(DomainAccountInterfaceCode::GET_ACCOUNT_SERVER_CONFIG, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Result is error=%{public}d.", result);
        return result;
    }
    std::unique_ptr<DomainServerConfig> serverConfig(reply.ReadParcelable<DomainServerConfig>());
    if (serverConfig == nullptr) {
        ACCOUNT_LOGE("ReadParcelable domainServerConfig fail");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    config = *serverConfig;
    return ERR_OK;
}

ErrCode DomainAccountProxy::UpdateAccountInfo(
    const DomainAccountInfo &oldAccountInfo, const DomainAccountInfo &newAccountInfo)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Fail to write descriptor");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&oldAccountInfo)) {
        ACCOUNT_LOGE("Fail to write oldAccountInfo");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&newAccountInfo)) {
        ACCOUNT_LOGE("Fail to write newAccountInfo");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    MessageParcel reply;
    return SendRequest(DomainAccountInterfaceCode::DOMAIN_UPDATE_ACCOUNT_INFO, data, reply);
}
} // namespace AccountSA
} // namespace OHOS