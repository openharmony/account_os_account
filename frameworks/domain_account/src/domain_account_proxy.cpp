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

#include "domain_account_proxy.h"

#include "account_error_no.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
DomainAccountProxy::DomainAccountProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IDomainAccount>(object)
{}

DomainAccountProxy::~DomainAccountProxy()
{}

ErrCode DomainAccountProxy::SendRequest(IDomainAccount::Message code, MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCOUNT_LOGE("remote is nullptr, code = %{public}d", code);
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    MessageOption option(MessageOption::TF_SYNC);
    return remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
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
    ErrCode result = SendRequest(IDomainAccount::Message::REGISTER_PLUGIN, data, reply);
    if (result != ERR_OK) {
        return result;
    }
    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGE("fail to read result");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    return result;
}

ErrCode DomainAccountProxy::UnregisterPlugin()
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("fail to write descriptor");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    MessageParcel reply;
    ErrCode result = SendRequest(IDomainAccount::Message::UNREGISTER_PLUGIN, data, reply);
    if (result != ERR_OK) {
        return result;
    }
    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGE("fail to read result");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    return result;
}

ErrCode DomainAccountProxy::Auth(const DomainAccountInfo &info, const std::vector<uint8_t> &password,
    const sptr<IDomainAuthCallback> &callback)
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
    if ((callback == nullptr) || (!data.WriteRemoteObject(callback->AsObject()))) {
        ACCOUNT_LOGE("fail to write callback");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    MessageParcel reply;
    ErrCode result = SendRequest(IDomainAccount::Message::DOMAIN_AUTH, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("fail to send request, error: %{public}d", result);
        return result;
    }
    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGE("fail to read result");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    return result;
}

ErrCode DomainAccountProxy::AuthUser(int32_t userId, const std::vector<uint8_t> &password,
    const sptr<IDomainAuthCallback> &callback)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("fail to write descriptor");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        ACCOUNT_LOGE("fail to write userId");
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
    ErrCode result = SendRequest(IDomainAccount::Message::DOMAIN_AUTH_USER, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("fail to send request, error: %{public}d", result);
        return result;
    }
    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGE("fail to read result");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    return result;
}
}  // namespace AccountSA
}  // namespace OHOS