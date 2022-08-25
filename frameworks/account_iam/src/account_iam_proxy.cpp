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

#include "account_iam_proxy.h"

#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
AccountIAMProxy::AccountIAMProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IAccountIAM>(object)
{}

AccountIAMProxy::~AccountIAMProxy()
{}

ErrCode AccountIAMProxy::SendRequest(IAccountIAM::Message code, MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCOUNT_LOGD("remote is nullptr, code = %{public}d", code);
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != ERR_OK) {
        ACCOUNT_LOGD("failed to SendRequest, code = %{public}d, result = %{public}d", code, result);
        return ERR_ACCOUNT_IAM_SEND_REQUEST;
    }
    return ERR_OK;
}

ErrCode AccountIAMProxy::ActivateUserKey(
    int32_t userId, const std::vector<uint8_t> &token, const std::vector<uint8_t> &secret)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGD("failed to write descriptor for activating user key!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        ACCOUNT_LOGD("failed to write userId for activating user key!");
        return ERR_ACCOUNT_IAM_WRITE_USER_ID;
    }
    if (!data.WriteUInt8Vector(token)) {
        ACCOUNT_LOGD("failed to write token for activating user key!");
        return ERR_ACCOUNT_IAM_WRITE_TOKEN;
    }
    if (!data.WriteUInt8Vector(secret)) {
        ACCOUNT_LOGD("failed to write secret for activating user key!");
        return ERR_ACCOUNT_IAM_WRITE_SECRET;
    }
    MessageParcel reply;
    ErrCode result = SendRequest(IAccountIAM::Message::ACTIVATE_USER_KEY, data, reply);
    if (result != ERR_OK) {
        return result;
    }
    result = reply.ReadInt32();
    ACCOUNT_LOGD("result: %{public}d", result);
    return result;
}

ErrCode AccountIAMProxy::UpdateUserKey(int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &token,
    const std::vector<uint8_t> &newSecret)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGD("failed to write descriptor for updating user key!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        ACCOUNT_LOGD("failed to write userId for updating user key!");
        return ERR_ACCOUNT_IAM_WRITE_USER_ID;
    }
    if (!data.WriteUint64(credentialId)) {
        ACCOUNT_LOGD("failed to write credentialId for updating user key!");
        return ERR_ACCOUNT_IAM_WRITE_CREDENTIAL_ID;
    }
    if (!data.WriteUInt8Vector(token)) {
        ACCOUNT_LOGD("failed to write token for updating user key!");
        return ERR_ACCOUNT_IAM_WRITE_TOKEN;
    }
    if (!data.WriteUInt8Vector(newSecret)) {
        ACCOUNT_LOGD("failed to write secret for updating user key!");
        return ERR_ACCOUNT_IAM_WRITE_SECRET;
    }
    MessageParcel reply;
    ErrCode result = SendRequest(IAccountIAM::Message::UPDATE_USER_KEY, data, reply);
    if (result != ERR_OK) {
        return result;
    }
    result = reply.ReadInt32();
    return result;
}

ErrCode AccountIAMProxy::RemoveUserKey(int32_t userId, const std::vector<uint8_t> &token)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGD("failed to write descriptor for removing user key!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        ACCOUNT_LOGD("failed to write userId for removing user key!");
        return ERR_ACCOUNT_IAM_WRITE_USER_ID;
    }
    if (!data.WriteUInt8Vector(token)) {
        ACCOUNT_LOGD("failed to write token for removing user key!");
        return ERR_ACCOUNT_IAM_WRITE_TOKEN;
    }
    MessageParcel reply;
    ErrCode result = SendRequest(IAccountIAM::Message::REMOVE_USER_KEY, data, reply);
    if (result != ERR_OK) {
        return result;
    }
    result = reply.ReadInt32();
    return result;
}

ErrCode AccountIAMProxy::RestoreUserKey(int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &token)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGD("failed to write descriptor for restoring user key!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        ACCOUNT_LOGD("failed to write userId for restoring user key!");
        return ERR_ACCOUNT_IAM_WRITE_USER_ID;
    }
    if (!data.WriteUint64(credentialId)) {
        ACCOUNT_LOGD("failed to write credentialId for restoring user key!");
        return ERR_ACCOUNT_IAM_WRITE_CREDENTIAL_ID;
    }
    if (!data.WriteUInt8Vector(token)) {
        ACCOUNT_LOGD("failed to write token for restoring user key!");
        return ERR_ACCOUNT_IAM_WRITE_TOKEN;
    }
    MessageParcel reply;
    ErrCode result = SendRequest(IAccountIAM::Message::RESTORE_USER_KEY, data, reply);
    if (result != ERR_OK) {
        return result;
    }
    result = reply.ReadInt32();
    return result;
}
}  // namespace AccountSA
}  // OHOS