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

#include "account_error_no.h"
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
        return ERR_ACCOUNT_IAM_KIT_SEND_REQUEST;
    }
    return ERR_OK;
}

bool AccountIAMProxy::WriteCommonData(MessageParcel &data, int32_t userId)
{
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGD("failed to write descriptor!");
        return false;
    }
    if (!data.WriteInt32(userId)) {
        ACCOUNT_LOGD("failed to write userId!");
        return false;
    }
    return true;
}

void AccountIAMProxy::OpenSession(int32_t userId, std::vector<uint8_t> &challenge)
{
    challenge.clear();
    MessageParcel data;
    if (!WriteCommonData(data, userId)) {
        return;
    }
    MessageParcel reply;
    if (SendRequest(IAccountIAM::Message::OPEN_SESSION, data, reply) != ERR_OK) {
        return;
    }
    if (!reply.ReadUInt8Vector(&challenge)) {
        ACCOUNT_LOGD("failed to read challenge!");
    }
}

void AccountIAMProxy::CloseSession(int32_t userId)
{
    MessageParcel data;
    if (!WriteCommonData(data, userId)) {
        return;
    }
    MessageParcel reply;
    SendRequest(IAccountIAM::Message::CLOSE_SESSION, data, reply);
}

void AccountIAMProxy::AddOrUpdateCredential(
    int32_t userId, const CredentialParameters &credInfo, const sptr<IIDMCallback> &callback, bool isAdd)
{
    if (callback == nullptr) {
        ACCOUNT_LOGD("callback is nullptr");
        return;
    }
    MessageParcel data;
    if (!WriteCommonData(data, userId)) {
        return;
    }
    if (!data.WriteInt32(credInfo.authType)) {
        ACCOUNT_LOGD("failed to write authType");
        return;
    }
    PinSubType pinType = credInfo.pinType.value_or(PinSubType::PIN_MAX);
    if (!data.WriteInt32(pinType)) {
        ACCOUNT_LOGD("failed to write pinType");
        return;
    }
    if (!data.WriteUInt8Vector(credInfo.token)) {
        ACCOUNT_LOGD("failed to write token");
        return;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        ACCOUNT_LOGD("failed to write callback");
        return;
    }
    MessageParcel reply;
    if (isAdd) {
        SendRequest(IAccountIAM::Message::ADD_CREDENTIAL, data, reply);
    } else {
        SendRequest(IAccountIAM::Message::UPDATE_CREDENTIAL, data, reply);
    }
}

void AccountIAMProxy::AddCredential(
    int32_t userId, const CredentialParameters &credInfo, const sptr<IIDMCallback> &callback)
{
    AddOrUpdateCredential(userId, credInfo, callback, true);
}

void AccountIAMProxy::UpdateCredential(
    int32_t userId, const CredentialParameters &credInfo, const sptr<IIDMCallback> &callback)
{
    AddOrUpdateCredential(userId, credInfo, callback, false);
}

int32_t AccountIAMProxy::Cancel(int32_t userId, uint64_t challenge)
{
    MessageParcel data;
    int32_t result = ResultCode::FAIL;
    if (!WriteCommonData(data, userId)) {
        return result;
    }
    MessageParcel reply;
    if (SendRequest(IAccountIAM::Message::CANCEL, data, reply) != ERR_OK) {
        return result;
    }
    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGD("failed to read result");
    }
    return result;
}

void AccountIAMProxy::DelCred(
    int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken, const sptr<IIDMCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGD("callback is nullptr");
        return;
    }
    MessageParcel data;
    if (!WriteCommonData(data, userId)) {
        return;
    }
    if (!data.WriteUint64(credentialId)) {
        ACCOUNT_LOGD("failed to write userId");
        return;
    }
    if (!data.WriteUInt8Vector(authToken)) {
        ACCOUNT_LOGD("failed to write token");
        return;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        ACCOUNT_LOGD("failed to write callback");
        return;
    }
    MessageParcel reply;
    SendRequest(IAccountIAM::Message::DEL_CRED, data, reply);
}

void AccountIAMProxy::DelUser(int32_t userId, const std::vector<uint8_t> &authToken, const sptr<IIDMCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGD("callback is nullptr");
        return;
    }
    MessageParcel data;
    if (!WriteCommonData(data, userId)) {
        return;
    }
    if (!data.WriteUInt8Vector(authToken)) {
        ACCOUNT_LOGD("failed to write token");
        return;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        ACCOUNT_LOGD("failed to write callback");
        return;
    }
    MessageParcel reply;
    SendRequest(IAccountIAM::Message::DEL_USER, data, reply);
}

void AccountIAMProxy::GetCredentialInfo(
    int32_t userId, AuthType authType, const sptr<IGetCredInfoCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGD("callback is nullptr");
        return;
    }
    MessageParcel data;
    if (!WriteCommonData(data, userId)) {
        return;
    }
    if (!data.WriteInt32(authType)) {
        ACCOUNT_LOGD("failed to write authType");
        return;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        ACCOUNT_LOGD("failed to write callback");
        return;
    }
    MessageParcel reply;
    SendRequest(IAccountIAM::Message::GET_CREDENTIAL_INFO, data, reply);
}

uint64_t AccountIAMProxy::AuthUser(int32_t userId, const std::vector<uint8_t> &challenge, AuthType authType,
    AuthTrustLevel authTrustLevel, const sptr<IIDMCallback> &callback)
{
    uint64_t contextId = 0;
    if (callback == nullptr) {
        ACCOUNT_LOGD("callback is nullptr");
        return contextId;
    }
    MessageParcel data;
    if (!WriteCommonData(data, userId)) {
        return contextId;
    }
    if (!data.WriteUInt8Vector(challenge)) {
        ACCOUNT_LOGD("failed to write challenge");
        return contextId;
    }
    if (!data.WriteInt32(authType)) {
        ACCOUNT_LOGD("failed to write authType");
        return contextId;
    }
    if (!data.WriteUint32(authTrustLevel)) {
        ACCOUNT_LOGD("failed to write authTrustLevel");
        return contextId;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        ACCOUNT_LOGD("failed to write callback");
        return contextId;
    }
    MessageParcel reply;
    if (SendRequest(IAccountIAM::Message::AUTH_USER, data, reply) != ERR_OK) {
        return contextId;
    }
    if (!reply.ReadUint64(contextId)) {
        ACCOUNT_LOGD("failed to read contextId");
    }
    return contextId;
}

int32_t AccountIAMProxy::CancelAuth(uint64_t contextId)
{
    int32_t result = ResultCode::FAIL;
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGD("failed to write descriptor");
        return result;
    }
    if (!data.WriteUint64(contextId)) {
        ACCOUNT_LOGD("failed to write contextId");
        return result;
    }
    MessageParcel reply;
    if (SendRequest(IAccountIAM::Message::CANCEL_AUTH, data, reply) != ERR_OK) {
        return result;
    }
    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGD("failed to read result");
    }
    return result;
}

int32_t AccountIAMProxy::GetAvailableStatus(const AuthType authType, const AuthTrustLevel authTrustLevel)
{
    int32_t status = 0;
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGD("failed to write descriptor");
        return status;
    }
    if (!data.WriteInt32(authType)) {
        ACCOUNT_LOGD("failed to write authType");
        return status;
    }
    if (!data.WriteUint32(authTrustLevel)) {
        ACCOUNT_LOGD("failed to write authTrustLevel");
        return status;
    }
    MessageParcel reply;
    if (SendRequest(IAccountIAM::Message::GET_AVAILABLE_STATUS, data, reply) != ERR_OK) {
        return status;
    }
    if (!reply.ReadInt32(status)) {
        ACCOUNT_LOGD("failed to read status");
    }
    return status;
}

void AccountIAMProxy::GetProperty(
    int32_t userId, const GetPropertyRequest &request, const sptr<IGetSetPropCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGD("get property callback is nullptr");
        return;
    }
    MessageParcel data;
    if (!WriteCommonData(data, userId)) {
        return;
    }
    if (!data.WriteInt32(request.authType)) {
        ACCOUNT_LOGD("failed to write authType");
        return;
    }
    std::vector<uint32_t> attrKeys;
    for (const auto &key : request.keys) {
        attrKeys.push_back(static_cast<uint32_t>(key));
    }
    if (!data.WriteUInt32Vector(attrKeys)) {
        ACCOUNT_LOGD("failed to write keys");
        return;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        ACCOUNT_LOGD("failed to write callback");
        return;
    }
    MessageParcel reply;
    SendRequest(IAccountIAM::Message::GET_PROPERTY, data, reply);
}

void AccountIAMProxy::SetProperty(
    int32_t userId, const SetPropertyRequest &request, const sptr<IGetSetPropCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGD("set property callback is nullptr");
        return;
    }
    MessageParcel data;
    if (!WriteCommonData(data, userId)) {
        return;
    }
    if (!data.WriteInt32(request.authType)) {
        ACCOUNT_LOGD("failed to write authType");
        return;
    }
    auto buffer = request.attrs.Serialize();
    if (!data.WriteUInt8Vector(buffer)) {
        ACCOUNT_LOGD("failed to write attributes");
        return;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        ACCOUNT_LOGD("failed to write callback");
        return;
    }
    MessageParcel reply;
    SendRequest(IAccountIAM::Message::SET_PROPERTY, data, reply);
}

bool AccountIAMProxy::RegisterInputer(const sptr<IGetDataCallback> &inputer)
{
    bool result = false;
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGD("failed to write descriptor");
        return result;
    }
    if (!data.WriteRemoteObject(inputer->AsObject())) {
        ACCOUNT_LOGD("failed to write inputer");
        return result;
    }
    MessageParcel reply;
    if (SendRequest(IAccountIAM::Message::REGISTER_INPUTER, data, reply) != ERR_OK) {
        return result;
    }
    if (!reply.ReadBool(result)) {
        ACCOUNT_LOGD("failed to read result");
    }
    return result;
}

void AccountIAMProxy::UnRegisterInputer()
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGD("failed to write descriptor");
        return;
    }
    MessageParcel reply;
    SendRequest(IAccountIAM::Message::UNREGISTER_INPUTER, data, reply);
}
}  // namespace AccountSA
}  // namespace OHOS
