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

#include "account_iam_mgr_proxy.h"

#include "account_error_no.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
AccountIAMMgrProxy::AccountIAMMgrProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IAccountIAM>(object)
{}

AccountIAMMgrProxy::~AccountIAMMgrProxy()
{}

ErrCode AccountIAMMgrProxy::SendRequest(IAccountIAM::Message code, MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCOUNT_LOGE("remote is nullptr, code = %{public}d", code);
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to SendRequest, code = %{public}d, result = %{public}d", code, result);
    }
    return result;
}

bool AccountIAMMgrProxy::WriteCommonData(MessageParcel &data, int32_t userId)
{
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return false;
    }
    if (!data.WriteInt32(userId)) {
        ACCOUNT_LOGE("failed to write userId!");
        return false;
    }
    return true;
}

int32_t AccountIAMMgrProxy::OpenSession(int32_t userId, std::vector<uint8_t> &challenge)
{
    challenge.clear();
    MessageParcel data;
    if (!WriteCommonData(data, userId)) {
        return ERR_ACCOUNT_IAM_KIT_WRITE_PARCEL_FAIL;
    }
    MessageParcel reply;
    int32_t result = SendRequest(IAccountIAM::Message::OPEN_SESSION, data, reply);
    if (result != ERR_OK) {
        return result;
    }
    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGE("failed to read result");
        return ERR_ACCOUNT_IAM_KIT_READ_PARCEL_FAIL;
    }
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to open session, result: %{public}d", result);
        return result;
    }
    if (!reply.ReadUInt8Vector(&challenge)) {
        ACCOUNT_LOGE("failed to read challenge!");
        return ERR_ACCOUNT_IAM_KIT_READ_PARCEL_FAIL;
    }
    return ERR_OK;
}

int32_t AccountIAMMgrProxy::CloseSession(int32_t userId)
{
    MessageParcel data;
    if (!WriteCommonData(data, userId)) {
        return ERR_ACCOUNT_IAM_KIT_WRITE_PARCEL_FAIL;
    }
    MessageParcel reply;
    int32_t result = SendRequest(IAccountIAM::Message::CLOSE_SESSION, data, reply);
    if (result != ERR_OK) {
        return result;
    }
    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGE("failed to read result");
        return ERR_ACCOUNT_IAM_KIT_READ_PARCEL_FAIL;
    }
    return result;
}

void AccountIAMMgrProxy::AddOrUpdateCredential(
    int32_t userId, const CredentialParameters &credInfo, const sptr<IIDMCallback> &callback, bool isAdd)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return;
    }
    Attributes emptyResult;
    MessageParcel data;
    if (!WriteCommonData(data, userId)) {
        callback->OnResult(ERR_ACCOUNT_IAM_KIT_WRITE_PARCEL_FAIL, emptyResult);
        return;
    }
    if (!data.WriteInt32(credInfo.authType)) {
        ACCOUNT_LOGE("failed to write authType");
        callback->OnResult(ERR_ACCOUNT_IAM_KIT_WRITE_PARCEL_FAIL, emptyResult);
        return;
    }
    PinSubType pinType = credInfo.pinType.value_or(PinSubType::PIN_MAX);
    if (!data.WriteInt32(pinType)) {
        ACCOUNT_LOGE("failed to write pinType");
        callback->OnResult(ERR_ACCOUNT_IAM_KIT_WRITE_PARCEL_FAIL, emptyResult);
        return;
    }
    if (!data.WriteUInt8Vector(credInfo.token)) {
        ACCOUNT_LOGE("failed to write token");
        callback->OnResult(ERR_ACCOUNT_IAM_KIT_WRITE_PARCEL_FAIL, emptyResult);
        return;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        ACCOUNT_LOGE("failed to write callback");
        callback->OnResult(ERR_ACCOUNT_IAM_KIT_WRITE_PARCEL_FAIL, emptyResult);
        return;
    }
    MessageParcel reply;
    int32_t result;
    if (isAdd) {
        result = SendRequest(IAccountIAM::Message::ADD_CREDENTIAL, data, reply);
    } else {
        result = SendRequest(IAccountIAM::Message::UPDATE_CREDENTIAL, data, reply);
    }
    if (result != ERR_OK) {
        callback->OnResult(result, emptyResult);
    }
}

void AccountIAMMgrProxy::AddCredential(
    int32_t userId, const CredentialParameters &credInfo, const sptr<IIDMCallback> &callback)
{
    AddOrUpdateCredential(userId, credInfo, callback, true);
}

void AccountIAMMgrProxy::UpdateCredential(
    int32_t userId, const CredentialParameters &credInfo, const sptr<IIDMCallback> &callback)
{
    AddOrUpdateCredential(userId, credInfo, callback, false);
}

int32_t AccountIAMMgrProxy::Cancel(int32_t userId)
{
    MessageParcel data;
    if (!WriteCommonData(data, userId)) {
        return ERR_ACCOUNT_IAM_KIT_WRITE_PARCEL_FAIL;
    }
    MessageParcel reply;
    int32_t result = SendRequest(IAccountIAM::Message::CANCEL, data, reply);
    if (result != ERR_OK) {
        return result;
    }
    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGE("failed to read result");
        return ERR_ACCOUNT_IAM_KIT_READ_PARCEL_FAIL;
    }
    return result;
}

void AccountIAMMgrProxy::DelCred(
    int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken, const sptr<IIDMCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return;
    }
    Attributes emptyResult;
    MessageParcel data;
    if (!WriteCommonData(data, userId)) {
        callback->OnResult(ERR_ACCOUNT_IAM_KIT_WRITE_PARCEL_FAIL, emptyResult);
        return;
    }
    if (!data.WriteUint64(credentialId)) {
        ACCOUNT_LOGE("failed to write userId");
        callback->OnResult(ERR_ACCOUNT_IAM_KIT_WRITE_PARCEL_FAIL, emptyResult);
        return;
    }
    if (!data.WriteUInt8Vector(authToken)) {
        ACCOUNT_LOGE("failed to write token for DelCred");
        callback->OnResult(ERR_ACCOUNT_IAM_KIT_WRITE_PARCEL_FAIL, emptyResult);
        return;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        ACCOUNT_LOGE("failed to write callback for DelCred");
        callback->OnResult(ERR_ACCOUNT_IAM_KIT_WRITE_PARCEL_FAIL, emptyResult);
        return;
    }
    MessageParcel reply;
    int32_t result = SendRequest(IAccountIAM::Message::DEL_CRED, data, reply);
    if (result != ERR_OK) {
        callback->OnResult(result, emptyResult);
    }
}

void AccountIAMMgrProxy::DelUser(
    int32_t userId, const std::vector<uint8_t> &authToken, const sptr<IIDMCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return;
    }
    Attributes emptyResult;
    MessageParcel data;
    if (!WriteCommonData(data, userId)) {
        callback->OnResult(ERR_ACCOUNT_IAM_KIT_WRITE_PARCEL_FAIL, emptyResult);
        return;
    }
    if (!data.WriteUInt8Vector(authToken)) {
        ACCOUNT_LOGE("failed to write token for DelUser");
        callback->OnResult(ERR_ACCOUNT_IAM_KIT_WRITE_PARCEL_FAIL, emptyResult);
        return;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        ACCOUNT_LOGE("failed to write callback for DelUser");
        callback->OnResult(ERR_ACCOUNT_IAM_KIT_WRITE_PARCEL_FAIL, emptyResult);
        return;
    }
    MessageParcel reply;
    int32_t result = SendRequest(IAccountIAM::Message::DEL_USER, data, reply);
    if (result != ERR_OK) {
        callback->OnResult(result, emptyResult);
    }
}

int32_t AccountIAMMgrProxy::GetCredentialInfo(
    int32_t userId, AuthType authType, const sptr<IGetCredInfoCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return ERR_APPACCOUNT_KIT_INVALID_PARAMETER;
    }
    MessageParcel data;
    if (!WriteCommonData(data, userId)) {
        return ERR_ACCOUNT_IAM_KIT_WRITE_PARCEL_FAIL;
    }
    if (!data.WriteInt32(authType)) {
        ACCOUNT_LOGE("failed to write authType");
        return ERR_ACCOUNT_IAM_KIT_WRITE_PARCEL_FAIL;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        ACCOUNT_LOGE("failed to write callback");
        return ERR_ACCOUNT_IAM_KIT_WRITE_PARCEL_FAIL;
    }
    MessageParcel reply;
    int32_t result = SendRequest(IAccountIAM::Message::GET_CREDENTIAL_INFO, data, reply);
    if (result != ERR_OK) {
        return result;
    }
    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGE("failed to read result");
        return ERR_ACCOUNT_IAM_KIT_READ_PARCEL_FAIL;
    }
    return result;
}

uint64_t AccountIAMMgrProxy::AuthUser(int32_t userId, const std::vector<uint8_t> &challenge, AuthType authType,
    AuthTrustLevel authTrustLevel, const sptr<IIDMCallback> &callback)
{
    uint64_t contextId = 0;
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return contextId;
    }
    MessageParcel data;
    if (!WriteCommonData(data, userId)) {
        return contextId;
    }
    if (!data.WriteUInt8Vector(challenge)) {
        ACCOUNT_LOGE("failed to write challenge");
        return contextId;
    }
    if (!data.WriteInt32(authType)) {
        ACCOUNT_LOGE("failed to write authType");
        return contextId;
    }
    if (!data.WriteUint32(authTrustLevel)) {
        ACCOUNT_LOGE("failed to write authTrustLevel");
        return contextId;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        ACCOUNT_LOGE("failed to write callback");
        return contextId;
    }
    MessageParcel reply;
    if (SendRequest(IAccountIAM::Message::AUTH_USER, data, reply) != ERR_OK) {
        return contextId;
    }
    if (!reply.ReadUint64(contextId)) {
        ACCOUNT_LOGE("failed to read contextId");
    }
    return contextId;
}

int32_t AccountIAMMgrProxy::CancelAuth(uint64_t contextId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor");
        return ERR_ACCOUNT_IAM_KIT_WRITE_PARCEL_FAIL;
    }
    if (!data.WriteUint64(contextId)) {
        ACCOUNT_LOGE("failed to write contextId");
        return ERR_ACCOUNT_IAM_KIT_WRITE_PARCEL_FAIL;
    }
    MessageParcel reply;
    int32_t result = SendRequest(IAccountIAM::Message::CANCEL_AUTH, data, reply);
    if (result != ERR_OK) {
        return result;
    }
    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGE("failed to read result");
        return ERR_ACCOUNT_IAM_KIT_READ_PARCEL_FAIL;
    }
    return result;
}

int32_t AccountIAMMgrProxy::GetAvailableStatus(const AuthType authType, const AuthTrustLevel authTrustLevel,
    int32_t &status)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor");
        return ERR_ACCOUNT_IAM_KIT_WRITE_PARCEL_FAIL;
    }
    if (!data.WriteInt32(authType)) {
        ACCOUNT_LOGE("failed to write authType");
        return ERR_ACCOUNT_IAM_KIT_WRITE_PARCEL_FAIL;
    }
    if (!data.WriteUint32(authTrustLevel)) {
        ACCOUNT_LOGE("failed to write authTrustLevel");
        return ERR_ACCOUNT_IAM_KIT_WRITE_PARCEL_FAIL;
    }
    MessageParcel reply;
    int32_t res = SendRequest(IAccountIAM::Message::GET_AVAILABLE_STATUS, data, reply);
    if (res != ERR_OK) {
        return res;
    }
    if (!reply.ReadInt32(res)) {
        ACCOUNT_LOGE("failed to read result");
        return ERR_ACCOUNT_IAM_KIT_READ_PARCEL_FAIL;
    }
    if (res != ERR_OK) {
        ACCOUNT_LOGE("failed to get available status, result: %{public}d", res);
        return res;
    }
    if (!reply.ReadInt32(status)) {
        ACCOUNT_LOGE("failed to read status");
        return ERR_ACCOUNT_IAM_KIT_READ_PARCEL_FAIL;
    }
    return ERR_OK;
}

void AccountIAMMgrProxy::GetProperty(
    int32_t userId, const GetPropertyRequest &request, const sptr<IGetSetPropCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("get property callback is nullptr");
        return;
    }
    Attributes emptyResult;
    MessageParcel data;
    if (!WriteCommonData(data, userId)) {
        callback->OnResult(ERR_ACCOUNT_IAM_KIT_WRITE_PARCEL_FAIL, emptyResult);
        return;
    }
    if (!data.WriteInt32(request.authType)) {
        ACCOUNT_LOGE("failed to write authType for GetProperty");
        callback->OnResult(ERR_ACCOUNT_IAM_KIT_WRITE_PARCEL_FAIL, emptyResult);
        return;
    }
    std::vector<uint32_t> attrKeys;
    std::transform(request.keys.begin(), request.keys.end(), std::back_inserter(attrKeys),
        [](const auto &key) { return static_cast<uint32_t>(key); });

    if (!data.WriteUInt32Vector(attrKeys)) {
        ACCOUNT_LOGE("failed to write keys");
        callback->OnResult(ERR_ACCOUNT_IAM_KIT_WRITE_PARCEL_FAIL, emptyResult);
        return;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        ACCOUNT_LOGE("failed to write callback");
        callback->OnResult(ERR_ACCOUNT_IAM_KIT_WRITE_PARCEL_FAIL, emptyResult);
        return;
    }
    MessageParcel reply;
    int32_t result = SendRequest(IAccountIAM::Message::GET_PROPERTY, data, reply);
    if (result != ERR_OK) {
        callback->OnResult(result, emptyResult);
    }
}

void AccountIAMMgrProxy::SetProperty(
    int32_t userId, const SetPropertyRequest &request, const sptr<IGetSetPropCallback> &callback)
{
    if (callback == nullptr) {
        ACCOUNT_LOGE("set property callback is nullptr");
        return;
    }
    Attributes emptyResult;
    MessageParcel data;
    if (!WriteCommonData(data, userId)) {
        callback->OnResult(ERR_ACCOUNT_IAM_KIT_WRITE_PARCEL_FAIL, emptyResult);
        return;
    }
    if (!data.WriteInt32(request.authType)) {
        ACCOUNT_LOGE("failed to write authType for SetProperty");
        callback->OnResult(ERR_ACCOUNT_IAM_KIT_WRITE_PARCEL_FAIL, emptyResult);
        return;
    }
    auto buffer = request.attrs.Serialize();
    if (!data.WriteUInt8Vector(buffer)) {
        ACCOUNT_LOGE("failed to write attributes");
        callback->OnResult(ERR_ACCOUNT_IAM_KIT_WRITE_PARCEL_FAIL, emptyResult);
        return;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        ACCOUNT_LOGE("failed to write callback");
        callback->OnResult(ERR_ACCOUNT_IAM_KIT_WRITE_PARCEL_FAIL, emptyResult);
        return;
    }
    MessageParcel reply;
    int32_t result = SendRequest(IAccountIAM::Message::SET_PROPERTY, data, reply);
    if (result != ERR_OK) {
        callback->OnResult(result, emptyResult);
    }
}

IAMState AccountIAMMgrProxy::GetAccountState(int32_t userId)
{
    IAMState defaultState = IDLE;
    MessageParcel data;
    if (!WriteCommonData(data, userId)) {
        return defaultState;
    }
    MessageParcel reply;
    SendRequest(IAccountIAM::Message::GET_ACCOUNT_STATE, data, reply);
    int32_t state = defaultState;
    if (!reply.ReadInt32(state)) {
        ACCOUNT_LOGE("failed to read state");
    }
    return static_cast<IAMState>(state);
}
}  // namespace AccountSA
}  // namespace OHOS
