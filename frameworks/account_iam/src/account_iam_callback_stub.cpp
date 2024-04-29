/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "account_iam_callback_stub.h"

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AccountSA {
namespace {
constexpr uint32_t MAX_VEC_SIZE = 1024;
}

int IDMCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    ACCOUNT_LOGD("Received stub message: %{public}d, callingUid: %{public}d, callingPid: %{public}d",
        code, IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingPid());
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCOUNT_LOGE("check IDMCallbackStub descriptor failed! code %{public}u.", code);
        return ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
    }
    switch (code) {
        case static_cast<uint32_t>(IDMCallbackInterfaceCode::ON_ACQUIRE_INFO):
            return ProcOnAcquireInfo(data, reply);
        case static_cast<uint32_t>(IDMCallbackInterfaceCode::ON_RESULT):
            return ProcOnResult(data, reply);
        default:
            break;
    }
    ACCOUNT_LOGW("remote request unhandled: %{public}d", code);
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

ErrCode IDMCallbackStub::ProcOnAcquireInfo(MessageParcel &data, MessageParcel &reply)
{
    int32_t module;
    int32_t acquireInfo;
    std::vector<uint8_t> buffer;
    if (!data.ReadInt32(module)) {
        ACCOUNT_LOGE("failed to read module");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (!data.ReadInt32(acquireInfo)) {
        ACCOUNT_LOGE("failed to read acquireInfo");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (!data.ReadUInt8Vector(&buffer)) {
        ACCOUNT_LOGE("failed to read buffer");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    Attributes extraInfo(buffer);
    OnAcquireInfo(module, acquireInfo, extraInfo);
    return ERR_OK;
}

ErrCode IDMCallbackStub::ProcOnResult(MessageParcel &data, MessageParcel &reply)
{
    int32_t result;
    if (!data.ReadInt32(result)) {
        ACCOUNT_LOGE("failed to read result for IDMCallback OnResult");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::vector<uint8_t> buffer;
    if (!data.ReadUInt8Vector(&buffer)) {
        ACCOUNT_LOGE("failed to read result for IDMCallback OnResult");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    Attributes extraInfo(buffer);
    OnResult(result, extraInfo);
    return ERR_OK;
}

int GetCredInfoCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    ACCOUNT_LOGD("Received stub message: %{public}d, callingUid: %{public}d, callingPid: %{public}d",
        code, IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingPid());
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCOUNT_LOGE("check GetCredInfoCallbackStub descriptor failed! code %{public}u.", code);
        return ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
    }
    switch (code) {
        case static_cast<uint32_t>(GetCredInfoCallbackInterfaceCode::ON_CREDENTIAL_INFO):
            return ProcOnCredentialInfo(data, reply);
        default:
            break;
    }
    ACCOUNT_LOGW("remote request unhandled: %{public}d", code);
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

ErrCode GetCredInfoCallbackStub::ProcOnCredentialInfo(MessageParcel &data, MessageParcel &reply)
{
    uint32_t vectorSize = 0;
    std::vector<CredentialInfo> infoList;
    if (!data.ReadUint32(vectorSize)) {
        ACCOUNT_LOGE("read size fail");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (vectorSize > MAX_VEC_SIZE) {
        ACCOUNT_LOGE("credential info list is oversize, the limit is %{public}d", MAX_VEC_SIZE);
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    for (uint32_t i = 0; i < vectorSize; ++i) {
        CredentialInfo info;
        int32_t authType = 0;
        int32_t pinType = 0;
        if (!data.ReadUint64(info.credentialId)) {
            ACCOUNT_LOGE("failed to read credentialId");
            return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
        }
        if (!data.ReadInt32(authType)) {
            ACCOUNT_LOGE("failed to read authType");
            return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
        }
        if (!data.ReadInt32(pinType)) {
            ACCOUNT_LOGE("failed to read pinSubType");
            return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
        }
        if (!data.ReadUint64(info.templateId)) {
            ACCOUNT_LOGE("failed to read templateId");
            return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
        }
        info.authType = static_cast<AuthType>(authType);
        info.pinType = static_cast<PinSubType>(pinType);
        infoList.push_back(info);
    }
    OnCredentialInfo(infoList);
    return ERR_OK;
}

int GetSetPropCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    ACCOUNT_LOGD("Received stub message: %{public}d, callingUid: %{public}d, callingPid: %{public}d",
        code, IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingPid());
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCOUNT_LOGE("check GetSetPropCallbackStub descriptor failed! code %{public}u.", code);
        return ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
    }
    switch (code) {
        case static_cast<uint32_t>(GetSetPropCallbackInterfaceCode::ON_RESULT):
            return ProcOnResult(data, reply);
        default:
            break;
    }
    ACCOUNT_LOGW("remote request unhandled: %{public}d", code);
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

ErrCode GetSetPropCallbackStub::ProcOnResult(MessageParcel &data, MessageParcel &reply)
{
    int32_t result;
    if (!data.ReadInt32(result)) {
        ACCOUNT_LOGE("failed to read result for GetSetPropCallback OnResult");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::vector<uint8_t> buffer;
    if (!data.ReadUInt8Vector(&buffer)) {
        ACCOUNT_LOGE("failed to read result for GetSetPropCallback OnResult");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    Attributes extraInfo(buffer);
    OnResult(result, extraInfo);
    return ERR_OK;
}

int GetEnrolledIdCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    ACCOUNT_LOGD("Received stub message: %{public}d, callingUid: %{public}d, callingPid: %{public}d",
        code, IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingPid());
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCOUNT_LOGE("Check GetCredInfoCallbackStub descriptor failed! code %{public}u.", code);
        return ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
    }
    switch (code) {
        case static_cast<uint32_t>(GetEnrolledIdCallbackInterfaceCode::ON_ENROLLED_ID):
            return ProcOnEnrolledId(data, reply);
        default:
            break;
    }
    ACCOUNT_LOGW("Remote request unhandled: %{public}d", code);
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

ErrCode GetEnrolledIdCallbackStub::ProcOnEnrolledId(MessageParcel &data, MessageParcel &reply)
{
    int32_t result;
    if (!data.ReadInt32(result)) {
        ACCOUNT_LOGE("Failed to read result");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    uint64_t enrolledId;
    if (!data.ReadUint64(enrolledId)) {
        ACCOUNT_LOGE("Failed to read enrolledId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    OnEnrolledId(result, enrolledId);
    return ERR_OK;
}

int PreRemoteAuthCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    ACCOUNT_LOGD("Received stub message: %{public}d, callingUid: %{public}d, callingPid: %{public}d",
        code, IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingPid());
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCOUNT_LOGE("Check PreRemoteAuthCallbackStub descriptor failed, code=%{public}u.", code);
        return ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
    }
    switch (code) {
        case static_cast<uint32_t>(PreRemoteAuthCallbackInterfaceCode::ON_RESULT):
            return ProcOnResult(data, reply);
        default:
            break;
    }
    ACCOUNT_LOGW("Remote request unhandled: %{public}d.", code);
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

ErrCode PreRemoteAuthCallbackStub::ProcOnResult(MessageParcel &data, MessageParcel &reply)
{
    int32_t result;
    if (!data.ReadInt32(result)) {
        ACCOUNT_LOGE("Read result for PreRemoteAuthCallbackStub OnResult failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    OnResult(result);
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
