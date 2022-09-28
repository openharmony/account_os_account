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

#include "account_iam_callback_stub.h"

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AccountSA {
const std::map<uint32_t, IDMCallbackStub::MessageProcFunction> IDMCallbackStub::messageProcMap_ = {
    {
        static_cast<uint32_t>(IIDMCallback::Message::ON_ACQUIRE_INFO),
        &IDMCallbackStub::ProcOnAcquireInfo
    },
    {
        static_cast<uint32_t>(IIDMCallback::Message::ON_RESULT),
        &IDMCallbackStub::ProcOnResult
    }
};

int IDMCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    ACCOUNT_LOGD("Received stub message: %{public}d, callingUid: %{public}d, callingPid: %{public}d",
        code, IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingPid());
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCOUNT_LOGE("check IDMCallbackStub descriptor failed! code %{public}u.", code);
        return ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
    }
    const auto &itFunc = messageProcMap_.find(code);
    if (itFunc != messageProcMap_.end()) {
        return (this->*(itFunc->second))(data, reply);
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
        return ERR_ACCOUNT_IAM_KIT_READ_PARCEL_FAIL;
    }
    if (!data.ReadInt32(acquireInfo)) {
        ACCOUNT_LOGE("failed to read acquireInfo");
        return ERR_ACCOUNT_IAM_KIT_READ_PARCEL_FAIL;
    }
    if (!data.ReadUInt8Vector(&buffer)) {
        ACCOUNT_LOGE("failed to read buffer");
        return ERR_ACCOUNT_IAM_KIT_READ_PARCEL_FAIL;
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
        return ERR_ACCOUNT_IAM_KIT_READ_PARCEL_FAIL;
    }
    std::vector<uint8_t> buffer;
    if (!data.ReadUInt8Vector(&buffer)) {
        ACCOUNT_LOGE("failed to read result for IDMCallback OnResult");
        return ERR_ACCOUNT_IAM_KIT_READ_PARCEL_FAIL;
    }
    Attributes extraInfo(buffer);
    OnResult(result, extraInfo);
    return ERR_OK;
}

const std::map<uint32_t, GetCredInfoCallbackStub::MessageProcFunction>
    GetCredInfoCallbackStub::messageProcMap_ = {
    {
        static_cast<uint32_t>(IGetCredInfoCallback::Message::ON_CREDENTIAL_INFO),
        &GetCredInfoCallbackStub::ProcOnCredentialInfo
    }
};

int GetCredInfoCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    ACCOUNT_LOGD("Received stub message: %{public}d, callingUid: %{public}d, callingPid: %{public}d",
        code, IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingPid());
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCOUNT_LOGE("check GetCredInfoCallbackStub descriptor failed! code %{public}u.", code);
        return ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
    }
    const auto &itFunc = messageProcMap_.find(code);
    if (itFunc != messageProcMap_.end()) {
        return (this->*(itFunc->second))(data, reply);
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
        return ERR_ACCOUNT_IAM_KIT_READ_PARCEL_FAIL;
    }
    for (uint32_t i = 0; i < vectorSize; ++i) {
        CredentialInfo info;
        int32_t authType = 0;
        int32_t pinType = 0;
        if (!data.ReadUint64(info.credentialId)) {
            ACCOUNT_LOGE("failed to read credentialId");
            return ERR_ACCOUNT_IAM_KIT_READ_PARCEL_FAIL;
        }
        if (!data.ReadInt32(authType)) {
            ACCOUNT_LOGE("failed to read authType");
            return ERR_ACCOUNT_IAM_KIT_READ_PARCEL_FAIL;
        }
        if (!data.ReadInt32(pinType)) {
            ACCOUNT_LOGE("failed to read pinSubType");
            return ERR_ACCOUNT_IAM_KIT_READ_PARCEL_FAIL;
        }
        if (!data.ReadUint64(info.templateId)) {
            ACCOUNT_LOGE("failed to read templateId");
            return ERR_ACCOUNT_IAM_KIT_READ_PARCEL_FAIL;
        }
        info.authType = static_cast<AuthType>(authType);
        info.pinType = static_cast<PinSubType>(pinType);
        infoList.push_back(info);
    }
    OnCredentialInfo(infoList);
    return ERR_OK;
}

const std::map<uint32_t, GetSetPropCallbackStub::MessageProcFunction> GetSetPropCallbackStub::messageProcMap_ = {
    {
        static_cast<uint32_t>(IGetSetPropCallback::Message::ON_RESULT),
        &GetSetPropCallbackStub::ProcOnResult
    }
};

int GetSetPropCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    ACCOUNT_LOGD("Received stub message: %{public}d, callingUid: %{public}d, callingPid: %{public}d",
        code, IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingPid());
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCOUNT_LOGE("check GetSetPropCallbackStub descriptor failed! code %{public}u.", code);
        return ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
    }
    const auto &itFunc = messageProcMap_.find(code);
    if (itFunc != messageProcMap_.end()) {
        return (this->*(itFunc->second))(data, reply);
    }
    ACCOUNT_LOGW("remote request unhandled: %{public}d", code);
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

ErrCode GetSetPropCallbackStub::ProcOnResult(MessageParcel &data, MessageParcel &reply)
{
    int32_t result;
    if (!data.ReadInt32(result)) {
        ACCOUNT_LOGE("failed to read result for GetSetPropCallback OnResult");
        return ERR_ACCOUNT_IAM_KIT_READ_PARCEL_FAIL;
    }
    std::vector<uint8_t> buffer;
    if (!data.ReadUInt8Vector(&buffer)) {
        ACCOUNT_LOGE("failed to read result for GetSetPropCallback OnResult");
        return ERR_ACCOUNT_IAM_KIT_READ_PARCEL_FAIL;
    }
    Attributes extraInfo(buffer);
    OnResult(result, extraInfo);
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
