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

#include "account_iam_client_callback_proxy.h"

#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
static ErrCode SendRequestFunc(
    const sptr<IRemoteObject> &remote, uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    if (remote == nullptr) {
        ACCOUNT_LOGE("remote is nullptr, code = %{public}d", code);
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to SendRequest, code = %{public}d, result = %{public}d", code, result);
        return ERR_ACCOUNT_IAM_KIT_SEND_REQUEST;
    }
    return ERR_OK;
}

static void OnResultFunc(const sptr<IRemoteObject> &remote, uint32_t code, std::u16string descriptor,
    int32_t result, const Attributes &extraInfo)
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(descriptor)) {
        ACCOUNT_LOGE("write descriptor fail");
        return;
    }
    if (!data.WriteInt32(result)) {
        ACCOUNT_LOGE("write result fail");
        return;
    }
    auto buffer = extraInfo.Serialize();
    if (!data.WriteUInt8Vector(buffer)) {
        ACCOUNT_LOGE("write buffer fail");
        return;
    }
    SendRequestFunc(remote, code, data, reply);
}

IDMCallbackProxy::IDMCallbackProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IIDMCallback>(object)
{}

void IDMCallbackProxy::OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo)
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("write descriptor fail");
        return;
    }
    if (!data.WriteInt32(module)) {
        ACCOUNT_LOGE("write module fail");
        return;
    }
    if (!data.WriteUint32(acquireInfo)) {
        ACCOUNT_LOGE("write acquireInfo fail");
        return;
    }
    auto buffer = extraInfo.Serialize();
    if (!data.WriteUInt8Vector(buffer)) {
        ACCOUNT_LOGE("write buffer fail");
        return;
    }
    uint32_t code = static_cast<uint32_t>(IIDMCallback::Message::ON_ACQUIRE_INFO);
    SendRequestFunc(Remote(), code, data, reply);
}

void IDMCallbackProxy::OnResult(int32_t result, const Attributes &extraInfo)
{
    uint32_t code = static_cast<uint32_t>(IIDMCallback::Message::ON_RESULT);
    OnResultFunc(Remote(), code, GetDescriptor(), result, extraInfo);
}

GetCredInfoCallbackProxy::GetCredInfoCallbackProxy(const sptr<IRemoteObject> &object)
    : IRemoteProxy<IGetCredInfoCallback>(object)
{}

void GetCredInfoCallbackProxy::OnCredentialInfo(const std::vector<CredentialInfo> &infoList)
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("write descriptor fail");
        return;
    }
    if (!data.WriteUint32(infoList.size())) {
        ACCOUNT_LOGE("write info size fail");
        return;
    }
    for (const auto &info : infoList) {
        if (!data.WriteUint64(info.credentialId)) {
            ACCOUNT_LOGE("write credentialId fail");
            return;
        }
        if (!data.WriteInt32(info.authType)) {
            ACCOUNT_LOGE("write authType fail");
            return;
        }
        PinSubType pinType = info.pinType.value_or(PinSubType::PIN_MAX);
        if (!data.WriteInt32(pinType)) {
            ACCOUNT_LOGE("write authSubType fail");
            return;
        }
        if (!data.WriteUint64(info.templateId)) {
            ACCOUNT_LOGE("write templateId fail");
            return;
        }
    }
    uint32_t code = static_cast<uint32_t>(IGetCredInfoCallback::Message::ON_CREDENTIAL_INFO);
    SendRequestFunc(Remote(), code, data, reply);
}

GetSetPropCallbackProxy::GetSetPropCallbackProxy(const sptr<IRemoteObject> &object)
    : IRemoteProxy<IGetSetPropCallback>(object)
{}

void GetSetPropCallbackProxy::OnResult(int32_t result, const Attributes &extraInfo)
{
    uint32_t code = static_cast<uint32_t>(IGetSetPropCallback::Message::ON_RESULT);
    OnResultFunc(Remote(), code, GetDescriptor(), result, extraInfo);
}
}  // namespace AccountSA
}  // namespace OHOS
