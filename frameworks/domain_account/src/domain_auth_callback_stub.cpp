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

#include "domain_auth_callback_stub.h"

#include "account_log_wrapper.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AccountSA {
DomainAuthCallbackStub::DomainAuthCallbackStub()
{}

DomainAuthCallbackStub::~DomainAuthCallbackStub()
{}

const std::map<uint32_t, DomainAuthCallbackStub::DomainAuthCallbackStubFunc> DomainAuthCallbackStub::stubFuncMap_ = {
    {
        IDomainAuthCallback::Message::DOMAIN_AUTH_ON_RESULT,
        &DomainAuthCallbackStub::ProcOnResult
    }
};

int32_t DomainAuthCallbackStub::OnRemoteRequest(
    std::uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    ACCOUNT_LOGD("Received stub message: %{public}d, callingUid: %{public}d", code, IPCSkeleton::GetCallingUid());
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCOUNT_LOGE("check descriptor failed! code %{public}u.", code);
        return ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
    }
    const auto &itFunc = stubFuncMap_.find(code);
    if (itFunc != stubFuncMap_.end()) {
        return (this->*(itFunc->second))(data, reply);
    }
    ACCOUNT_LOGW("remote request unhandled: %{public}d", code);
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

ErrCode DomainAuthCallbackStub::ProcOnResult(MessageParcel &data, MessageParcel &reply)
{
    int32_t resultCode;
    if (!data.ReadInt32(resultCode)) {
        ACCOUNT_LOGE("failed to read result code");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    DomainAuthResult result;
    if (!data.ReadUInt8Vector(&result.token)) {
        ACCOUNT_LOGE("failed to read token");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (!data.ReadInt32(result.authProperty.remainingTimes)) {
        ACCOUNT_LOGE("failed to read remaining times");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (!data.ReadInt32(result.authProperty.freezingTime)) {
        ACCOUNT_LOGE("failed to read freezing time");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    OnResult(resultCode, result);
    return ERR_NONE;
}
}  // namespace AccountSA
}  // namespace OHOS
