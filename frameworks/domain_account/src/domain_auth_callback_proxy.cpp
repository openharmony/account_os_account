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

#include "domain_auth_callback_proxy.h"

#include "account_error_no.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
DomainAuthCallbackProxy::DomainAuthCallbackProxy(const sptr<IRemoteObject> &object)
    : IRemoteProxy<IDomainAuthCallback>(object)
{}

DomainAuthCallbackProxy::~DomainAuthCallbackProxy()
{}

ErrCode DomainAuthCallbackProxy::SendRequest(IDomainAuthCallback::Message code, MessageParcel &data)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCOUNT_LOGE("remote is nullptr, code = %{public}d", code);
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    return remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
}

void DomainAuthCallbackProxy::OnResult(int32_t resultCode, const DomainAuthResult &result)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("fail to write descriptor");
        return;
    }
    if (!data.WriteInt32(resultCode)) {
        ACCOUNT_LOGE("fail to write result code");
        return;
    }
    if (!data.WriteUInt8Vector(result.token)) {
        ACCOUNT_LOGE("fail to write token");
        return;
    }
    if (!data.WriteInt32(result.authProperty.remainingTimes)) {
        ACCOUNT_LOGE("fail to write remaining times");
        return;
    }
    if (!data.WriteInt32(result.authProperty.freezingTime)) {
        ACCOUNT_LOGE("fail to write freezing time");
        return;
    }
    ErrCode errCode = SendRequest(IDomainAuthCallback::Message::DOMAIN_AUTH_ON_RESULT, data);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("fail to send request, error code: %{public}d", errCode);
    }
}
}  // namespace AccountSA
}  // namespace OHOS
