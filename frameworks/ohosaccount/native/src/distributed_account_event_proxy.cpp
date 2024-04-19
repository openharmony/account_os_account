/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "account_log_wrapper.h"
#include "distributed_account_event_proxy.h"

namespace OHOS {
namespace AccountSA {
DistributedAccountEventProxy::DistributedAccountEventProxy(
    const sptr<IRemoteObject> &object) : IRemoteProxy<IDistributedAccountEvent>(object)
{}

DistributedAccountEventProxy::~DistributedAccountEventProxy()
{}

void DistributedAccountEventProxy::OnAccountsChanged(const DistributedAccountEventData &eventData)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed.");
        return;
    }

    if (!data.WriteParcelable(&eventData)) {
        ACCOUNT_LOGE("Write eventData failed, eventData.id=%{public}d.", eventData.id_);
        return;
    }

    ErrCode result = SendRequest(DistributedAccountEventInterfaceCode::ON_ACCOUNT_CHANGED, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest for account changed failed, result=%{public}d eventData.id=%{public}d.",
            result, eventData.id_);
        return;
    }
}

ErrCode DistributedAccountEventProxy::SendRequest(
    DistributedAccountEventInterfaceCode code, MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCOUNT_LOGE("Remote is nullptr, code=%{public}d.", code);
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }

    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Send distributed account event request failed, code=%{public}d result=%{public}d.",
            code, result);
    }
    return result;
}
}  // namespace AccountSA
}  // namespace OHOS
