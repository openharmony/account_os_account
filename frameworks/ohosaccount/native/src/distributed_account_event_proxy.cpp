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

#include "distributed_account_event_proxy.h"
#include <thread>
#include "account_constants.h"
#include "account_log_wrapper.h"
#include "account_hisysevent_adapter.h"

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
        REPORT_OHOS_ACCOUNT_FAIL(eventData.id_, Constants::OPERATION_EVENT_PUBLISH,
            result, "Send OnAccountsChanged failed.");
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
    int32_t retryTimes = 0;
    int32_t result;
    MessageOption option(MessageOption::TF_SYNC);
    while (retryTimes < Constants::MAX_RETRY_TIMES) {
        result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
        if (result == ERR_OK || (result != Constants::E_IPC_ERROR &&
            result != Constants::E_IPC_SA_DIED)) {
            break;
        }
        retryTimes++;
        ACCOUNT_LOGE("Send distributed account event request failed, code=%{public}d, retryTimes=%{public}d",
            result, retryTimes);
        std::this_thread::sleep_for(std::chrono::milliseconds(Constants::DELAY_FOR_EXCEPTION));
    }
    return result;
}
}  // namespace AccountSA
}  // namespace OHOS
