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
#include "distributed_account_event_stub.h"

namespace OHOS {
namespace AccountSA {
DistributedAccountEventStub::DistributedAccountEventStub()
{}

DistributedAccountEventStub::~DistributedAccountEventStub()
{}

int DistributedAccountEventStub::OnRemoteRequest(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCOUNT_LOGE("Check descriptor failed, code=%{public}u.", code);
        return ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
    }

    switch (code) {
        case static_cast<uint32_t>(DistributedAccountEventInterfaceCode::ON_ACCOUNT_CHANGED) : {
            std::shared_ptr<DistributedAccountEventData> dataPtr(data.ReadParcelable<DistributedAccountEventData>());
            if (dataPtr == nullptr) {
                ACCOUNT_LOGE("Read subscribe data failed.");
                return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
            }
            DistributedAccountEventData eventData;
            eventData.id_ = dataPtr->id_;
            eventData.type_ = dataPtr->type_;
            OnAccountsChanged(eventData);
            break;
        }
        default:
            ACCOUNT_LOGE("Switch code failed, code=%{public}u, flags=%{public}u", code, option.GetFlags());
            return IPC_PROXY_INVALID_CODE_ERR;
    }

    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
