/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "os_account_event_stub.h"

namespace OHOS {
namespace AccountSA {
OsAccountEventStub::OsAccountEventStub()
{}

OsAccountEventStub::~OsAccountEventStub()
{}

int OsAccountEventStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCOUNT_LOGE("check descriptor failed! code %{public}u.", code);
        return ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
    }

    switch (code) {
        case static_cast<uint32_t>(IOsAccountEvent::Message::ACCOUNT_CHANGED): {
            int id;
            if (!data.ReadInt32(id)) {
                ACCOUNT_LOGE("failed to read localId");
                return ERR_OSACCOUNT_KIT_READ_IN_LOCAL_ID_ERROR;
            }
            OnAccountsChanged(id);
            break;
        }
        default:
            ACCOUNT_LOGI("default, code = %{public}u, flags = %{public}u", code, option.GetFlags());
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }

    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
