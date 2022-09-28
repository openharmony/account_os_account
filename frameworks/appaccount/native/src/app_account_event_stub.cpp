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

#include "app_account_event_stub.h"

#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
AppAccountEventStub::AppAccountEventStub()
{}

AppAccountEventStub::~AppAccountEventStub()
{}

int AppAccountEventStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCOUNT_LOGE("failed to check descriptor! code %{public}u.", code);
        return ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
    }

    switch (code) {
        case static_cast<uint32_t>(IAppAccountEvent::Message::ACCOUNT_CHANGED): {
            std::vector<AppAccountInfo> accounts;
            if (!ReadParcelableVector(accounts, data)) {
                ACCOUNT_LOGE("failed to read parcelable vector for account info");
                if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_PARCELABLE_VECTOR_ACCOUNT_INFO)) {
                    ACCOUNT_LOGE("failed to write reply");
                    return IPC_STUB_WRITE_PARCEL_ERR;
                }
            }
            OnAccountsChanged(accounts);
            break;
        }
        default:
            ACCOUNT_LOGI("default, code = %{public}u, flags = %{public}u", code, option.GetFlags());
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }

    return ERR_NONE;
}

template<typename T>
bool AppAccountEventStub::ReadParcelableVector(std::vector<T> &parcelableVector, MessageParcel &data)
{
    uint32_t size = 0;
    if (!data.ReadUint32(size)) {
        ACCOUNT_LOGE("failed to ReadInt32 for size");
        return false;
    }

    parcelableVector.clear();
    for (uint32_t index = 0; index < size; index += 1) {
        std::shared_ptr<T> parcelable(data.ReadParcelable<T>());
        if (parcelable == nullptr) {
            ACCOUNT_LOGE("failed to ReadParcelable for T");
            return false;
        }
        parcelableVector.emplace_back(*parcelable);
    }

    return true;
}
}  // namespace AccountSA
}  // namespace OHOS
