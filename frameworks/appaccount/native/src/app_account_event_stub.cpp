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
        case static_cast<uint32_t>(AppAccountEventInterfaceCode::ACCOUNT_CHANGED):
            return ProcOnAccountsChanged(data);
        default:
            ACCOUNT_LOGI("default, code = %{public}u, flags = %{public}u", code, option.GetFlags());
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }

    return ERR_NONE;
}

ErrCode AppAccountEventStub::ProcOnAccountsChanged(MessageParcel &data)
{
    uint32_t size = 0;
    if (!data.ReadUint32(size)) {
        ACCOUNT_LOGE("failed to the account list size");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }

    if (size > Constants::MAX_ALLOWED_ARRAY_SIZE_INPUT) {
        ACCOUNT_LOGE("ReadAppAccountList failed");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::vector<AppAccountInfo> accounts;
    for (uint32_t index = 0; index < size; index++) {
        std::shared_ptr<AppAccountInfo> account(data.ReadParcelable<AppAccountInfo>());
        if (account == nullptr) {
            ACCOUNT_LOGE("failed read app account info");
            return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
        }
        accounts.emplace_back(*account);
    }
    OnAccountsChanged(accounts);
    return ERR_NONE;
}
}  // namespace AccountSA
}  // namespace OHOS
