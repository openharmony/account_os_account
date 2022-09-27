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

#include "app_account_event_proxy.h"

#include "account_error_no.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
AppAccountEventProxy::AppAccountEventProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IAppAccountEvent>(object)
{}

AppAccountEventProxy::~AppAccountEventProxy()
{}

void AppAccountEventProxy::OnAccountsChanged(const std::vector<AppAccountInfo> &accounts)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return;
    }

    if (!WriteParcelableVector(accounts, data)) {
        ACCOUNT_LOGE("failed to write WriteVector accounts");
        return;
    }

    ErrCode result = SendRequest(IAppAccountEvent::Message::ACCOUNT_CHANGED, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest failed! error code %{public}d.", result);
        return;
    }
}

ErrCode AppAccountEventProxy::SendRequest(IAppAccountEvent::Message code, MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> remoteEvent = Remote();
    if (remoteEvent == nullptr) {
        ACCOUNT_LOGE("remote is nullptr, code = %{public}d", code);
        return ERR_APPACCOUNT_KIT_REMOTE_IS_NULLPTR;
    }

    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = remoteEvent->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to SendRequest, code = %{public}d, result = %{public}d", code, result);
        return ERR_APPACCOUNT_KIT_SEND_REQUEST;
    }

    return ERR_OK;
}

template<typename T>
bool AppAccountEventProxy::WriteParcelableVector(const std::vector<T> &parcelableVector, Parcel &data)
{
    if (!data.WriteUint32(parcelableVector.size())) {
        ACCOUNT_LOGE("failed to WriteInt32 for parcelableVector.size()");
        return false;
    }

    for (const auto &parcelable : parcelableVector) {
        if (!data.WriteParcelable(&parcelable)) {
            ACCOUNT_LOGE("failed to WriteParcelable for parcelable");
            return false;
        }
    }

    return true;
}
}  // namespace AccountSA
}  // namespace OHOS
