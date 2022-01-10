/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "app_account_event_proxy.h"

namespace OHOS {
namespace AccountSA {
AppAccountEventProxy::AppAccountEventProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IAppAccountEvent>(object)
{
    ACCOUNT_LOGI("enter");
}

AppAccountEventProxy::~AppAccountEventProxy()
{}

void AppAccountEventProxy::OnAccountsChanged(const std::vector<AppAccountInfo> &accounts)
{
    ACCOUNT_LOGI("enter");

    MessageParcel data;
    MessageParcel reply;

    if (!WriteParcelableVector(accounts, data)) {
        ACCOUNT_LOGE("failed to write WriteVector accounts");
    }

    ErrCode result = SendRequest(IAppAccountEvent::Message::ACCOUNT_CHANGED, data, reply);
    if (result != ERR_OK) {
        return;
    }
}

ErrCode AppAccountEventProxy::SendRequest(IAppAccountEvent::Message code, MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGI("enter");

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCOUNT_LOGE("remote is nullptr, code = %{public}d", code);
        return ERR_APPACCOUNT_KIT_REMOTE_IS_NULLPTR;
    }

    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to SendRequest, code = %{public}d, result = %{public}d", code, result);
        return ERR_APPACCOUNT_KIT_SEND_REQUEST;
    }

    return ERR_OK;
}

template<typename T>
bool AppAccountEventProxy::WriteParcelableVector(const std::vector<T> &parcelableVector, Parcel &data)
{
    ACCOUNT_LOGI("enter");

    if (!data.WriteInt32(parcelableVector.size())) {
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
