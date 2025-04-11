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

#include <thread>
#include "account_constants.h"
#include "account_error_no.h"
#include "account_hisysevent_adapter.h"
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

    ErrCode result = SendRequest(AppAccountEventInterfaceCode::ACCOUNT_CHANGED, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest failed! error code %{public}d.", result);
        REPORT_APP_ACCOUNT_FAIL("", "", Constants::OPERATION_EVENT_PUBLISH,
            result, "Send OnAccountsChanged failed.");
        return;
    }
}

ErrCode AppAccountEventProxy::SendRequest(AppAccountEventInterfaceCode code, MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> remoteEvent = Remote();
    if (remoteEvent == nullptr) {
        ACCOUNT_LOGE("remote is nullptr, code = %{public}d", code);
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    int32_t retryTimes = 0;
    int32_t result;
    MessageOption option(MessageOption::TF_SYNC);
    while (retryTimes < Constants::MAX_RETRY_TIMES) {
        result = remoteEvent->SendRequest(static_cast<uint32_t>(code), data, reply, option);
        if (result == ERR_OK || (result != Constants::E_IPC_ERROR &&
            result != Constants::E_IPC_SA_DIED)) {
            break;
        }
        retryTimes++;
        ACCOUNT_LOGE("Failed to SendRequest, code = %{public}d, retryTimes = %{public}d",
            result, retryTimes);
        std::this_thread::sleep_for(std::chrono::milliseconds(Constants::DELAY_FOR_EXCEPTION));
    }
    if (result != ERR_OK) {
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
