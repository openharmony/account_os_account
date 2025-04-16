/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "os_account_event_proxy.h"
#include <thread>
#include "account_constants.h"
#include "account_log_wrapper.h"
#include "account_hisysevent_adapter.h"
#include "os_account_constants.h"

namespace OHOS {
namespace AccountSA {
OsAccountEventProxy::OsAccountEventProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IOsAccountEvent>(object)
{}

OsAccountEventProxy::~OsAccountEventProxy()
{}

void OsAccountEventProxy::OnAccountsChanged(const int &localId)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return;
    }

    if (!data.WriteInt32(localId)) {
        ACCOUNT_LOGE("failed to write WriteInt32 localId %{public}d.", localId);
        return;
    }

    ErrCode result = SendRequest(OsAccountEventInterfaceCode::ACCOUNT_CHANGED, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest for account changed failed! result %{public}d, localId %{public}d.",
            result, localId);
        REPORT_OS_ACCOUNT_FAIL(localId, Constants::OPERATION_EVENT_PUBLISH,
            result, "Send OnAccountsChanged subscribe failed");
        return;
    }
}

void OsAccountEventProxy::OnAccountsSwitch(const int &newId, const int &oldId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed.");
        return;
    }

    if (!data.WriteInt32(newId)) {
        ACCOUNT_LOGE("Write newId failed.");
        return;
    }

    if (!data.WriteInt32(oldId)) {
        ACCOUNT_LOGE("Write oldId failed.");
        return;
    }
    MessageParcel reply;
    ErrCode result = SendRequest(OsAccountEventInterfaceCode::ACCOUNT_SWITCHED, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest failed, result=%{public}d.", result);
        REPORT_OS_ACCOUNT_FAIL(newId, Constants::OPERATION_EVENT_PUBLISH,
            result, "Send OnAccountsSwitch subscribe failed, from=" +
            std::to_string(oldId) + ", to=" + std::to_string(newId));
        return;
    }
}

ErrCode OsAccountEventProxy::OnStateChanged(const OsAccountStateParcel &stateParcel)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Failed to write descriptor");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    if (!data.WriteParcelable(&stateParcel)) {
        ACCOUNT_LOGE("Failed to write state parcel");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    MessageParcel reply;
    ErrCode result = SendRequest(OsAccountEventInterfaceCode::ON_STATE_CHANGED, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest failed, result=%{public}d.", result);
    }
    return result;
}

ErrCode OsAccountEventProxy::SendRequest(OsAccountEventInterfaceCode code, MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCOUNT_LOGE("remote is nullptr, code = %{public}d", code);
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
        ACCOUNT_LOGE("Failed to send the OS account event, reqCode: %{public}d, retryTimes: %{public}d",
            result, retryTimes);
        std::this_thread::sleep_for(std::chrono::milliseconds(Constants::DELAY_FOR_EXCEPTION));
    }
    return result;
}
}  // namespace AccountSA
}  // namespace OHOS
