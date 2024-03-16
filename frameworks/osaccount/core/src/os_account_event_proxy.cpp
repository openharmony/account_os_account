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

#include "account_log_wrapper.h"

#include "os_account_event_proxy.h"

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
        return;
    }
}

ErrCode OsAccountEventProxy::SendRequest(OsAccountEventInterfaceCode code, MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCOUNT_LOGE("remote is nullptr, code = %{public}d", code);
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }

    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to send os account event request, code = %{public}d, result = %{public}d", code, result);
    }
    return result;
}
}  // namespace AccountSA
}  // namespace OHOS
