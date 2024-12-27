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

#include "os_account_state_reply_callback.h"
#include "accountmgr_service_ipc_interface_code.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
OsAccountStateReplyCallback::OsAccountStateReplyCallback(
    const sptr<IRemoteObject> &object) : IRemoteProxy<IOsAccountStateReplyCallback>(object)
{}

ErrCode OsAccountStateReplyCallback::SendRequest(
    StateReplyCallbackInterfaceCode code, MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCOUNT_LOGE("Remote is nullptr, code = %{public}d", code);
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }

    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Failed to send request, code = %{public}d, result = %{public}d", code, result);
    } else {
        ACCOUNT_LOGI("Send OnComplete successfully, code = %{public}d", code);
    }
    return result;
}

void OsAccountStateReplyCallback::OnComplete()
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Failed to write descriptor!");
        return;
    }

    MessageParcel reply;
    SendRequest(StateReplyCallbackInterfaceCode::ON_COMPLETE, data, reply);
}
}  // namespace AccountSA
}  // namespace OHOS
