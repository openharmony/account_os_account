/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "os_account_state_subscriber.h"
#include "ios_account_state_reply_callback.h"
#include "app_account_control_manager.h"

namespace OHOS {
namespace AccountSA {
OsAccountStateSubscriber::OsAccountStateSubscriber()
{}

ErrCode OsAccountStateSubscriber::OnStateChanged(const OsAccountStateParcel &parcel)
{
    ACCOUNT_LOGI("State: %{public}d, fromId: %{public}d, toId: %{public}d", parcel.state, parcel.fromId, parcel.toId);
    if (parcel.state == OsAccountState::STOPPING) {
        ACCOUNT_LOGI("Account stopping id=%{public}d", parcel.fromId);
        AppAccountControlManager::GetInstance().OnUserStopping(parcel.fromId);
    }
    auto callback = iface_cast<IOsAccountStateReplyCallback>(parcel.callback);
    if (callback == nullptr) {
        ACCOUNT_LOGE("Callback is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    callback->OnComplete();
    return ERR_OK;
}

void OsAccountStateSubscriber::OnAccountsChanged(const int &localId)
{}

void OsAccountStateSubscriber::OnAccountsSwitch(const int &newId, const int &oldId)
{}
} // namespace AccountSA
} // namespace OHOS