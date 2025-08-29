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
#include "ipc_skeleton.h"
#include "app_account_control_manager.h"

namespace OHOS {
namespace AccountSA {
namespace {
const uid_t ACCOUNT_UID = 3058;
}
OsAccountStateSubscriber::OsAccountStateSubscriber()
{}

ErrCode OsAccountStateSubscriber::OnStateChanged(const OsAccountStateParcel &parcel)
{
    ACCOUNT_LOGI("State: %{public}d, fromId: %{public}d, toId: %{public}d",
        parcel.state, parcel.fromId, parcel.toId);
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

ErrCode OsAccountStateSubscriber::OnAccountsChanged(int32_t localId)
{
    return ERR_OK;
}

ErrCode OsAccountStateSubscriber::OnAccountsSwitch(int32_t newId, int32_t oldId)
{
    return ERR_OK;
}

ErrCode OsAccountStateSubscriber::CallbackEnter([[maybe_unused]] uint32_t code)
{
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid != ACCOUNT_UID) {
        ACCOUNT_LOGE("GetCallingUid failed, please check callingUid: %{public}d", callingUid);
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    return ERR_OK;
}

ErrCode OsAccountStateSubscriber::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    return ERR_OK;
}
} // namespace AccountSA
} // namespace OHOS