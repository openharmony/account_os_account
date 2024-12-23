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
#include "os_account_event_listener.h"
#include <pthread.h>
#include <thread>

namespace OHOS {
namespace AccountSA {
namespace {
const char THREAD_OS_ACCOUNT_EVENT[] = "OsAccountEvent";
}
OsAccountEventListener::OsAccountEventListener(const std::shared_ptr<OsAccountSubscriber> &subscriber)
    : osAccountSubscriber_(subscriber)
{}

OsAccountEventListener::~OsAccountEventListener()
{}

ErrCode OsAccountEventListener::OnStateChanged(const OsAccountStateParcel &parcel)
{
    ACCOUNT_LOGI("State: %{public}d, fromId: %{public}d, toId: %{public}d", parcel.state, parcel.fromId, parcel.toId);
    if (osAccountSubscriber_ == nullptr) {
        ACCOUNT_LOGE("Subscriber is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    OsAccountStateData data;
    data.fromId = parcel.fromId;
    data.toId = parcel.toId;
    data.state = parcel.state;
    if (parcel.callback != nullptr) {
        data.callback = iface_cast<OsAccountStateReplyCallback>(parcel.callback);
    }
    auto task = [this, data] { this->osAccountSubscriber_->OnStateChanged(data); };
    std::thread taskThread(task);
    pthread_setname_np(taskThread.native_handle(), THREAD_OS_ACCOUNT_EVENT);
    taskThread.detach();
    return ERR_OK;
}

void OsAccountEventListener::OnAccountsChanged(const int &id)
{
    if (osAccountSubscriber_ == nullptr) {
        ACCOUNT_LOGI("osAccountSubscriber_ is nullptr");
        return;
    }

    osAccountSubscriber_->OnAccountsChanged(id);
}

void OsAccountEventListener::OnAccountsSwitch(const int &newId, const int &oldId)
{
    if (osAccountSubscriber_ == nullptr) {
        ACCOUNT_LOGI("OsAccountSubscriber_ is nullptr.");
        return;
    }

    osAccountSubscriber_->OnAccountsSwitch(newId, oldId);
}

void OsAccountEventListener::Stop()
{}
}  // namespace AccountSA
}  // namespace OHOS
