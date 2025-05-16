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
    const sptr<IRemoteObject> &object)
{}

OsAccountStateReplyCallback::OsAccountStateReplyCallback(
    const std::shared_ptr<std::condition_variable> &cv, const std::shared_ptr<bool> &callbackCounter)
    : cv_(cv), callbackCounter(callbackCounter)
{}

void OsAccountStateReplyCallback::OnComplete()
{
    if (cv_ == nullptr || callbackCounter == nullptr) {
        return;
    }
    callbackCounter.reset();
    cv_->notify_one();
}
}  // namespace AccountSA
}  // namespace OHOS
