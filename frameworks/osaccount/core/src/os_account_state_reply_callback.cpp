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

namespace OHOS {
namespace AccountSA {

OsAccountStateReplyCallback::OsAccountStateReplyCallback(const sptr<IRemoteObject> &object)
{}

OsAccountStateReplyCallback::OsAccountStateReplyCallback(
    const std::shared_ptr<std::condition_variable> &cv,
    const std::shared_ptr<std::atomic<int>> &counter)
    : cv_(cv), counter_(counter)
{}

void OsAccountStateReplyCallback::OnComplete()
{
    if (counter_ == nullptr || cv_ == nullptr) {
        return;
    }
    counter_->fetch_sub(1);
    cv_->notify_one();
}

} // namespace AccountSA
} // namespace OHOS
