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

#ifndef OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_OS_ACCOUNT_STATE_REPLY_CALLBACK_H
#define OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_OS_ACCOUNT_STATE_REPLY_CALLBACK_H

#include <atomic>
#include <condition_variable>
#include <memory>
#include "iremote_object.h"

namespace OHOS {
namespace AccountSA {

class OsAccountStateReplyCallback {
public:
    explicit OsAccountStateReplyCallback(const sptr<IRemoteObject> &object);
    OsAccountStateReplyCallback(const std::shared_ptr<std::condition_variable> &cv,
                                const std::shared_ptr<std::atomic<int>> &counter);
    void OnComplete();

private:
    std::shared_ptr<std::condition_variable> cv_;
    std::shared_ptr<std::atomic<int>> counter_;
};

} // namespace AccountSA
} // namespace OHOS

#endif // OS_ACCOUNT_STATE_REPLY_CALLBACK_H
