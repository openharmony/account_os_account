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

#ifndef OS_ACCOUNT_FRAMEWORKS_ACCOUNT_TIMEOUT_TASK_H
#define OS_ACCOUNT_FRAMEWORKS_ACCOUNT_TIMEOUT_TASK_H

#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include "account_constants.h"

namespace OHOS {
namespace AccountSA {
class AccountTimeoutTask : public std::enable_shared_from_this<AccountTimeoutTask> {
public:
    bool RunTask(std::string taskName, const std::function<void()> &callback, int32_t timeout = WAIT_TIME);

    bool isCalled_ = false;
    std::mutex mutex_;
    std::condition_variable cv_;
};
} // AccountSA
} // OHOS
#endif // OS_ACCOUNT_FRAMEWORKS_ACCOUNT_TIMEOUT_TASK_H