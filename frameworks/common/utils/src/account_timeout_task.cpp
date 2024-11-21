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
#include "account_timeout_task.h"
#include <thread>

namespace OHOS {
namespace AccountSA {
bool AccountTimeoutTask::RunTask(std::string taskName, const std::function<void()> &callback, int32_t timeout)
{
    auto task = [callback, weakPtr = weak_from_this()] {
        callback();
        auto ptr = weakPtr.lock();
        if (ptr) {
            std::unique_lock<std::mutex> lock(ptr->mutex_);
            ptr->isCalled_ = true;
            ptr->cv_.notify_one();
        }
    };
    
    std::thread taskThread(task);
    pthread_setname_np(taskThread.native_handle(), taskName.c_str());
    taskThread.detach();

    std::unique_lock<std::mutex> lock(mutex_);
    return cv_.wait_for(lock, std::chrono::seconds(timeout), [this] { return isCalled_; });
}
} // namespace AccountSA
} // namespace OHOS