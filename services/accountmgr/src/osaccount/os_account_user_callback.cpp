/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "os_account_user_callback.h"
#include <chrono>
#include <thread>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "os_account_manager.h"
#include "os_account_interface.h"

namespace OHOS {
namespace AccountSA {
void OsAccountUserCallback::OnStopUserDone(int userId, int errcode)
{
    std::unique_lock<std::mutex> lock(mutex_);
    ACCOUNT_LOGI("in call back account, OnStopUserDone id is %{public}d, errcode is %{public}d.",
        userId, errcode);
    isReturnOk_ = (errcode == 0);
    onStopCondition_.notify_one();
}

void OsAccountUserCallback::OnStartUserDone(int userId, int errcode)
{
    std::unique_lock<std::mutex> lock(mutex_);
    ACCOUNT_LOGI("in call back account, OnStartUserDone id is %{public}d, errcode is %{public}d.",
        userId, errcode);
    isReturnOk_ = (errcode == 0);
    onStartCondition_.notify_one();
}
}  // namespace AccountSA
}  // namespace OHOS
