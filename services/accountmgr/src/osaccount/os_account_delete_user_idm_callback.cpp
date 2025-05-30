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
#include "os_account_delete_user_idm_callback.h"
#include "account_error_no.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
#ifdef HAS_USER_AUTH_PART
void OsAccountDeleteUserIdmCallback::OnResult(int32_t result, const UserIam::UserAuth::Attributes &extraInfo)
{
    std::unique_lock<std::mutex> lock(mutex_);
    ACCOUNT_LOGI("IAM OnResult callback! result %{public}d", result);
    isCalled_ = true;
    resultCode_ = result;
    onResultCondition_.notify_one();
}

void OsAccountDeleteUserIdmCallback::OnAcquireInfo(int32_t module, uint32_t acquireInfo,
    const UserIam::UserAuth::Attributes &extraInfo)
{
    ACCOUNT_LOGI("IAM OnAcquireInfo callback! module %{public}d, acquire %{public}u.", module, acquireInfo);
}
#endif // HAS_USER_AUTH_PART
}  // namespace AccountSA
}  // namespace OHOS