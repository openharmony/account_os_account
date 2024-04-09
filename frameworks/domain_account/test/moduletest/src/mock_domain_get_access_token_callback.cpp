/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "mock_domain_get_access_token_callback.h"

#include "account_log_wrapper.h"
#include "os_account_manager.h"
#include "parcel.h"

namespace OHOS {
namespace AccountSA {
TestGetAccessTokenCallback::TestGetAccessTokenCallback(
    const std::shared_ptr<MockDomainGetAccessTokenCallback> &callback)
    : callback_(callback)
{}

TestGetAccessTokenCallback::~TestGetAccessTokenCallback()
{}

void TestGetAccessTokenCallback::OnResult(const int32_t errCode, const std::vector<uint8_t> &accessToken)
{
    if (callback_ == nullptr) {
        return;
    }
    callback_->OnResult(errCode, accessToken);
    std::unique_lock<std::mutex> lock(mutex);
    isReady = true;
    cv.notify_one();
    return;
}
}  // AccountSA
}  // OHOS