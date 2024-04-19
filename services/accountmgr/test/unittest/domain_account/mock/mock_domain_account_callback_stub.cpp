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

#include "mock_domain_account_callback_stub.h"

#include "account_log_wrapper.h"
#include "gmock/gmock.h"
#include "parcel.h"

namespace OHOS {
namespace AccountSA {

MockDomainAccountCallbackStub::MockDomainAccountCallbackStub(const std::shared_ptr<MockDomainAccountCallback> &callback)
    : innerCallback_(callback)
{}

MockDomainAccountCallbackStub::~MockDomainAccountCallbackStub()
{}

void MockDomainAccountCallbackStub::OnResult(const int32_t errCode, Parcel &parcel)
{
    ACCOUNT_LOGI("MockDomainAccountCallbackStub OnResult enter");
    innerCallback_->OnResult(errCode, parcel);
    std::unique_lock<std::mutex> lock(mutex);
    isReady = true;
    cv.notify_one();
    return;
}
} // namespace AccountSA
} // namespace OHOS