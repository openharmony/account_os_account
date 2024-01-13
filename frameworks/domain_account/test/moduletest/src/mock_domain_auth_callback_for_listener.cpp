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

#include "mock_domain_auth_callback_for_listener.h"

#include "account_log_wrapper.h"
#include "os_account_manager.h"

namespace OHOS {
namespace AccountSA {
TestDomainAuthCallbackForListener::TestDomainAuthCallbackForListener(
    const std::shared_ptr<MockDomainAuthCallbackForListener> &callback)
    : callback_(callback)
{}

TestDomainAuthCallbackForListener::~TestDomainAuthCallbackForListener()
{}

void TestDomainAuthCallbackForListener::OnResult(const int32_t errCode, Parcel &parcel)
{
    ACCOUNT_LOGI("TestDomainAuthCallbackForListener");
    if (callback_ == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return;
    }
    std::shared_ptr<DomainAuthResult> authResult(DomainAuthResult::Unmarshalling(parcel));
    if (authResult == nullptr) {
        return;
    }
    callback_->OnResult(errCode, *authResult);
    std::unique_lock<std::mutex> lock(mutex);
    isReady = true;
    cv.notify_one();
}

void TestDomainAuthCallbackForListener::SetOsAccountInfo(const OsAccountInfo &accountInfo)
{
    accountInfo_ = accountInfo;
}
}  // AccountSA
}  // OHOS