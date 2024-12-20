/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_FRAMEWORKS_DOMAIN_ACCOUNT_TEST_INCLUDE_MOCK_DOMAIN_AUTH_CALLBACK_FOR_LISTENER_H
#define OS_ACCOUNT_FRAMEWORKS_DOMAIN_ACCOUNT_TEST_INCLUDE_MOCK_DOMAIN_AUTH_CALLBACK_FOR_LISTENER_H

#include <mutex>
#include <gmock/gmock.h>
#include "condition_variable"
#include "domain_account_callback.h"
#include "os_account_info.h"

namespace OHOS {
namespace AccountSA {
class MockDomainAuthCallbackForListener {
public:
    MOCK_METHOD2(OnResult, void(int32_t resultCode, const DomainAuthResult &result));
};

class TestDomainAuthCallbackForListener : public DomainAccountCallback {
public:
    TestDomainAuthCallbackForListener(const std::shared_ptr<MockDomainAuthCallbackForListener> &callback);
    virtual ~TestDomainAuthCallbackForListener();
    void OnResult(const int32_t errCode, Parcel &parcel) override;
    void SetOsAccountInfo(const OsAccountInfo &info);
    std::condition_variable cv;
    bool isReady = false;
    std::mutex mutex;

private:
    std::shared_ptr<MockDomainAuthCallbackForListener> callback_;
    OsAccountInfo accountInfo_;
};
}  // AccountSA
}  // OHOS
#endif  // OS_ACCOUNT_FRAMEWORKS_DOMAIN_ACCOUNT_TEST_INCLUDE_MOCK_DOMAIN_AUTH_CALLBACK_FOR_LISTENER_H