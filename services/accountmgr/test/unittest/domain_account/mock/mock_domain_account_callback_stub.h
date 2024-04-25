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

#ifndef OS_ACCOUNT_SERVICE_DOMAIN_ACCOUNT_TEST_INCLUDE_MOCK_DOMAIN_ACCOUNT_CALLBACK_H
#define OS_ACCOUNT_SERVICE_DOMAIN_ACCOUNT_TEST_INCLUDE_MOCK_DOMAIN_ACCOUNT_CALLBACK_H

#include "domain_account_callback_stub.h"
#include "gmock/gmock.h"

namespace OHOS {
namespace AccountSA {
class MockDomainAccountCallback {
public:
    MOCK_METHOD2(OnResult, void(int32_t resultCode, Parcel &parcel));
};

class MockDomainAccountCallbackStub : public DomainAccountCallbackStub {
public:
    explicit MockDomainAccountCallbackStub(const std::shared_ptr<MockDomainAccountCallback> &callback);
    virtual ~MockDomainAccountCallbackStub();
    void OnResult(const int32_t errCode, Parcel &parcel) override;
    std::condition_variable cv;
    bool isReady = false;
    std::mutex mutex;

private:
    std::shared_ptr<MockDomainAccountCallback> innerCallback_;
};
} // namespace AccountSA
} // namespace OHOS

#endif  // OS_ACCOUNT_SERVICE_DOMAIN_ACCOUNT_TEST_INCLUDE_MOCK_DOMAIN_ACCOUNT_CALLBACK_H