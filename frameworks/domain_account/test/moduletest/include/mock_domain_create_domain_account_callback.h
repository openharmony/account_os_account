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

#ifndef OS_ACCOUNT_FRAMEWORKS_DOMAIN_ACCOUNT_TEST_INCLUDE_MOCK_DOMAIN_CREATE_DOMAIN_ACCOUNT_CALLBACK_H
#define OS_ACCOUNT_FRAMEWORKS_DOMAIN_ACCOUNT_TEST_INCLUDE_MOCK_DOMAIN_CREATE_DOMAIN_ACCOUNT_CALLBACK_H

#include <mutex>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "condition_variable"
#include "domain_account_callback.h"
#include "os_account_info.h"

namespace OHOS {
namespace AccountSA {
class MockDomainCreateDomainAccountCallback {
public:
    MOCK_METHOD4(OnResult, void(const int32_t errCode, const std::string &accountName, const std::string &domain,
                                const std::string &accountId));
};

class TestCreateDomainAccountCallback : public DomainAccountCallback {
public:
    TestCreateDomainAccountCallback(const std::shared_ptr<MockDomainCreateDomainAccountCallback> &callback);
    virtual ~TestCreateDomainAccountCallback();
    void OnResult(const int32_t errCode, Parcel &parcel) override;
    int32_t GetLocalId();
    std::condition_variable cv;
    bool isReady = false;
    std::mutex mutex;
private:
    int32_t localId_;
    std::shared_ptr<MockDomainCreateDomainAccountCallback> callback_;
};
}  // AccountSA
}  // OHOS
#endif  // OS_ACCOUNT_FRAMEWORKS_DOMAIN_ACCOUNT_TEST_INCLUDE_MOCK_DOMAIN_CREATE_DOMAIN_ACCOUNT_CALLBACK_H