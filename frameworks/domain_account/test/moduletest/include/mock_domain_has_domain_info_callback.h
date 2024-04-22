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

#ifndef OS_ACCOUNT_FRAMEWORKS_DOMAIN_ACCOUNT_TEST_INCLUDE_MOCK_DOMAIN_HAS_DOMAIN_INFO_CALLBACK_H
#define OS_ACCOUNT_FRAMEWORKS_DOMAIN_ACCOUNT_TEST_INCLUDE_MOCK_DOMAIN_HAS_DOMAIN_INFO_CALLBACK_H

#include <gmock/gmock.h>
#include "domain_account_callback.h"
#include "os_account_info.h"

namespace OHOS {
namespace AccountSA {
class MockDomainHasDomainInfoCallback {
public:
    MOCK_METHOD2(OnResult, void(const int32_t errCode, const bool hasDomainInfo));
};

class TestHasDomainInfoCallback : public DomainAccountCallback {
public:
    TestHasDomainInfoCallback(const std::shared_ptr<MockDomainHasDomainInfoCallback> &callback);
    virtual ~TestHasDomainInfoCallback();
    void OnResult(const int32_t errCode, Parcel &parcel) override;
    bool GetHasDomainInfo();
    std::condition_variable cv;
    bool isReady = false;
    std::mutex mutex;

private:
    std::shared_ptr<MockDomainHasDomainInfoCallback> callback_;
    bool hasDomainInfo_ = false;
};

class MockGetDomainAccountInfoCallback {
public:
    MOCK_METHOD2(OnResult, void(const int32_t errCode, Parcel &parcel));
};

class TestGetDomainAccountInfoCallback : public DomainAccountCallback {
public:
    TestGetDomainAccountInfoCallback(const std::shared_ptr<MockGetDomainAccountInfoCallback> &callback);
    virtual ~TestGetDomainAccountInfoCallback();
    void OnResult(const int32_t errCode, Parcel &parcel) override;
    std::condition_variable cv;
    bool isReady = false;
    std::mutex mutex;

private:
    std::shared_ptr<MockGetDomainAccountInfoCallback> callback_;
};
}  // AccountSA
}  // OHOS
#endif  // OS_ACCOUNT_FRAMEWORKS_DOMAIN_ACCOUNT_TEST_INCLUDE_MOCK_DOMAIN_HAS_DOMAIN_INFO_CALLBACK_H