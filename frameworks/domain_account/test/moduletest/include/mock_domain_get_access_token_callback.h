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

#ifndef OS_ACCOUNT_FRAMEWORKS_DOMAIN_ACCOUNT_TEST_INCLUDE_MOCK_DOMAIN_GET_ACCESS_TOKEN_CALLBACK_H
#define OS_ACCOUNT_FRAMEWORKS_DOMAIN_ACCOUNT_TEST_INCLUDE_MOCK_DOMAIN_GET_ACCESS_TOKEN_CALLBACK_H

#include <gmock/gmock.h>
#include "get_access_token_callback.h"
#include "os_account_info.h"

namespace OHOS {
namespace AccountSA {
class MockDomainGetAccessTokenCallback {
public:
    MOCK_METHOD2(OnResult, void(const int32_t errCode, const std::vector<uint8_t> token));
};

class TestGetAccessTokenCallback : public GetAccessTokenCallback {
public:
    TestGetAccessTokenCallback(const std::shared_ptr<MockDomainGetAccessTokenCallback> &callback);
    virtual ~TestGetAccessTokenCallback();
    void OnResult(const int32_t errCode, const std::vector<uint8_t> &accessToken) override;
    std::condition_variable cv;
    bool isReady = false;
    std::mutex mutex;

private:
    std::shared_ptr<MockDomainGetAccessTokenCallback> callback_;
};
}  // AccountSA
}  // OHOS
#endif  // OS_ACCOUNT_FRAMEWORKS_DOMAIN_ACCOUNT_TEST_INCLUDE_MOCK_DOMAIN_GET_ACCESS_TOKEN_CALLBACK_H