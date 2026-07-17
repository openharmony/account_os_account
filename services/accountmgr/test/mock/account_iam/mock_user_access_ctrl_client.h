/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_TEST_MOCK_USER_ACCESS_CTRL_CLIENT_H
#define OS_ACCOUNT_TEST_MOCK_USER_ACCESS_CTRL_CLIENT_H

#include <gmock/gmock.h>
#include "user_access_ctrl_client.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockUserAccessCtrlClient : public UserAccessCtrlClient {
public:
    MockUserAccessCtrlClient() = default;
    virtual ~MockUserAccessCtrlClient() = default;

    static MockUserAccessCtrlClient &GetMock();

    MOCK_METHOD(void, VerifyAuthToken, (const std::vector<uint8_t> &tokenIn, uint64_t allowableDuration,
        const std::shared_ptr<VerifyTokenCallback> &callback), (override));
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // OS_ACCOUNT_TEST_MOCK_USER_ACCESS_CTRL_CLIENT_H
