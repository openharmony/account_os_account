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

#include "mock_user_idm_client.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
static MockUserIdmClient &GetMockInstance()
{
    static auto *instance = new MockUserIdmClient();
    // Static singleton: gmock reports it as leaked at program exit; AllowLeak suppresses that.
    ::testing::Mock::AllowLeak(instance);
    // Default behavior: DeleteSubProfile immediately invokes the callback with SUCCESS
    // so tests that call RemoveSubProfile do not block on the 5s wait_for timeout.
    ON_CALL(*instance, DeleteSubProfile(::testing::_, ::testing::_))
        .WillByDefault(::testing::Invoke([](int32_t,
            const std::shared_ptr<UserIdmClientCallback> &callback) {
            callback->OnResult(ResultCode::SUCCESS, Attributes());
        }));
    return *instance;
}

MockUserIdmClient &MockUserIdmClient::GetMock()
{
    return GetMockInstance();
}

UserIdmClient &UserIdmClient::GetInstance()
{
    return GetMockInstance();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
