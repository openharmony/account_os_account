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

#ifndef OS_ACCOUNT_TEST_MOCK_USER_IDM_CLIENT_H
#define OS_ACCOUNT_TEST_MOCK_USER_IDM_CLIENT_H

#include <gmock/gmock.h>
#include "user_idm_client.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class MockUserIdmClient : public UserIdmClient {
public:
    MockUserIdmClient() = default;
    virtual ~MockUserIdmClient() = default;

    static MockUserIdmClient &GetMock();

    MOCK_METHOD(std::vector<uint8_t>, OpenSession, (int32_t userId), (override));
    MOCK_METHOD(void, CloseSession, (int32_t userId), (override));
    MOCK_METHOD(void, AddCredential, (int32_t userId, const CredentialParameters &para,
        const std::shared_ptr<UserIdmClientCallback> &callback), (override));
    MOCK_METHOD(void, UpdateCredential, (int32_t userId, const CredentialParameters &para,
        const std::shared_ptr<UserIdmClientCallback> &callback), (override));
    MOCK_METHOD(int32_t, Cancel, (int32_t userId), (override));
    MOCK_METHOD(void, DeleteCredential, (int32_t userId, uint64_t credentialId,
        const std::vector<uint8_t> &authToken, const std::shared_ptr<UserIdmClientCallback> &callback), (override));
    MOCK_METHOD(void, DeleteUser, (int32_t userId, const std::vector<uint8_t> &authToken,
        const std::shared_ptr<UserIdmClientCallback> &callback), (override));
    MOCK_METHOD(int32_t, EraseUser,
        (int32_t userId, const std::shared_ptr<UserIdmClientCallback> &callback), (override));
    MOCK_METHOD(int32_t, GetCredentialInfo, (int32_t userId, AuthType authType,
        const std::shared_ptr<GetCredentialInfoCallback> &callback), (override));
    MOCK_METHOD(int32_t, GetSecUserInfo,
        (int32_t userId, const std::shared_ptr<GetSecUserInfoCallback> &callback), (override));
    MOCK_METHOD(void, ClearRedundancyCredential, (const std::shared_ptr<UserIdmClientCallback> &callback), (override));
    MOCK_METHOD(int32_t, RegistCredChangeEventListener, (const std::vector<AuthType> &authTypes,
        const std::shared_ptr<CredChangeEventListener> &listener), (override));
    MOCK_METHOD(int32_t, UnRegistCredChangeEventListener,
        (const std::shared_ptr<CredChangeEventListener> &listener), (override));
    MOCK_METHOD(int32_t, GetCredentialInfoSync, (int32_t userId, AuthType authType,
        std::vector<CredentialInfo> &credentialInfoList), (override));
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // OS_ACCOUNT_TEST_MOCK_USER_IDM_CLIENT_H
