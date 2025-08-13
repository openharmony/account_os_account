/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#ifndef APP_ACCOUNT_MANAGER_TEST_CALLBACK_H
#define APP_ACCOUNT_MANAGER_TEST_CALLBACK_H

#include <gmock/gmock.h>

#include "app_account_authenticator_callback_stub.h"

namespace OHOS {
namespace AccountTest {
class MockAuthenticatorCallback final : public AccountSA::AppAccountAuthenticatorCallbackStub {
public:
    MOCK_METHOD2(OnResult, ErrCode(int32_t resultCode, const AAFwk::Want &result));
    MOCK_METHOD1(OnRequestRedirected, ErrCode(const AAFwk::Want &request));
    MOCK_METHOD0(OnRequestContinued, ErrCode());
    MOCK_METHOD1(CallbackEnter, ErrCode(uint32_t code));
    MOCK_METHOD2(CallbackExit, ErrCode(uint32_t code, int32_t result));
};
} // namespace AccountTest
} // namespace OHOS

#endif // namespace APP_ACCOUNT_MANAGER_TEST_CALLBACK_H
