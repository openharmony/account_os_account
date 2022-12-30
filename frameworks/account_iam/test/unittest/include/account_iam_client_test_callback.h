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

#ifndef ACCOUNT_IAM_CLIENT_TEST_CALLBACK_H
#define ACCOUNT_IAM_CLIENT_TEST_CALLBACK_H

#include <vector>
#include <gmock/gmock.h>
#include "account_iam_client_callback.h"
#include "account_iam_info.h"

namespace OHOS {
namespace AccountTest {
class MockIDMCallback final : public AccountSA::IDMCallback {
public:
    MOCK_METHOD2(OnResult, void(int32_t result, const AccountSA::Attributes &extraInfo));
    MOCK_METHOD3(OnAcquireInfo, void(int32_t module, uint32_t acquireInfo, const AccountSA::Attributes &extraInfo));
};

class MockGetCredInfoCallback final : public AccountSA::GetCredInfoCallback {
public:
    MOCK_METHOD2(OnCredentialInfo, void(int32_t result, const std::vector<AccountSA::CredentialInfo> &infoList));
};

class MockGetSetPropCallback final : public AccountSA::GetSetPropCallback {
public:
    MOCK_METHOD2(OnResult, void(int32_t result, const AccountSA::Attributes &extraInfo));
};
}  // namespace AccountTest
}  // namespace OHOS

#endif  // ACCOUNT_IAM_CLIENT_TEST_CALLBACK_H