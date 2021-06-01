/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include <gtest/gtest.h>

#include "ohos_account_manager.h"
#include "account_info.h"
using namespace testing::ext;
using namespace OHOS::AccountSA;
class OhosAccountManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
void OhosAccountManagerTest::SetUpTestCase() {}
void OhosAccountManagerTest::TearDownTestCase() {}
void OhosAccountManagerTest::SetUp() {}
void OhosAccountManagerTest::TearDown() {}
/**
 * @tc.name: OhosAccountManagerTestTokenInvalid004
 * @tc.desc: Account manager handle token invalid event test
 * @tc.type: FUNC
 * @tc.require: AR000CUF5U AR000CUF5V SR000CUF5T
 */
HWTEST_F(OhosAccountManagerTest, OhosAccountManagerTestTokenInvalid004, TestSize.Level0)
{
    /**
     * @tc.steps: step1. init one account
     * @tc.expected: step1. The current account state is AccountStateMachine::ACCOUNT_STATE_UNBOUND
     */
    OhosAccountManager accountManager;
    std::string uid("TestUid");
    std::string invalidUid("NotExistUid");
    std::string name("TestName");
    accountManager.OnInitialize();
    auto ret = accountManager.LoginOhosAccount(name, uid, OHOS_ACCOUNT_EVENT_LOGIN);
    EXPECT_EQ(true, ret);
    /**
    * @tc.steps: step2. trigger token_invalid event for a different uid
    * @tc.expected: step2. process result is true AND state changes
    */
    ret = accountManager.HandleOhosAccountTokenInvalidEvent(name, invalidUid, OHOS_ACCOUNT_EVENT_TOKEN_INVALID);
    EXPECT_EQ(true, ret);
    EXPECT_EQ(ACCOUNT_STATE_NOTLOGIN, accountManager.GetAccountState());
    /**
    * @tc.steps: step3. trigger token_invalid event with the same uid
    * @tc.expected: step3. process result is true AND state changes
    */
    ret = accountManager.HandleOhosAccountTokenInvalidEvent(name, uid, OHOS_ACCOUNT_EVENT_TOKEN_INVALID);
    EXPECT_EQ(true, ret);
    EXPECT_EQ(ACCOUNT_STATE_NOTLOGIN, accountManager.GetAccountState());
    /**
    * @tc.steps: step4. logout the account
    * @tc.expected: step4. The current account logout
    */
    ret = accountManager.LogoutOhosAccount(name, uid, OHOS_ACCOUNT_EVENT_LOGOUT);
    EXPECT_EQ(true, ret);
}
