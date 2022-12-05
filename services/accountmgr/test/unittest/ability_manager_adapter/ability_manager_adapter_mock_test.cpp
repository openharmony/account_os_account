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

#include <gtest/gtest.h>
#define private public
#include "ability_manager_adapter.h"
#undef private
#include "ability_connect_callback_stub.h"
#include "account_event_provider.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;
using namespace OHOS::AAFwk;

namespace {
    const std::int32_t MAIN_ACCOUNT_ID = 100;
    const std::int32_t USER_ID = 100;
    const std::string TEST_SESSIONID = "testsessionId";
}

class AbilityManagerAdapterMockTest : public testing::Test {
public:

    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AbilityManagerAdapterMockTest::SetUpTestCase() {}

void AbilityManagerAdapterMockTest::TearDownTestCase() {}

void AbilityManagerAdapterMockTest::SetUp() {}

void AbilityManagerAdapterMockTest::TearDown() {}

class AbilityConnectCallbackTest : public AAFwk::AbilityConnectionStub {
public:
    explicit AbilityConnectCallbackTest(const std::string &sessionId) {}
    virtual ~AbilityConnectCallbackTest() {}
    void OnAbilityConnectDone(const AppExecFwk::ElementName &element,
        const sptr<IRemoteObject> &remoteObject, int32_t resultCode) {}
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode) {}
};

/**
 * @tc.name: AbilityManagerAdapterMockTest001
 * @tc.desc: Test ConnectAbility GetAbilityManager failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityManagerAdapterMockTest, AbilityManagerAdapterMockTest001, TestSize.Level0)
{
    AAFwk::Want want;
    sptr<AbilityConnectCallbackTest> conn = new (std::nothrow) AbilityConnectCallbackTest(TEST_SESSIONID);
    EXPECT_EQ(ERR_ACCOUNT_COMMON_CONNECT_ABILITY_MANAGER_SERVICE_ERROR,
        AbilityManagerAdapter::GetInstance()->ConnectAbility(want, conn, nullptr, USER_ID));
}

/**
 * @tc.name: AbilityManagerAdapterMockTest002
 * @tc.desc: Test DisconnectAbility GetAbilityManager failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityManagerAdapterMockTest, AbilityManagerAdapterMockTest002, TestSize.Level0)
{
    sptr<AbilityConnectCallbackTest> conn = new (std::nothrow) AbilityConnectCallbackTest(TEST_SESSIONID);
    EXPECT_EQ(ERR_ACCOUNT_COMMON_CONNECT_ABILITY_MANAGER_SERVICE_ERROR,
        AbilityManagerAdapter::GetInstance()->DisconnectAbility(conn));
}

/**
 * @tc.name: AbilityManagerAdapterMockTest003
 * @tc.desc: Test StartUser GetAbilityManager failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityManagerAdapterMockTest, AbilityManagerAdapterMockTest003, TestSize.Level0)
{
    EXPECT_EQ(ERR_ACCOUNT_COMMON_CONNECT_ABILITY_MANAGER_SERVICE_ERROR,
        AbilityManagerAdapter::GetInstance()->StartUser(MAIN_ACCOUNT_ID));
}

/**
 * @tc.name: AbilityManagerAdapterMockTest004
 * @tc.desc: Test StopUser GetAbilityManager failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityManagerAdapterMockTest, AbilityManagerAdapterMockTest004, TestSize.Level0)
{
    EXPECT_EQ(ERR_ACCOUNT_COMMON_CONNECT_ABILITY_MANAGER_SERVICE_ERROR,
        AbilityManagerAdapter::GetInstance()->StopUser(MAIN_ACCOUNT_ID, nullptr));
}
