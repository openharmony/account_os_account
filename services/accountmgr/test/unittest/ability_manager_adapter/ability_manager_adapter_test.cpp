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
#include "account_event_provider.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "ability_connect_callback_stub.h"
#include "ability_manager_errors.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;
using namespace OHOS::AAFwk;

namespace {
    const std::int32_t MAIN_ACCOUNT_ID = 100;
    const std::int32_t USER_ID = 100;
}

class AbilityManagerAdapterTest : public testing::Test {
public:

    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AbilityManagerAdapterTest::SetUpTestCase() {}

void AbilityManagerAdapterTest::TearDownTestCase() {}

void AbilityManagerAdapterTest::SetUp() {}

void AbilityManagerAdapterTest::TearDown() {}

/**
 * @tc.name: AbilityManagerAdapterTest001
 * @tc.desc: Test DisconnectAbility with connect is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityManagerAdapterTest, AbilityManagerAdapterTest001, TestSize.Level0)
{
    EXPECT_EQ(ERR_INVALID_VALUE, AbilityManagerAdapter::GetInstance()->DisconnectAbility(nullptr));
}

/**
 * @tc.name: AbilityManagerAdapterTest002
 * @tc.desc: Test StopUser with callback is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityManagerAdapterTest, AbilityManagerAdapterTest002, TestSize.Level0)
{
    EXPECT_EQ(CHECK_PERMISSION_FAILED, AbilityManagerAdapter::GetInstance()->StopUser(MAIN_ACCOUNT_ID, nullptr));
}

class AbilityConnectCallbackTest : public AAFwk::AbilityConnectionStub {
public:
    explicit AbilityConnectCallbackTest(const std::string &sessionId) {}
    virtual ~AbilityConnectCallbackTest() {}
    void OnAbilityConnectDone(const AppExecFwk::ElementName &element,
        const sptr<IRemoteObject> &remoteObject, int32_t resultCode) {}
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode) {}
};

/**
 * @tc.name: AbilityManagerAdapterTest003
 * @tc.desc: Test DoConnectAbility with invalid data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AbilityManagerAdapterTest, AbilityManagerAdapterTest003, TestSize.Level0)
{
    sptr<ISystemAbilityManager> systemMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(systemMgr, nullptr);
    sptr<IRemoteObject> abms = systemMgr->GetSystemAbility(SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN);
    ASSERT_NE(abms, nullptr);
    AAFwk::Want want;
    std::string sessionId = "testsessionId";
    sptr<AbilityConnectCallbackTest> conn_ = new (std::nothrow) AbilityConnectCallbackTest(sessionId);
    ASSERT_NE(conn_, nullptr);
    EXPECT_EQ(ERR_INVALID_VALUE,
        AbilityManagerAdapter::GetInstance()->DoConnectAbility(nullptr, want, conn_, nullptr, USER_ID));
    EXPECT_EQ(ERR_INVALID_VALUE,
        AbilityManagerAdapter::GetInstance()->DoConnectAbility(abms, want, nullptr, nullptr, USER_ID));
}
