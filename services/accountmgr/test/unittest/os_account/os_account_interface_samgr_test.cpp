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

#include <gtest/gtest.h>

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "errors.h"
#include "ipc_object_stub.h"
#include "iservice_registry_mock_helper.h"
#include "mock_system_ability_manager.h"
#include "os_account_subscribe_info.h"
#include "system_ability_definition.h"
#define private public
#include "os_account_interface.h"
#undef private

using namespace testing::ext;

namespace {
constexpr int32_t TEST_LOCAL_ID = 100;
constexpr int32_t TEST_ERROR_CODE = 12345;
}

namespace OHOS {
namespace AccountSA {

class OsAccountInterfaceSamgrTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void OsAccountInterfaceSamgrTest::SetUpTestCase(void)
{
}

void OsAccountInterfaceSamgrTest::TearDownTestCase(void)
{
}

void OsAccountInterfaceSamgrTest::SetUp(void)
{
}

void OsAccountInterfaceSamgrTest::TearDown(void)
{
    ResetMockSystemAbilityManager();
}

/**
 * @tc.name: SendToSamgrUserState_Activating_Success_001
 * @tc.desc: Test SendToSamgrUserState with ACTIVATING state, success scenario
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInterfaceSamgrTest, SendToSamgrUserState_Activating_Success_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendToSamgrUserState_Activating_Success_001 start";
    auto mockManager = new MockSystemAbilityManager();
    mockManager->SetMockResult(ERR_OK);
    SetMockSystemAbilityManager(mockManager);

    ErrCode result = OsAccountInterface::SendToSamgrUserState(TEST_LOCAL_ID,
        OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATING);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "SendToSamgrUserState_Activating_Success_001 end";
}

/**
 * @tc.name: SendToSamgrUserState_Switching_Success_001
 * @tc.desc: Test SendToSamgrUserState with SWITCHING state, success scenario
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInterfaceSamgrTest, SendToSamgrUserState_Switching_Success_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendToSamgrUserState_Switching_Success_001 start";
    sptr<MockSystemAbilityManager> mockManager = new MockSystemAbilityManager();
    mockManager->SetMockResult(ERR_OK);
    SetMockSystemAbilityManager(mockManager);

    ErrCode result = OsAccountInterface::SendToSamgrUserState(TEST_LOCAL_ID,
        OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHING);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "SendToSamgrUserState_Switching_Success_001 end";
}

/**
 * @tc.name: SendToSamgrUserState_Stopping_Success_001
 * @tc.desc: Test SendToSamgrUserState with STOPPING state, success scenario
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInterfaceSamgrTest, SendToSamgrUserState_Stopping_Success_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendToSamgrUserState_Stopping_Success_001 start";
    sptr<MockSystemAbilityManager> mockManager = new MockSystemAbilityManager();
    mockManager->SetMockResult(ERR_OK);
    SetMockSystemAbilityManager(mockManager);

    ErrCode result = OsAccountInterface::SendToSamgrUserState(TEST_LOCAL_ID,
        OS_ACCOUNT_SUBSCRIBE_TYPE::STOPPING);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "SendToSamgrUserState_Stopping_Success_001 end";
}

/**
 * @tc.name: SendToSamgrUserState_InvalidState_001
 * @tc.desc: Test SendToSamgrUserState with invalid state (default branch)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInterfaceSamgrTest, SendToSamgrUserState_InvalidState_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendToSamgrUserState_InvalidState_001 start";
    OsAccountState invalidState = static_cast<OsAccountState>(999);

    ErrCode result = OsAccountInterface::SendToSamgrUserState(TEST_LOCAL_ID, invalidState);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "SendToSamgrUserState_InvalidState_001 end";
}

/**
 * @tc.name: SendToSamgrUserState_GetSystemAbilityManagerFailed_001
 * @tc.desc: Test SendToSamgrUserState when GetSystemAbilityManager returns nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInterfaceSamgrTest, SendToSamgrUserState_GetSystemAbilityManagerFailed_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendToSamgrUserState_GetSystemAbilityManagerFailed_001 start";
    SetMockSystemAbilityManager(nullptr);

    ErrCode result = OsAccountInterface::SendToSamgrUserState(TEST_LOCAL_ID,
        OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATING);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER);
    GTEST_LOG_(INFO) << "SendToSamgrUserState_GetSystemAbilityManagerFailed_001 end";
}

/**
 * @tc.name: SendToSamgrUserState_OnUserStateChangedFailed_001
 * @tc.desc: Test SendToSamgrUserState when OnUserStateChanged returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInterfaceSamgrTest, SendToSamgrUserState_OnUserStateChangedFailed_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendToSamgrUserState_OnUserStateChangedFailed_001 start";
    sptr<MockSystemAbilityManager> mockManager = new MockSystemAbilityManager();
    mockManager->SetMockResult(TEST_ERROR_CODE);
    SetMockSystemAbilityManager(mockManager);

    ErrCode result = OsAccountInterface::SendToSamgrUserState(TEST_LOCAL_ID,
        OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATING);
    EXPECT_EQ(result, ERR_OSACCOUNT_SERVICE_SAMGR_USER_STATE_FAILED);
    GTEST_LOG_(INFO) << "SendToSamgrUserState_OnUserStateChangedFailed_001 end";
}

/**
 * @tc.name: SendToSamgrUserState_OnUserStateChangedFailed_Switching_001
 * @tc.desc: Test SendToSamgrUserState with SWITCHING state when OnUserStateChanged returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInterfaceSamgrTest, SendToSamgrUserState_OnUserStateChangedFailed_Switching_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendToSamgrUserState_OnUserStateChangedFailed_Switching_001 start";
    sptr<MockSystemAbilityManager> mockManager = new MockSystemAbilityManager();
    mockManager->SetMockResult(TEST_ERROR_CODE);
    SetMockSystemAbilityManager(mockManager);

    ErrCode result = OsAccountInterface::SendToSamgrUserState(TEST_LOCAL_ID,
        OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHING);
    EXPECT_EQ(result, ERR_OSACCOUNT_SERVICE_SAMGR_USER_STATE_FAILED);
    GTEST_LOG_(INFO) << "SendToSamgrUserState_OnUserStateChangedFailed_Switching_001 end";
}

/**
 * @tc.name: SendToSamgrUserState_OnUserStateChangedFailed_Stopping_001
 * @tc.desc: Test SendToSamgrUserState with STOPPING state when OnUserStateChanged returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInterfaceSamgrTest, SendToSamgrUserState_OnUserStateChangedFailed_Stopping_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendToSamgrUserState_OnUserStateChangedFailed_Stopping_001 start";
    sptr<MockSystemAbilityManager> mockManager = new MockSystemAbilityManager();
    mockManager->SetMockResult(TEST_ERROR_CODE);
    SetMockSystemAbilityManager(mockManager);

    ErrCode result = OsAccountInterface::SendToSamgrUserState(TEST_LOCAL_ID,
        OS_ACCOUNT_SUBSCRIBE_TYPE::STOPPING);
    EXPECT_EQ(result, ERR_OSACCOUNT_SERVICE_SAMGR_USER_STATE_FAILED);
    GTEST_LOG_(INFO) << "SendToSamgrUserState_OnUserStateChangedFailed_Stopping_001 end";
}

/**
 * @tc.name: SendToSamgrUserState_BoundaryLocalId_001
 * @tc.desc: Test SendToSamgrUserState with boundary localId value (0)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInterfaceSamgrTest, SendToSamgrUserState_BoundaryLocalId_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendToSamgrUserState_BoundaryLocalId_001 start";
    sptr<MockSystemAbilityManager> mockManager = new MockSystemAbilityManager();
    mockManager->SetMockResult(ERR_OK);
    SetMockSystemAbilityManager(mockManager);

    ErrCode result = OsAccountInterface::SendToSamgrUserState(0,
        OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATING);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "SendToSamgrUserState_BoundaryLocalId_001 end";
}

/**
 * @tc.name: SendToSamgrUserState_BoundaryLocalId_Negative_001
 * @tc.desc: Test SendToSamgrUserState with negative localId value (-1)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInterfaceSamgrTest, SendToSamgrUserState_BoundaryLocalId_Negative_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendToSamgrUserState_BoundaryLocalId_Negative_001 start";
    sptr<MockSystemAbilityManager> mockManager = new MockSystemAbilityManager();
    mockManager->SetMockResult(ERR_OK);
    SetMockSystemAbilityManager(mockManager);

    ErrCode result = OsAccountInterface::SendToSamgrUserState(-1,
        OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATING);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "SendToSamgrUserState_BoundaryLocalId_Negative_001 end";
}

/**
 * @tc.name: SendToSamgrUserState_LargeLocalId_001
 * @tc.desc: Test SendToSamgrUserState with large localId value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInterfaceSamgrTest, SendToSamgrUserState_LargeLocalId_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendToSamgrUserState_LargeLocalId_001 start";
    sptr<MockSystemAbilityManager> mockManager = new MockSystemAbilityManager();
    mockManager->SetMockResult(ERR_OK);
    SetMockSystemAbilityManager(mockManager);

    ErrCode result = OsAccountInterface::SendToSamgrUserState(9999,
        OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATING);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "SendToSamgrUserState_LargeLocalId_001 end";
}

/**
 * @tc.name: SendToSamgrUserState_Activating_WithErrorResult_001
 * @tc.desc: Test SendToSamgrUserState with ACTIVATING state when OnUserStateChanged returns specific error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInterfaceSamgrTest, SendToSamgrUserState_Activating_WithErrorResult_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendToSamgrUserState_Activating_WithErrorResult_001 start";
    sptr<MockSystemAbilityManager> mockManager = new MockSystemAbilityManager();
    mockManager->SetMockResult(ERR_INVALID_VALUE);
    SetMockSystemAbilityManager(mockManager);

    ErrCode result = OsAccountInterface::SendToSamgrUserState(TEST_LOCAL_ID,
        OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATING);
    EXPECT_EQ(result, ERR_OSACCOUNT_SERVICE_SAMGR_USER_STATE_FAILED);
    GTEST_LOG_(INFO) << "SendToSamgrUserState_Activating_WithErrorResult_001 end";
}

/**
 * @tc.name: SendToSamgrUserState_MultipleCalls_001
 * @tc.desc: Test SendToSamgrUserState with multiple sequential calls
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInterfaceSamgrTest, SendToSamgrUserState_MultipleCalls_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendToSamgrUserState_MultipleCalls_001 start";
    sptr<MockSystemAbilityManager> mockManager = new MockSystemAbilityManager();
    mockManager->SetMockResult(ERR_OK);
    SetMockSystemAbilityManager(mockManager);

    ErrCode result1 = OsAccountInterface::SendToSamgrUserState(TEST_LOCAL_ID,
        OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATING);
    EXPECT_EQ(result1, ERR_OK);

    ErrCode result2 = OsAccountInterface::SendToSamgrUserState(TEST_LOCAL_ID,
        OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHING);
    EXPECT_EQ(result2, ERR_OK);

    ErrCode result3 = OsAccountInterface::SendToSamgrUserState(TEST_LOCAL_ID,
        OS_ACCOUNT_SUBSCRIBE_TYPE::STOPPING);
    EXPECT_EQ(result3, ERR_OK);
    GTEST_LOG_(INFO) << "SendToSamgrUserState_MultipleCalls_001 end";
}

/**
 * @tc.name: SendToSamgrUserState_DynamicResultChange_001
 * @tc.desc: Test SendToSamgrUserState with dynamic result change via SetMockResult
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInterfaceSamgrTest, SendToSamgrUserState_DynamicResultChange_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendToSamgrUserState_DynamicResultChange_001 start";
    sptr<MockSystemAbilityManager> mockManager = new MockSystemAbilityManager();
    mockManager->SetMockResult(ERR_OK);
    SetMockSystemAbilityManager(mockManager);

    ErrCode result1 = OsAccountInterface::SendToSamgrUserState(TEST_LOCAL_ID,
        OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATING);
    EXPECT_EQ(result1, ERR_OK);

    mockManager->SetMockResult(TEST_ERROR_CODE);
    ErrCode result2 = OsAccountInterface::SendToSamgrUserState(TEST_LOCAL_ID,
        OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATING);
    EXPECT_EQ(result2, ERR_OSACCOUNT_SERVICE_SAMGR_USER_STATE_FAILED);

    mockManager->SetMockResult(ERR_OK);
    ErrCode result3 = OsAccountInterface::SendToSamgrUserState(TEST_LOCAL_ID,
        OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATING);
    EXPECT_EQ(result3, ERR_OK);
    GTEST_LOG_(INFO) << "SendToSamgrUserState_DynamicResultChange_001 end";
}
}  // namespace AccountSA
}  // namespace OHOS