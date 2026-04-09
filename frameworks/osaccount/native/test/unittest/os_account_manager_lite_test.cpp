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

#include "account_test_common.h"
#include "ipc_skeleton.h"
#include "os_account_manager_lite.h"
#include "os_account_manager.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
constexpr int32_t MAIN_ACCOUNT_ID = 100;
uint64_t g_selfTokenId = 0;
uint64_t g_accountTokenId = 0;
}

class OsAccountManagerLiteTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void OsAccountManagerLiteTest::SetUpTestCase(void)
{
    g_selfTokenId = IPCSkeleton::GetSelfTokenID();
    g_accountTokenId = GetAllAccountPermission();
    ASSERT_NE(g_accountTokenId, 0);
}

void OsAccountManagerLiteTest::TearDownTestCase(void)
{
    if (g_accountTokenId != 0) {
        ASSERT_TRUE(RecoveryPermission(g_accountTokenId, g_selfTokenId));
    }
}

HWTEST_F(OsAccountManagerLiteTest, GetForegroundOsAccountLocalId001, TestSize.Level1)
{
    ASSERT_EQ(OsAccountManager::ActivateOsAccount(MAIN_ACCOUNT_ID), ERR_OK);

    int32_t localId = -1;
    EXPECT_EQ(OsAccountManagerLite::GetForegroundOsAccountLocalId(localId), ERR_OK);
    EXPECT_EQ(localId, MAIN_ACCOUNT_ID);
}

HWTEST_F(OsAccountManagerLiteTest, GetForegroundOsAccountLocalId002, TestSize.Level1)
{
    ASSERT_EQ(OsAccountManager::ActivateOsAccount(MAIN_ACCOUNT_ID), ERR_OK);

    int32_t localId = -1;
    int32_t localIdSecond = -1;
    EXPECT_EQ(OsAccountManagerLite::GetForegroundOsAccountLocalId(localId), ERR_OK);
    EXPECT_EQ(OsAccountManagerLite::GetForegroundOsAccountLocalId(localIdSecond), ERR_OK);
    EXPECT_EQ(localId, MAIN_ACCOUNT_ID);
    EXPECT_EQ(localIdSecond, MAIN_ACCOUNT_ID);
    EXPECT_EQ(localId, localIdSecond);
}

/**
 * @tc.name: GetForegroundOsAccountLocalIdCompare001
 * @tc.desc: Test lite interface result is consistent with OsAccountManager in main account.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerLiteTest, GetForegroundOsAccountLocalIdCompare001, TestSize.Level1)
{
    ASSERT_EQ(OsAccountManager::ActivateOsAccount(MAIN_ACCOUNT_ID), ERR_OK);

    int32_t liteLocalId = -1;
    int32_t managerLocalId = -1;
    ErrCode liteResult = OsAccountManagerLite::GetForegroundOsAccountLocalId(liteLocalId);
    ErrCode managerResult = OsAccountManager::GetForegroundOsAccountLocalId(managerLocalId);

    EXPECT_EQ(liteResult, managerResult);
    EXPECT_EQ(liteLocalId, managerLocalId);
}

#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
/**
 * @tc.name: GetForegroundOsAccountLocalId003
 * @tc.desc: Test lite interface result is consistent with OsAccountManager after account switch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerLiteTest, GetForegroundOsAccountLocalId003, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    int32_t createdLocalId = -1;
    ASSERT_EQ(CreateOsAccountForTest(
        "GetForegroundOsAccountLocalId003", "GetForegroundOsAccountLocalId003", OsAccountType::NORMAL, osAccountInfo),
        ERR_OK);
    createdLocalId = osAccountInfo.GetLocalId();

    ASSERT_EQ(OsAccountManager::ActivateOsAccount(MAIN_ACCOUNT_ID), ERR_OK);
    int32_t localId = -1;
    EXPECT_EQ(OsAccountManagerLite::GetForegroundOsAccountLocalId(localId), ERR_OK);
    EXPECT_EQ(localId, MAIN_ACCOUNT_ID);

    ASSERT_EQ(OsAccountManager::ActivateOsAccount(osAccountInfo.GetLocalId()), ERR_OK);
    EXPECT_EQ(OsAccountManagerLite::GetForegroundOsAccountLocalId(localId), ERR_OK);
    EXPECT_EQ(localId, osAccountInfo.GetLocalId());
    int32_t managerLocalId = -1;
    EXPECT_EQ(OsAccountManager::GetForegroundOsAccountLocalId(managerLocalId), ERR_OK);
    EXPECT_EQ(localId, managerLocalId);

    ASSERT_EQ(OsAccountManager::ActivateOsAccount(MAIN_ACCOUNT_ID), ERR_OK);
    EXPECT_EQ(OsAccountManagerLite::GetForegroundOsAccountLocalId(localId), ERR_OK);
    EXPECT_EQ(localId, MAIN_ACCOUNT_ID);
    EXPECT_EQ(OsAccountManager::GetForegroundOsAccountLocalId(managerLocalId), ERR_OK);
    EXPECT_EQ(localId, managerLocalId);

    if (createdLocalId >= 0) {
        EXPECT_EQ(OsAccountManager::ActivateOsAccount(MAIN_ACCOUNT_ID), ERR_OK);
        EXPECT_EQ(OsAccountManager::DeactivateOsAccount(createdLocalId), ERR_OK);
        EXPECT_EQ(RemoveOsAccountForTest(createdLocalId), ERR_OK);
    }
}
#endif
