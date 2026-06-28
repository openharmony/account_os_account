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
#include <unistd.h>

#include "account_test_common.h"
#include "ipc_skeleton.h"
#include "os_account_manager_lite.h"
#include "os_account_subprofile_client.h"
#include "os_account_manager.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
constexpr int32_t MAIN_ACCOUNT_ID = 100;
constexpr int32_t TEST_NON_EXIST_ACCOUNT_ID = 200;
constexpr int32_t TEST_UID_USER_100 = MAIN_ACCOUNT_ID * 200000;
constexpr int32_t TEST_SUB_PROFILE_ID_BASE = MAIN_ACCOUNT_ID * 1000 + 1;
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

/**
 * @tc.name: GetOsAccountSubProfileIdByAppIndex001
 * @tc.desc: Test GetOsAccountSubProfileId by localId and appIndex returns correct subProfileId on main account.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerLiteTest, GetOsAccountSubProfileIdByAppIndex001, TestSize.Level1)
{
    int32_t subProfileId = -1;
    EXPECT_EQ(OsAccountManagerLite::GetOsAccountSubProfileId(MAIN_ACCOUNT_ID, 0, subProfileId), ERR_OK);
    EXPECT_EQ(subProfileId, TEST_SUB_PROFILE_ID_BASE);
}

/**
 * @tc.name: GetOsAccountSubProfileIdByAppIndex002
 * @tc.desc: Test GetOsAccountSubProfileId by localId and appIndex returns error on non-existent account.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerLiteTest, GetOsAccountSubProfileIdByAppIndex002, TestSize.Level1)
{
    int32_t subProfileId = -1;
    ErrCode ret = OsAccountManagerLite::GetOsAccountSubProfileId(TEST_NON_EXIST_ACCOUNT_ID, 0, subProfileId);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
    EXPECT_EQ(subProfileId, -1);
}

/**
 * @tc.name: GetOsAccountSubProfileIdByAppIndex003
 * @tc.desc: Test GetOsAccountSubProfileId by localId and appIndex returns error on restricted account (user 0).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerLiteTest, GetOsAccountSubProfileIdByAppIndex003, TestSize.Level1)
{
    int32_t subProfileId = -1;
    ErrCode ret = OsAccountManagerLite::GetOsAccountSubProfileId(0, 0, subProfileId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
}

/**
 * @tc.name: GetOsAccountSubProfileIdByAppIndex004
 * @tc.desc: Test GetOsAccountSubProfileId by localId and appIndex returns error on non-existent appIndex.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerLiteTest, GetOsAccountSubProfileIdByAppIndex004, TestSize.Level1)
{
    int32_t subProfileId = -1;
    ErrCode ret = OsAccountManagerLite::GetOsAccountSubProfileId(
        MAIN_ACCOUNT_ID, -1, subProfileId);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: GetOsAccountSubProfileIdByTokenId001
 * @tc.desc: Test GetOsAccountSubProfileId by tokenId returns correct subProfileId for user 100.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerLiteTest, GetOsAccountSubProfileIdByTokenId001, TestSize.Level1)
{
    ASSERT_EQ(0, setuid(TEST_UID_USER_100));

    int32_t subProfileId = -1;
    EXPECT_EQ(OsAccountManagerLite::GetOsAccountSubProfileId(
        static_cast<uint32_t>(IPCSkeleton::GetCallingTokenID()), subProfileId), ERR_OK);
    EXPECT_EQ(subProfileId, TEST_SUB_PROFILE_ID_BASE);

    ASSERT_EQ(0, setuid(0));
}

/**
 * @tc.name: GetOsAccountSubProfileIdByTokenId002
 * @tc.desc: Test GetOsAccountSubProfileId by tokenId returns error on invalid token (0).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerLiteTest, GetOsAccountSubProfileIdByTokenId002, TestSize.Level1)
{
    int32_t subProfileId = -1;
    ErrCode ret = OsAccountManagerLite::GetOsAccountSubProfileId(static_cast<uint32_t>(0), subProfileId);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: GetOsAccountSubProfileIdConsistency001
 * @tc.desc: Test lite interface result is consistent between localId+appIndex and tokenId overloads on main account.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerLiteTest, GetOsAccountSubProfileIdConsistency001, TestSize.Level1)
{
    ASSERT_EQ(0, setuid(TEST_UID_USER_100));

    int32_t subProfileIdByIndex = -1;
    int32_t subProfileIdByToken = -1;
    EXPECT_EQ(OsAccountManagerLite::GetOsAccountSubProfileId(MAIN_ACCOUNT_ID, 0, subProfileIdByIndex), ERR_OK);
    EXPECT_EQ(OsAccountManagerLite::GetOsAccountSubProfileId(
        static_cast<uint32_t>(IPCSkeleton::GetCallingTokenID()), subProfileIdByToken), ERR_OK);
    EXPECT_EQ(subProfileIdByIndex, subProfileIdByToken);
    EXPECT_EQ(subProfileIdByIndex, TEST_SUB_PROFILE_ID_BASE);

    ASSERT_EQ(0, setuid(0));
}

/**
 * @tc.name: GetOsAccountSubProfileIndex001
 * @tc.desc: Test GetOsAccountSubProfileIndex returns correct index for headless subProfileId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerLiteTest, GetOsAccountSubProfileIndex001, TestSize.Level1)
{
    int32_t index = -1;
    EXPECT_EQ(OsAccountManagerLite::GetOsAccountSubProfileIndex(
        MAIN_ACCOUNT_ID, TEST_SUB_PROFILE_ID_BASE, index), ERR_OK);
    EXPECT_EQ(index, 0);
}

/**
 * @tc.name: GetOsAccountSubProfileIndex002
 * @tc.desc: Test GetOsAccountSubProfileIndex returns error on non-existent account.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerLiteTest, GetOsAccountSubProfileIndex002, TestSize.Level1)
{
    int32_t index = -1;
    ErrCode ret = OsAccountManagerLite::GetOsAccountSubProfileIndex(
        TEST_NON_EXIST_ACCOUNT_ID, TEST_NON_EXIST_ACCOUNT_ID * 1000, index);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
    EXPECT_EQ(index, -1);
}

/**
 * @tc.name: GetOsAccountSubProfileIndex003
 * @tc.desc: Test GetOsAccountSubProfileIndex returns error on restricted account (user 0).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerLiteTest, GetOsAccountSubProfileIndex003, TestSize.Level1)
{
    int32_t index = -1;
    ErrCode ret = OsAccountManagerLite::GetOsAccountSubProfileIndex(0, 0, index);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
}

/**
 * @tc.name: GetOsAccountSubProfileIndex004
 * @tc.desc: Test GetOsAccountSubProfileIndex returns error on mismatched subProfileId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerLiteTest, GetOsAccountSubProfileIndex004, TestSize.Level1)
{
    int32_t index = -1;
    ErrCode ret = OsAccountManagerLite::GetOsAccountSubProfileIndex(
        MAIN_ACCOUNT_ID, TEST_NON_EXIST_ACCOUNT_ID * 1000, index);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
}

/**
 * @tc.name: GetOsAccountSubProfileIndex005
 * @tc.desc: Test GetOsAccountSubProfileIndex returns error on non-existent subspace.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerLiteTest, GetOsAccountSubProfileIndex005, TestSize.Level1)
{
    int32_t index = -1;
    ErrCode ret = OsAccountManagerLite::GetOsAccountSubProfileIndex(
        MAIN_ACCOUNT_ID, MAIN_ACCOUNT_ID * 1000 + 999, index);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
}

/**
 * @tc.name: GetOsAccountSubProfileIndexConsistency001
 * @tc.desc: Test lite interface result is consistent with OsAccountSubProfileClient on main account.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerLiteTest, GetOsAccountSubProfileIndexConsistency001, TestSize.Level1)
{
    int32_t liteIndex = -1;
    int32_t clientIndex = -1;
    ErrCode liteResult = OsAccountManagerLite::GetOsAccountSubProfileIndex(
        MAIN_ACCOUNT_ID, TEST_SUB_PROFILE_ID_BASE, liteIndex);
    ErrCode clientResult = OsAccountSubProfileClient::GetInstance().GetOsAccountSubProfileIndex(
        MAIN_ACCOUNT_ID, TEST_SUB_PROFILE_ID_BASE, clientIndex);
    EXPECT_EQ(liteResult, clientResult);
    EXPECT_EQ(liteIndex, clientIndex);
}

/**
 * @tc.name: GetOsAccountForegroundSubProfileId001
 * @tc.desc: Test GetOsAccountForegroundSubProfileId returns correct subProfileId for main account.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerLiteTest, GetOsAccountForegroundSubProfileId001, TestSize.Level1)
{
    int32_t subProfileId = -1;
    EXPECT_EQ(OsAccountManagerLite::GetOsAccountForegroundSubProfileId(
        MAIN_ACCOUNT_ID, subProfileId), ERR_OK);
    EXPECT_GT(subProfileId, 0);
}

/**
 * @tc.name: GetOsAccountForegroundSubProfileId002
 * @tc.desc: Test GetOsAccountForegroundSubProfileId returns error on non-existent account.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerLiteTest, GetOsAccountForegroundSubProfileId002, TestSize.Level1)
{
    int32_t subProfileId = -1;
    ErrCode ret = OsAccountManagerLite::GetOsAccountForegroundSubProfileId(
        TEST_NON_EXIST_ACCOUNT_ID, subProfileId);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
    EXPECT_EQ(subProfileId, -1);
}

/**
 * @tc.name: GetOsAccountForegroundSubProfileId003
 * @tc.desc: Test GetOsAccountForegroundSubProfileId returns error on restricted account (user 0).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerLiteTest, GetOsAccountForegroundSubProfileId003, TestSize.Level1)
{
    int32_t subProfileId = -1;
    ErrCode ret = OsAccountManagerLite::GetOsAccountForegroundSubProfileId(0, subProfileId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
}

/**
 * @tc.name: GetOsAccountLocalIdForSubProfile001
 * @tc.desc: Test GetOsAccountLocalIdForSubProfile returns correct osAccountId for headless subProfileId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerLiteTest, GetOsAccountLocalIdForSubProfile001, TestSize.Level1)
{
    int32_t osAccountId = -1;
    EXPECT_EQ(OsAccountManagerLite::GetOsAccountLocalIdForSubProfile(
        TEST_SUB_PROFILE_ID_BASE, osAccountId), ERR_OK);
    EXPECT_EQ(osAccountId, MAIN_ACCOUNT_ID);
}

/**
 * @tc.name: GetOsAccountLocalIdForSubProfile002
 * @tc.desc: Test GetOsAccountLocalIdForSubProfile returns error on non-existent subProfileId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerLiteTest, GetOsAccountLocalIdForSubProfile002, TestSize.Level1)
{
    int32_t osAccountId = -1;
    ErrCode ret = OsAccountManagerLite::GetOsAccountLocalIdForSubProfile(
        TEST_NON_EXIST_ACCOUNT_ID * 1000, osAccountId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
    EXPECT_EQ(osAccountId, -1);
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
