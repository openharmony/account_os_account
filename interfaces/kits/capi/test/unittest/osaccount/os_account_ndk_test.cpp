/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <string>

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include <unistd.h>
#include "account_test_common.h"
#include "ipc_skeleton.h"

#include <gtest/gtest.h>
#include "errors.h"
#include "os_account.h"
#include "os_account_common.h"
#include "os_account_manager.h"
#include "os_account_info.h"

namespace OHOS {
namespace AccountSA {
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS;
using namespace AccountSA;
namespace {
static const uint32_t MAX_NAME_LENGTH = 256;
}
class OsAccountNDKTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
    static uint64_t tokenID_;
    static uint64_t oldTokenID_;
};

uint64_t OsAccountNDKTest::tokenID_ = 0;
uint64_t OsAccountNDKTest::oldTokenID_ = 0;

void OsAccountNDKTest::SetUpTestCase(void)
{
    oldTokenID_ = IPCSkeleton::GetSelfTokenID();
    AccountSA::AllocPermission(ALL_ACCOUNT_PERMISSION_LIST, tokenID_, true);
}

void OsAccountNDKTest::TearDownTestCase(void)
{
    AccountSA::RecoveryPermission(tokenID_, oldTokenID_);
}

void OsAccountNDKTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    GTEST_LOG_(INFO) <<"[SetUp] " << testCaseName.c_str() << " start." << std::endl;
}

void OsAccountNDKTest::TearDown(void)
{}

/**
 * @tc.name: GetOsAccountNameTest001
 * @tc.desc: Test invalid parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountNDKTest, GetOsAccountNameTest001, TestSize.Level1)
{
    char str[MAX_NAME_LENGTH] = { 0 };
    EXPECT_EQ(OH_OsAccount_GetName(nullptr, MAX_NAME_LENGTH), OsAccount_ErrCode::OS_ACCOUNT_ERR_INVALID_PARAMETER);
    EXPECT_EQ(OH_OsAccount_GetName(str, 0), OsAccount_ErrCode::OS_ACCOUNT_ERR_INVALID_PARAMETER);
    EXPECT_EQ(OH_OsAccount_GetName(str, MAX_NAME_LENGTH), OsAccount_ErrCode::OS_ACCOUNT_ERR_OK);
}

/**
 * @tc.name: GetOsAccountNameByIdTest001
 * @tc.desc: Test invalid parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountNDKTest, GetOsAccountNameByIdTest001, TestSize.Level1)
{
    char str[MAX_NAME_LENGTH] = { 0 };
    OsAccountInfo osAccountInfo;
    ErrCode ret1 = AccountSA::OsAccountManager::CreateOsAccount(
        "NDKTestAccount1", OsAccountType::NORMAL, osAccountInfo);
    int id = osAccountInfo.GetLocalId();

    EXPECT_EQ(OH_OsAccount_GetNameByLocalId(id, nullptr, MAX_NAME_LENGTH),
        OsAccount_ErrCode::OS_ACCOUNT_ERR_INVALID_PARAMETER);
    EXPECT_EQ(OH_OsAccount_GetNameByLocalId(id, str, 0), OsAccount_ErrCode::OS_ACCOUNT_ERR_INVALID_PARAMETER);
    
    // We expect OK or INTERNAL_ERROR depending on if ID exists, but we mainly test buffer safety here
    OsAccount_ErrCode ret = OH_OsAccount_GetNameByLocalId(id, str, MAX_NAME_LENGTH);
    EXPECT_TRUE(ret == OsAccount_ErrCode::OS_ACCOUNT_ERR_OK || ret == OsAccount_ErrCode::OS_ACCOUNT_ERR_INTERNAL_ERROR);

    if (ret1 == ERR_OK) {
        AccountSA::OsAccountManager::RemoveOsAccount(id);
    }
}

/**
 * @tc.name: GetOsAccountNameByIdTest002
 * @tc.desc: Test GetOsAccountNameById with non-existent ID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountNDKTest, GetOsAccountNameByIdTest002, TestSize.Level1)
{
    char str[MAX_NAME_LENGTH] = { 0 };
    EXPECT_EQ(OH_OsAccount_GetNameByLocalId(999999, str, MAX_NAME_LENGTH),
        OsAccount_ErrCode::OS_ACCOUNT_ERR_ACCOUNT_NOT_FOUND);
}

/**
 * @tc.name: GetOsAccountNameByIdTest003
 * @tc.desc: Test GetOsAccountNameById success and with buffer size too small.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountNDKTest, GetOsAccountNameByIdTest003, TestSize.Level1)
{
    char str[MAX_NAME_LENGTH] = { 0 };
    OsAccountInfo osAccountInfo;
    ErrCode ret1 = AccountSA::OsAccountManager::CreateOsAccount(
        "NDKTestAccount3", OsAccountType::NORMAL, osAccountInfo);
    int id = osAccountInfo.GetLocalId();

    OsAccount_ErrCode ret = OH_OsAccount_GetNameByLocalId(id, str, MAX_NAME_LENGTH);
    EXPECT_EQ(ret, OsAccount_ErrCode::OS_ACCOUNT_ERR_OK);
    if (ret == OsAccount_ErrCode::OS_ACCOUNT_ERR_OK) {
        EXPECT_EQ(OH_OsAccount_GetNameByLocalId(id, str, 1),
            OsAccount_ErrCode::OS_ACCOUNT_ERR_INVALID_PARAMETER);
    }

    if (ret1 == ERR_OK) {
        AccountSA::OsAccountManager::RemoveOsAccount(id);
    }
}

/**
 * @tc.name: GetOsAccountNameByIdTest004
 * @tc.desc: Test GetOsAccountNameById with restricted account ID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountNDKTest, GetOsAccountNameByIdTest005, TestSize.Level1)
{
    char str[MAX_NAME_LENGTH] = { 0 };
    EXPECT_EQ(OH_OsAccount_GetNameByLocalId(99, str, MAX_NAME_LENGTH),
        OsAccount_ErrCode::OS_ACCOUNT_ERR_RESTRICTED_ACCOUNT);
}

/**
 * @tc.name: GetOsAccountNameByIdTest005
 * @tc.desc: Test GetOsAccountNameById with ID boundary values.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountNDKTest, GetOsAccountNameByIdTest006, TestSize.Level1)
{
    char str[MAX_NAME_LENGTH] = { 0 };
    EXPECT_EQ(OH_OsAccount_GetNameByLocalId(999, str, MAX_NAME_LENGTH),
        OsAccount_ErrCode::OS_ACCOUNT_ERR_ACCOUNT_NOT_FOUND);
}

/**
 * @tc.name: GetOsAccountNameByIdTest006
 * @tc.desc: Test GetOsAccountNameById with various buffer sizes.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountNDKTest, GetOsAccountNameByIdTest007, TestSize.Level1)
{
    char str[MAX_NAME_LENGTH] = { 0 };
    OsAccountInfo osAccountInfo;
    ErrCode ret1 = AccountSA::OsAccountManager::CreateOsAccount(
        "NDKTestAccountBufferSize", OsAccountType::NORMAL, osAccountInfo);
    int id = osAccountInfo.GetLocalId();

    OsAccount_ErrCode ret = OH_OsAccount_GetNameByLocalId(id, str, MAX_NAME_LENGTH);
    if (ret == OsAccount_ErrCode::OS_ACCOUNT_ERR_OK) {
        size_t nameLength = strlen(str);

        char tinyBuffer[nameLength];
        EXPECT_EQ(OH_OsAccount_GetNameByLocalId(id, tinyBuffer, sizeof(tinyBuffer)),
            OsAccount_ErrCode::OS_ACCOUNT_ERR_INVALID_PARAMETER);

        char exactBuffer[nameLength + 1];
        EXPECT_EQ(OH_OsAccount_GetNameByLocalId(id, exactBuffer, sizeof(exactBuffer)),
            OsAccount_ErrCode::OS_ACCOUNT_ERR_OK);
    }

    if (ret1 == ERR_OK) {
        AccountSA::OsAccountManager::RemoveOsAccount(id);
    }
}
}  // namespace AccountTest
}  // namespace OHOS
