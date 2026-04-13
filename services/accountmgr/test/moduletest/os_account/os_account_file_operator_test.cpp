/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include <thread>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "os_account_constants.h"
#define private public
#include "os_account_file_operator.h"
#undef private

namespace OHOS {
namespace AccountSA {
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS;
using namespace AccountSA;

namespace {
const std::string STRING_TEST_NAME = "name";
std::shared_ptr<OsAccountFileOperator> g_osAccountFileOperator = nullptr;
}  // namespace

class OsAccountFileOperatorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);
};

void OsAccountFileOperatorTest::SetUpTestCase(void)
{
    g_osAccountFileOperator = std::make_shared<OsAccountFileOperator>();
}

void OsAccountFileOperatorTest::TearDownTestCase(void)
{}

void OsAccountFileOperatorTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void OsAccountFileOperatorTest::TearDown(void)
{}

/**
 * @tc.name: OsAccountFileOperator_CheckConstraints_0001
 * @tc.desc: Return true when constraints is empty.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountFileOperatorTest, CheckConstraints_0001, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountFileOperator_CheckConstraintsList_0001");

    std::vector<std::string> constraints;
    EXPECT_TRUE(g_osAccountFileOperator->CheckConstraints(constraints));
}

/**
 * @tc.name: OsAccountFileOperator_CheckConstraints_0002
 * @tc.desc: Return true for the valid constraints.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountFileOperatorTest, CheckConstraints_0002, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountFileOperator_CheckConstraintsList_0002");

    // valid constraint returns true; invalid constraint returns false
    std::vector<std::string> valid = { "constraint.os.account.create" };
    EXPECT_TRUE(g_osAccountFileOperator->CheckConstraints(valid));

    std::vector<std::string> invalid = { "constraint.invalid.not.exist.xyz" };
    EXPECT_FALSE(g_osAccountFileOperator->CheckConstraints(invalid));
}

/**
 * @tc.name: OsAccountFileOperator_GetConstraintsByType_0001
 * @tc.desc: Get constraints list for NORMAL and ADMIN account type.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountFileOperatorTest, GetConstraintsByType_0001, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountFileOperator_GetConstraintsByType_0001");

    std::vector<std::string> constraints;
    // Type 1 = ADMIN, type 2 = NORMAL; both should succeed
    ErrCode ret = g_osAccountFileOperator->GetConstraintsByType(OsAccountType::NORMAL, constraints);
    EXPECT_EQ(ret, ERR_OK);

    constraints.clear();
    ret = g_osAccountFileOperator->GetConstraintsByType(OsAccountType::ADMIN, constraints);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: OsAccountFileOperator_GetIsMultiOsAccountEnable_0001
 * @tc.desc: GetIsMultiOsAccountEnable returns ERR_OK and a valid bool.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountFileOperatorTest, GetIsMultiOsAccountEnable_0001, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountFileOperator_GetIsMultiOsAccountEnable_0001");

    bool isMultiEnable = false;
    ErrCode ret = g_osAccountFileOperator->GetIsMultiOsAccountEnable(isMultiEnable);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: OsAccountFileOperator_IsAllowedCreateAdmin_0001
 * @tc.desc: IsAllowedCreateAdmin returns ERR_OK and a valid bool.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountFileOperatorTest, IsAllowedCreateAdmin_0001, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountFileOperator_IsAllowedCreateAdmin_0001");

    bool isAllowed = false;
    ErrCode ret = g_osAccountFileOperator->IsAllowedCreateAdmin(isAllowed);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: OsAccountFileOperator_GetGlobalOAConstraintsList_0001
 * @tc.desc: GetGlobalOAConstraintsList returns without crash.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountFileOperatorTest, GetGlobalOAConstraintsList_0001, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountFileOperator_GetGlobalOAConstraintsList_0001");

    std::vector<std::string> constraints;
    ErrCode ret = g_osAccountFileOperator->GetGlobalOAConstraintsList(constraints);
    EXPECT_TRUE(ret == ERR_OK || ret == ERR_OSACCOUNT_SERVICE_GET_DATA_FROM_GLOBAL_CONSTRAINTS_FILE_EMPTY);
}

/**
 * @tc.name: OsAccountFileOperator_GetSpecificOAConstraintsList_0001
 * @tc.desc: GetSpecificOAConstraintsList for admin and normal accounts.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountFileOperatorTest, GetSpecificOAConstraintsList_0001, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountFileOperator_GetSpecificOAConstraintsList_0001");

    std::vector<std::string> constraints;
    ErrCode ret = g_osAccountFileOperator->GetSpecificOAConstraintsList(
        Constants::ADMIN_LOCAL_ID, constraints);
    EXPECT_TRUE(ret == ERR_OK || ret == ERR_OSACCOUNT_SERVICE_GET_DATA_FROM_SPECIFIC_CONSTRAINTS_FILE_EMPTY);

    constraints.clear();
    ret = g_osAccountFileOperator->GetSpecificOAConstraintsList(
        Constants::START_USER_ID, constraints);
    EXPECT_TRUE(ret == ERR_OK || ret == ERR_OSACCOUNT_SERVICE_GET_DATA_FROM_SPECIFIC_CONSTRAINTS_FILE_EMPTY);
}
}  // namespace AccountSA
}  // namespace OHOS