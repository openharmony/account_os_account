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
#include "os_account_control_file_manager.h"
#undef private

namespace OHOS {
namespace AccountSA {
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS;
using namespace AccountSA;

namespace {
const std::string STRING_TEST_NAME = "name";
}  // namespace

class OsAccountControlFileManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);
};

void OsAccountControlFileManagerTest::SetUpTestCase(void)
{}

void OsAccountControlFileManagerTest::TearDownTestCase(void)
{}

void OsAccountControlFileManagerTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void OsAccountControlFileManagerTest::TearDown(void)
{}

/**
 * @tc.name: OsAccountControlFileManager_GetValidAccountID_0001
 * @tc.desc: Test CreateOsAccount when create max accounts.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerTest, GetValidAccountID_0001, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountControlFileManager_GetValidAccountID_0001");

    std::string dirName = "";
    std::int32_t accountID = Constants::INVALID_OS_ACCOUNT_ID;
    ErrCode ret = OHOS::AccountSA::GetValidAccountID(dirName, accountID);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: OsAccountControlFileManager_GetValidAccountID_0002
 * @tc.desc: Test CreateOsAccount when create max accounts.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerTest, GetValidAccountID_0002, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountControlFileManager_GetValidAccountID_0002");

    std::string dirName = "namehahahahahaha";
    std::int32_t accountID = Constants::INVALID_OS_ACCOUNT_ID;

    ErrCode ret = OHOS::AccountSA::GetValidAccountID(dirName, accountID);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: OsAccountControlFileManager_GetValidAccountID_0003
 * @tc.desc: Test CreateOsAccount when create max accounts.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerTest, GetValidAccountID_0003, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountControlFileManager_GetValidAccountID_0003");

    std::string dirName = "1";
    std::int32_t accountID = Constants::INVALID_OS_ACCOUNT_ID;

    ErrCode ret = OHOS::AccountSA::GetValidAccountID(dirName, accountID);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: OsAccountControlFileManager_GetValidAccountID_0004
 * @tc.desc: Test CreateOsAccount when create max accounts.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerTest, GetValidAccountID_0004, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountControlFileManager_GetValidAccountID_0004");

    std::string dirName = "na";
    std::int32_t accountID = Constants::INVALID_OS_ACCOUNT_ID;

    ErrCode ret = OHOS::AccountSA::GetValidAccountID(dirName, accountID);
    EXPECT_EQ(ret, false);
}

}  // namespace AccountSA
}  // namespace OHOS