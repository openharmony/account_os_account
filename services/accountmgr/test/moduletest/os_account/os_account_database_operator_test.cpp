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
#include "os_account_database_operator.h"
#undef private

namespace OHOS {
namespace AccountSA {
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS;
using namespace AccountSA;

namespace {
const std::string STRING_TEST_NAME = "name";
std::shared_ptr<OsAccountDatabaseOperator> g_osAccountDatabaseOperator = nullptr;
}  // namespace

class OsAccountDatabaseOperatorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);
};

void OsAccountDatabaseOperatorTest::SetUpTestCase(void)
{
    g_osAccountDatabaseOperator = std::make_shared<OsAccountDatabaseOperator>();
}

void OsAccountDatabaseOperatorTest::TearDownTestCase(void)
{}

void OsAccountDatabaseOperatorTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void OsAccountDatabaseOperatorTest::TearDown(void)
{}

/**
 * @tc.name: OsAccountDatabaseOperatorTest_InsertOsAccountIntoDataBase_0001
 * @tc.desc: Test CreateOsAccount when create max accounts.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountDatabaseOperatorTest, InsertOsAccountIntoDataBase_0001, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountDatabaseOperatorTest_InsertOsAccountIntoDataBase_0001");

    OsAccountInfo info;
    int localId = 1;  // 1 is invalid test local id
    info.SetLocalId(localId);
    g_osAccountDatabaseOperator->InsertOsAccountIntoDataBase(info);
    EXPECT_EQ(info.GetLocalId(), localId);
}

/**
 * @tc.name: OsAccountDatabaseOperatorTest_InsertOsAccountIntoDataBase_0002
 * @tc.desc: Test CreateOsAccount when create max accounts.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountDatabaseOperatorTest, InsertOsAccountIntoDataBase_0002, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountDatabaseOperatorTest_InsertOsAccountIntoDataBase_0002");

    OsAccountInfo info;
    int localId = 300;  // 300 is invalid test local id
    info.SetLocalId(localId);
    g_osAccountDatabaseOperator->InsertOsAccountIntoDataBase(info);
    EXPECT_EQ(info.GetLocalId(), localId);
}

}  // namespace AccountSA
}  // namespace OHOS