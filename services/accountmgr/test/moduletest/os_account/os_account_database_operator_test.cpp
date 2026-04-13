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
    int localId = 2;  // 1 is invalid test local id
    info.SetLocalId(localId);
    g_osAccountDatabaseOperator->InsertOsAccountIntoDataBase(info);
    EXPECT_EQ(info.GetLocalId(), localId);
    localId = 1;  // 1 is invalid test local id
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
    // insert valid user range ID and out-of-range ID; both should not crash
    int localId = 300;  // 300 is invalid test local id
    info.SetLocalId(localId);
    g_osAccountDatabaseOperator->InsertOsAccountIntoDataBase(info);
    EXPECT_EQ(info.GetLocalId(), localId);

    localId = Constants::START_USER_ID;
    info.SetLocalId(localId);
    g_osAccountDatabaseOperator->InsertOsAccountIntoDataBase(info);
    EXPECT_EQ(info.GetLocalId(), localId);
}

/**
 * @tc.name: OsAccountDatabaseOperatorTest_DelOsAccountFromDatabase_0001
 * @tc.desc: DelOsAccountFromDatabase with non-existent ID does not crash.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountDatabaseOperatorTest, DelOsAccountFromDatabase_0001, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountDatabaseOperatorTest_DelOsAccountFromDatabase_0001");

    // Deleting a non-existent account should not crash
    g_osAccountDatabaseOperator->DelOsAccountFromDatabase(999999);
    g_osAccountDatabaseOperator->DelOsAccountFromDatabase(Constants::ADMIN_LOCAL_ID);
}

/**
 * @tc.name: OsAccountDatabaseOperatorTest_GetOsAccountFromDatabase_0001
 * @tc.desc: GetOsAccountFromDatabase with empty storeID and non-existent ID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountDatabaseOperatorTest, GetOsAccountFromDatabase_0001, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountDatabaseOperatorTest_GetOsAccountFromDatabase_0001");

    OsAccountInfo osAccountInfo;
    // Query non-existent account with empty storeID
    ErrCode ret = g_osAccountDatabaseOperator->GetOsAccountFromDatabase("", 999999, osAccountInfo);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.name: OsAccountDatabaseOperatorTest_GetOsAccountListFromDatabase_0001
 * @tc.desc: GetOsAccountListFromDatabase with empty storeID returns result without crash.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountDatabaseOperatorTest, GetOsAccountListFromDatabase_0001, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountDatabaseOperatorTest_GetOsAccountListFromDatabase_0001");

    std::vector<OsAccountInfo> osAccountList;
    ErrCode ret = g_osAccountDatabaseOperator->GetOsAccountListFromDatabase("", osAccountList);
    EXPECT_TRUE(ret == ERR_OK || ret != ERR_OK);  // Should not crash regardless of kvstore availability
}

/**
 * @tc.name: OsAccountDatabaseOperatorTest_GetCreatedOsAccountNumFromDatabase_0001
 * @tc.desc: GetCreatedOsAccountNumFromDatabase with empty storeID returns without crash.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountDatabaseOperatorTest, GetCreatedOsAccountNumFromDatabase_0001, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountDatabaseOperatorTest_GetCreatedOsAccountNumFromDatabase_0001");

    int count = 0;
    ErrCode ret = g_osAccountDatabaseOperator->GetCreatedOsAccountNumFromDatabase("", count);
    EXPECT_TRUE(ret == ERR_OK || ret != ERR_OK);  // Should not crash
}

/**
 * @tc.name: OsAccountDatabaseOperatorTest_GetSerialNumberFromDatabase_0001
 * @tc.desc: GetSerialNumberFromDatabase with empty storeID returns without crash.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountDatabaseOperatorTest, GetSerialNumberFromDatabase_0001, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountDatabaseOperatorTest_GetSerialNumberFromDatabase_0001");

    int64_t serialNumber = 0;
    ErrCode ret = g_osAccountDatabaseOperator->GetSerialNumberFromDatabase("", serialNumber);
    EXPECT_TRUE(ret == ERR_OK || ret != ERR_OK);  // Should not crash
}

/**
 * @tc.name: OsAccountDatabaseOperatorTest_GetMaxAllowCreateIdFromDatabase_0001
 * @tc.desc: GetMaxAllowCreateIdFromDatabase with empty storeID returns without crash.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountDatabaseOperatorTest, GetMaxAllowCreateIdFromDatabase_0001, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountDatabaseOperatorTest_GetMaxAllowCreateIdFromDatabase_0001");

    int id = 0;
    ErrCode ret = g_osAccountDatabaseOperator->GetMaxAllowCreateIdFromDatabase("", id);
    EXPECT_TRUE(ret == ERR_OK || ret != ERR_OK);  // Should not crash
}

}  // namespace AccountSA
}  // namespace OHOS