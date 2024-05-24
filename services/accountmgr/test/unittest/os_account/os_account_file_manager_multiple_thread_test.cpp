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

#include <gtest/gtest.h>
#include <gtest/hwext/gtest-multithread.h>
#include <new>
#include <string>
#include "os_account_info.h"
#define private public
#include "os_account_control_file_manager.h"
#undef private

namespace OHOS {
namespace AccountSA {
using namespace testing;
using namespace testing::mt;
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS;
using namespace AccountSA;
namespace {
const OsAccountType OS_ACCOUNT_TYPE = OsAccountType::ADMIN;
const std::string STRING_TEST_USER_NAME = "testuser";
const int64_t STRING_TEST_USER_SHELLNUMBER = 1000;
int32_t g_id = 0;
bool g_write = false;
const int32_t ID = 100;
const std::vector<std::string> CONSTRAINTS = {
    "constraints.test",
};
OsAccountControlFileManager *g_controlManager = new (std::nothrow) OsAccountControlFileManager();
}  // namespace
class OsAccountControlFileManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

public:
    std::string storeID_ = "os_account_info";
};

void OsAccountControlFileManagerTest::SetUpTestCase(void)
{
    ASSERT_NE(g_controlManager, nullptr);
    g_controlManager->Init();
    g_controlManager->GetAllowCreateId(g_id);
    OsAccountInfo osAccountTestInfo(g_id, STRING_TEST_USER_NAME, OS_ACCOUNT_TYPE, STRING_TEST_USER_SHELLNUMBER);
    osAccountTestInfo.SetIsCreateCompleted(true);
    ASSERT_EQ(g_controlManager->InsertOsAccount(osAccountTestInfo), ERR_OK);
    ASSERT_EQ(g_controlManager->UpdateBaseOAConstraints(std::to_string(ID), CONSTRAINTS, true), ERR_OK);
    ASSERT_EQ(g_controlManager->UpdateGlobalOAConstraints(std::to_string(ID), CONSTRAINTS, true), ERR_OK);
    ASSERT_EQ(g_controlManager->UpdateSpecificOAConstraints(std::to_string(ID), std::to_string(ID), CONSTRAINTS, true),
        ERR_OK);
}

void OsAccountControlFileManagerTest::TearDownTestCase(void)
{
    g_controlManager->DelOsAccount(g_id);
    ASSERT_EQ(g_controlManager->UpdateBaseOAConstraints(std::to_string(ID), CONSTRAINTS, false), ERR_OK);
    ASSERT_EQ(g_controlManager->UpdateGlobalOAConstraints(std::to_string(ID), CONSTRAINTS, false), ERR_OK);
    ASSERT_EQ(g_controlManager->UpdateSpecificOAConstraints(std::to_string(ID), std::to_string(ID), CONSTRAINTS, false),
        ERR_OK);
}

void OsAccountControlFileManagerTest::SetUp(void)
{}

void OsAccountControlFileManagerTest::TearDown(void)
{}

void TestWriteReadFileInfo()
{
    g_write = !g_write;
    int32_t i = 1000;
    if (g_write) {
        while (i--) {
            std::string testName = STRING_TEST_USER_NAME + std::to_string(i);
            OsAccountInfo osAccountInfo(g_id, testName, OS_ACCOUNT_TYPE, STRING_TEST_USER_SHELLNUMBER);
            osAccountInfo.SetIsCreateCompleted(true);
            EXPECT_EQ(g_controlManager->UpdateOsAccount(osAccountInfo), ERR_OK);
        }
    } else {
        while (i--) {
            OsAccountInfo osAccountInfo;
            EXPECT_EQ(g_controlManager->GetOsAccountInfoById(g_id, osAccountInfo), ERR_OK);
            EXPECT_EQ(osAccountInfo.GetIsCreateCompleted(), true);
        }
    }
}

/**
 * @tc.name: OsAccountControlFileManagerTest001
 * @tc.desc: Test multiple thread file operate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerTest001, TestSize.Level1)
{
    GTEST_RUN_TASK(TestWriteReadFileInfo);
}

void TestIsFromBaseOAConstraintsList()
{
    int32_t i = 1000;
    while (i--) {
        bool isExits = false;
        EXPECT_EQ(g_controlManager->IsFromBaseOAConstraintsList(ID, CONSTRAINTS[0], isExits), ERR_OK);
        EXPECT_EQ(isExits, true);
    }
}

/**
 * @tc.name: OsAccountControlFileManagerTest002
 * @tc.desc: Test multiple thread file operate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerTest002, TestSize.Level1)
{
    GTEST_RUN_TASK(TestIsFromBaseOAConstraintsList);
}

void TestGetGlobalOAConstraintsList()
{
    int32_t i = 1000;
    while (i--) {
        std::vector<std::string> constraintsList;
        EXPECT_EQ(g_controlManager->GetGlobalOAConstraintsList(constraintsList), ERR_OK);
        EXPECT_EQ(constraintsList.size(), 1);
    }
}

/**
 * @tc.name: OsAccountControlFileManagerTest003
 * @tc.desc: Test multiple thread file operate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerTest003, TestSize.Level1)
{
    GTEST_RUN_TASK(TestGetGlobalOAConstraintsList);
}

void TestIsFromGlobalOAConstraintsList()
{
    int32_t i = 1000;
    while (i--) {
        std::vector<ConstraintSourceTypeInfo> globalSourceList;
        EXPECT_EQ(g_controlManager->IsFromGlobalOAConstraintsList(ID, ID, CONSTRAINTS[0], globalSourceList), ERR_OK);
        EXPECT_EQ(globalSourceList[0].localId, ID);
        EXPECT_EQ(globalSourceList[0].typeInfo, ConstraintSourceType::CONSTRAINT_TYPE_DEVICE_OWNER);
    }
}

/**
 * @tc.name: OsAccountControlFileManagerTest004
 * @tc.desc: Test multiple thread file operate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerTest004, TestSize.Level1)
{
    GTEST_RUN_TASK(TestIsFromGlobalOAConstraintsList);
}

void TestGetSpecificOAConstraintsList()
{
    int32_t i = 1000;
    while (i--) {
        std::vector<std::string> constraintsList;
        EXPECT_EQ(g_controlManager->GetSpecificOAConstraintsList(ID, constraintsList), ERR_OK);
        EXPECT_EQ(constraintsList.size(), 1);
    }
}

/**
 * @tc.name: OsAccountControlFileManagerTest005
 * @tc.desc: Test multiple thread file operate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerTest005, TestSize.Level1)
{
    GTEST_RUN_TASK(TestGetSpecificOAConstraintsList);
}

void TestIsFromSpecificOAConstraintsList()
{
    int32_t i = 1000;
    while (i--) {
        std::vector<ConstraintSourceTypeInfo> globalSourceList;
        EXPECT_EQ(g_controlManager->IsFromSpecificOAConstraintsList(ID, ID, CONSTRAINTS[0], globalSourceList), ERR_OK);
        EXPECT_EQ(globalSourceList[0].localId, ID);
        EXPECT_EQ(globalSourceList[0].typeInfo, ConstraintSourceType::CONSTRAINT_TYPE_DEVICE_OWNER);
    }
}

/**
 * @tc.name: OsAccountControlFileManagerTest006
 * @tc.desc: Test multiple thread file operate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountControlFileManagerTest, OsAccountControlFileManagerTest006, TestSize.Level1)
{
    GTEST_RUN_TASK(TestIsFromSpecificOAConstraintsList);
}
}  // namespace AccountSA
}  // namespace OHOS