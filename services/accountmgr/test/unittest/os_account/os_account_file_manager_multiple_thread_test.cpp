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
}

void OsAccountControlFileManagerTest::TearDownTestCase(void)
{
    g_controlManager->DelOsAccount(g_id);
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
}  // namespace AccountSA
}  // namespace OHOS