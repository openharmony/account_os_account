/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "os_account_constants.h"
#include "os_account_info.h"
#include "iinner_os_account_manager.h"
#include "os_account_control_file_manager.h"

namespace OHOS {
namespace AccountSA {
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS;
using namespace AccountSA;
const OsAccountType INT_TYPE = OsAccountType::ADMIN;

class OsAccountInnerAccmgrPluginMockTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

public:
    IInnerOsAccountManager *innerMgrService_ = &IInnerOsAccountManager::GetInstance();
};


void OsAccountInnerAccmgrPluginMockTest::SetUpTestCase(void)
{}

void OsAccountInnerAccmgrPluginMockTest::TearDownTestCase(void)
{}

void OsAccountInnerAccmgrPluginMockTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
}

void OsAccountInnerAccmgrPluginMockTest::TearDown(void)
{}

/**
 * @tc.name: OsAccountDataStorageTest001
 * @tc.desc: Test OsAccountDataStorageTest init
 * @tc.type: FUNC
 * @tc.require: SR000GGVFF
 */
HWTEST_F(OsAccountInnerAccmgrPluginMockTest, OsAccountDataStorageTest001, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(innerMgrService_->CreateOsAccount("", INT_TYPE, osAccountInfo),
        ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_PLUGIN_NOT_ALLOWED_CREATION_ERROR);
}
}  // namespace AccountSA
}  // namespace OHOS
