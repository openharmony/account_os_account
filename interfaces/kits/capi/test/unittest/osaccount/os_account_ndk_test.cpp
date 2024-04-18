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

#include <gtest/gtest.h>
#include "errors.h"
#include "os_account.h"
#include "os_account_common.h"

namespace OHOS {
namespace AccountSA {
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS;
using namespace AccountSA;
namespace {
static const uint32_t MAX_NAME_LENGTH = 1024;
}
class OsAccountNDKTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void OsAccountNDKTest::SetUpTestCase(void)
{
}

void OsAccountNDKTest::TearDownTestCase(void)
{}

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
 * @tc.desc: Test invalid paramter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountNDKTest, GetOsAccountNameTest001, TestSize.Level0)
{
    char str[MAX_NAME_LENGTH] = { 0 };
    EXPECT_EQ(OH_OsAccount_GetName(nullptr, MAX_NAME_LENGTH), OsAccount_ErrCode::OS_ACCOUNT_ERR_INVALID_PARAMETER);
    EXPECT_EQ(OH_OsAccount_GetName(str, 0), OsAccount_ErrCode::OS_ACCOUNT_ERR_INVALID_PARAMETER);
    EXPECT_EQ(OH_OsAccount_GetName(str, MAX_NAME_LENGTH), OsAccount_ErrCode::OS_ACCOUNT_ERR_OK);
}
}  // namespace AccountTest
}  // namespace OHOS