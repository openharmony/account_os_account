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
#include <string>

#include <gtest/gtest.h>
#include "errors.h"
#include "os_account_utils.h"


namespace OHOS {
namespace AccountSA {
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS;
using namespace AccountSA;
namespace {
constexpr std::int32_t UID_TRANSFORM_DIVISOR = 200000; // local account id = uid / UID_TRANSFORM_DIVISOR
constexpr std::int32_t USER_ID_TEST = 100;
}
class OsAccountUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void OsAccountUtilsTest::SetUpTestCase(void)
{}

void OsAccountUtilsTest::TearDownTestCase(void)
{}

void OsAccountUtilsTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    GTEST_LOG_(INFO) <<"[SetUp] " << testCaseName.c_str() << " start." << std::endl;
}

void OsAccountUtilsTest::TearDown(void)
{}

/**
 * @tc.name: GetOsAccountIdFroUid001
 * @tc.desc: Get osAccountId from uid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountUtilsTest, GetOsAccountIdFroUid001, TestSize.Level1)
{
    EXPECT_EQ(GetOsAccountIdForUid(-1), -1);
    EXPECT_EQ(GetOsAccountIdForUid(0), 0);
    EXPECT_EQ(GetOsAccountIdForUid(USER_ID_TEST * UID_TRANSFORM_DIVISOR), USER_ID_TEST);
}

/**
 * @tc.name: SetOsAccountId001
 * @tc.desc: SetOsAccountId with osAccountId is USER_ID_TEST.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountUtilsTest, SetOsAccountId001, TestSize.Level1)
{
    EXPECT_EQ(SetOsAccountId(USER_ID_TEST), 0);
    EXPECT_EQ(GetOsAccountId(), USER_ID_TEST);
}

/**
 * @tc.name: SetOsAccountId002
 * @tc.desc: SetOsAccountId with osAccountId is -1.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountUtilsTest, SetOsAccountId002, TestSize.Level1)
{
    EXPECT_EQ(SetOsAccountId(-1), -1);
}

/**
 * @tc.name: SetOsAccountId003
 * @tc.desc: SetOsAccountId with osAccountId is 0.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountUtilsTest, SetOsAccountId003, TestSize.Level1)
{
    EXPECT_EQ(SetOsAccountId(0), 0);
    EXPECT_EQ(GetOsAccountId(), 0);
}

/**
 * @tc.name: SetOsAccountId004
 * @tc.desc: SetOsAccountId with osAccountId1 and osAccountId2.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountUtilsTest, SetOsAccountId004, TestSize.Level1)
{
    EXPECT_EQ(SetOsAccountId(0), 0);
    EXPECT_EQ(SetOsAccountId(USER_ID_TEST), 0);
    EXPECT_EQ(GetOsAccountId(), USER_ID_TEST);
}
}  // namespace AccountTest
}  // namespace OHOS