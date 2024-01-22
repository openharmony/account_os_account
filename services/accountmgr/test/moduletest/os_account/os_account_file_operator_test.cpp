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
 * @tc.name: OsAccountFileOperator_CheckConstraintsList_0001
 * @tc.desc: Test CreateOsAccount when create max accounts.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountFileOperatorTest, CheckConstraintsList_0001, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountFileOperator_CheckConstraintsList_0001");

    std::vector<std::string> constraints;
    bool isExists = true;
    bool isOverSize = true;
    ErrCode ret = g_osAccountFileOperator->CheckConstraintsList(constraints, isExists, isOverSize);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_OS_FILE_GET_CONSTRAINTS_LITS_ERROR);
}

}  // namespace AccountSA
}  // namespace OHOS