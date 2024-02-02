/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <algorithm>
#include <ctime>
#include <gtest/gtest.h>
#include <iostream>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "os_account_constants.h"
#define private public
#include "os_account_user_callback.h"
#undef private

namespace OHOS {
namespace AccountSA {
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS;
using namespace AccountSA;
namespace {
    const int TEST_USER_ID = 100;
}  // namespace
class OsAccountServiceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void OsAccountServiceTest::SetUpTestCase(void)
{}

void OsAccountServiceTest::TearDownTestCase(void)
{}

void OsAccountServiceTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void OsAccountServiceTest::TearDown(void)
{}

/**
 * @tc.name: OnStopUserDone001
 * @tc.desc: Test OsAccountUserCallback::OnStopUserDone return errCode 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountServiceTest, OnStopUserDone001, TestSize.Level1)
{
    sptr<OsAccountUserCallback> osAccountStopUserCallback = new (std::nothrow) OsAccountUserCallback();
    ASSERT_NE(nullptr, osAccountStopUserCallback);
    int errCode = 0;
    osAccountStopUserCallback->OnStopUserDone(TEST_USER_ID, errCode);
    EXPECT_TRUE(osAccountStopUserCallback->isReturnOk_);
}

/**
 * @tc.name: OnStartUserDone001
 * @tc.desc: Test OsAccountUserCallback::OnStartUserDone return errCode 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountServiceTest, OnStartUserDone001, TestSize.Level1)
{
    sptr<OsAccountUserCallback> osAccountStartUserCallback = new (std::nothrow) OsAccountUserCallback();
    ASSERT_NE(nullptr, osAccountStartUserCallback);
    int errCode = 0;
    osAccountStartUserCallback->OnStartUserDone(TEST_USER_ID, errCode);
    EXPECT_TRUE(osAccountStartUserCallback->isReturnOk_);
}
}  // namespace AccountSA
}  // namespace OHOS