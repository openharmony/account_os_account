/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include "os_account_manager_service.h"
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
const std::string TEST_STR = "1";
const std::string LONG_STR = std::string(400, '1');
const int TEST_USERID = 999;
}  // namespace
class OsAccountServiceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
public:
    OsAccountManagerService *osAccountService_ = nullptr;
};

void OsAccountServiceTest::SetUpTestCase(void)
{}

void OsAccountServiceTest::TearDownTestCase(void)
{
    std::string cmd = "chown -R 3058:3058 /data/service/el1/public/account";
    system(cmd.c_str());
}

void OsAccountServiceTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    osAccountService_ = new (std::nothrow) OsAccountManagerService();
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void OsAccountServiceTest::TearDown(void)
{
    if (osAccountService_ != nullptr) {
        free(osAccountService_);
        osAccountService_ = nullptr;
    }
}

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
    EXPECT_EQ(osAccountStopUserCallback->resultCode_, ERR_OK);
}

/**
 * @tc.name: OnStartUserDone001
 * @tc.desc: Test OsAccountUserCallback::OnStartUserDone return errCode 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountServiceTest, OnStartUserDone001, TestSize.Level1)
{
    sptr<OsAccountUserCallback> osAccountStartUserCallback = new (std::nothrow) OsAccountUserCallback(nullptr);
    ASSERT_NE(nullptr, osAccountStartUserCallback);
    int errCode = 0;
    osAccountStartUserCallback->OnStartUserDone(TEST_USER_ID, errCode);
    EXPECT_EQ(osAccountStartUserCallback->resultCode_, ERR_OK);
}

/**
 * @tc.name: CreateOsAccountForDomain001
 * @tc.desc: CreateOsAccountForDomain coverage
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountServiceTest, CreateOsAccountForDomain001, TestSize.Level1)
{
    DomainAccountInfo info;
    CreateOsAccountForDomainOptions options;
    EXPECT_EQ(osAccountService_->CreateOsAccountForDomain(OsAccountType::END, info, nullptr, options),
        ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    EXPECT_EQ(osAccountService_->CreateOsAccountForDomain(OsAccountType::ADMIN, info, nullptr, options),
        ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    info.accountName_ = TEST_STR;
    EXPECT_EQ(osAccountService_->CreateOsAccountForDomain(OsAccountType::ADMIN, info, nullptr, options),
        ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    info.accountName_ = LONG_STR;
    info.domain_ = TEST_STR;
    EXPECT_EQ(osAccountService_->CreateOsAccountForDomain(OsAccountType::ADMIN, info, nullptr, options),
        ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    info.accountName_ = TEST_STR;
    info.domain_ = LONG_STR;
    EXPECT_EQ(osAccountService_->CreateOsAccountForDomain(OsAccountType::ADMIN, info, nullptr, options),
        ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: GetOsAccountLocalIdFromDomain001
 * @tc.desc: GetOsAccountLocalIdFromDomain coverage
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountServiceTest, GetOsAccountLocalIdFromDomain001, TestSize.Level1)
{
    DomainAccountInfo info;
    int id;
    EXPECT_EQ(osAccountService_->GetOsAccountLocalIdFromDomain(info, id), ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    info.domain_ = LONG_STR;
    EXPECT_EQ(osAccountService_->GetOsAccountLocalIdFromDomain(info, id), ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    info.domain_ = TEST_STR;
    EXPECT_EQ(osAccountService_->GetOsAccountLocalIdFromDomain(info, id), ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    info.accountName_ = LONG_STR;
    EXPECT_EQ(osAccountService_->GetOsAccountLocalIdFromDomain(info, id), ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: IsOsAccountVerified001
 * @tc.desc: IsOsAccountVerified coverage
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountServiceTest, IsOsAccountVerified001, TestSize.Level1)
{
    bool isVerified;
    EXPECT_EQ(osAccountService_->IsOsAccountVerified(0, isVerified), ERR_OK);
    setuid(TEST_USERID * UID_TRANSFORM_DIVISOR);
    EXPECT_EQ(osAccountService_->IsOsAccountVerified(TEST_USERID, isVerified),
        ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
    setuid(0);
}
}  // namespace AccountSA
}  // namespace OHOS