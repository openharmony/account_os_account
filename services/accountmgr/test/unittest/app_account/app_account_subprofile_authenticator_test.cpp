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

#include <gtest/gtest.h>
#include <string>

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "app_account_authenticator_manager.h"
#include "app_account_common.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string AUTH_EXT_OWNER = "com.example.subprofile.auth.extension";
const std::string AUTH_ABILITY_OWNER = "com.example.subprofile.auth.ability";
const std::string AUTH_DISABLED_OWNER = "com.example.subprofile.auth.disabled";
const std::string AUTH_ABILITY_NAME = "AuthServiceAbility";
const int32_t TEST_USER_ID = 100;
}

class AppAccountSubprofileAuthenticatorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);
};

void AppAccountSubprofileAuthenticatorTest::SetUpTestCase(void)
{
    ACCOUNT_LOGI("SetUpTestCase");
}

void AppAccountSubprofileAuthenticatorTest::TearDownTestCase(void)
{
    ACCOUNT_LOGI("TearDownTestCase");
}

void AppAccountSubprofileAuthenticatorTest::SetUp(void)
{
    ACCOUNT_LOGI("SetUp");
}

void AppAccountSubprofileAuthenticatorTest::TearDown(void)
{
    ACCOUNT_LOGI("TearDown");
}

/**
 * @tc.name: AppAccountSubprofileAuthenticatorTest_GetAuthenticatorInfo_0100
 * @tc.desc: Subprofile (appIndex=1) discovers enabled extension at matching appIndex.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountSubprofileAuthenticatorTest,
    AppAccountSubprofileAuthenticatorTest_GetAuthenticatorInfo_0100, TestSize.Level1)
{
    AuthenticatorInfo info;
    ErrCode result = AppAccountAuthenticatorManager::GetAuthenticatorInfo(
        AUTH_EXT_OWNER, 1, TEST_USER_ID, info);
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
    ASSERT_EQ(result, ERR_OK);
    EXPECT_EQ(info.abilityName, AUTH_ABILITY_NAME);
#else
    ASSERT_NE(result, ERR_OK);
#endif
}

/**
 * @tc.name: AppAccountSubprofileAuthenticatorTest_GetAuthenticatorInfo_0200
 * @tc.desc: Subprofile (appIndex=2) cannot discover extension at appIndex=1 (mismatch).
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountSubprofileAuthenticatorTest,
    AppAccountSubprofileAuthenticatorTest_GetAuthenticatorInfo_0200, TestSize.Level1)
{
    AuthenticatorInfo info;
    ErrCode result = AppAccountAuthenticatorManager::GetAuthenticatorInfo(
        AUTH_EXT_OWNER, 2, TEST_USER_ID, info);
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
    ASSERT_NE(result, ERR_OK);
#else
    ASSERT_NE(result, ERR_OK);
#endif
}

/**
 * @tc.name: AppAccountSubprofileAuthenticatorTest_GetAuthenticatorInfo_0300
 * @tc.desc: Main profile (appIndex=0) discovers ability via main-profile fallback.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountSubprofileAuthenticatorTest,
    AppAccountSubprofileAuthenticatorTest_GetAuthenticatorInfo_0300, TestSize.Level1)
{
    AuthenticatorInfo info;
    ErrCode result = AppAccountAuthenticatorManager::GetAuthenticatorInfo(
        AUTH_ABILITY_OWNER, 0, TEST_USER_ID, info);
    ASSERT_EQ(result, ERR_OK);
    EXPECT_EQ(info.abilityName, AUTH_ABILITY_NAME);
}

/**
 * @tc.name: AppAccountSubprofileAuthenticatorTest_GetAuthenticatorInfo_0400
 * @tc.desc: Disabled extension is skipped by lambda filter.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountSubprofileAuthenticatorTest,
    AppAccountSubprofileAuthenticatorTest_GetAuthenticatorInfo_0400, TestSize.Level1)
{
    AuthenticatorInfo info;
    ErrCode result = AppAccountAuthenticatorManager::GetAuthenticatorInfo(
        AUTH_DISABLED_OWNER, 1, TEST_USER_ID, info);
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
    ASSERT_NE(result, ERR_OK);
#else
    ASSERT_NE(result, ERR_OK);
#endif
}

/**
 * @tc.name: AppAccountSubprofileAuthenticatorTest_GetAuthenticatorInfo_0500
 * @tc.desc: Non-existent owner returns authenticator-not-exist error.
 * @tc.type: FUNC
 */
HWTEST_F(AppAccountSubprofileAuthenticatorTest,
    AppAccountSubprofileAuthenticatorTest_GetAuthenticatorInfo_0500, TestSize.Level1)
{
    AuthenticatorInfo info;
    ErrCode result = AppAccountAuthenticatorManager::GetAuthenticatorInfo(
        "com.example.notexist", 0, TEST_USER_ID, info);
    ASSERT_NE(result, ERR_OK);
}
