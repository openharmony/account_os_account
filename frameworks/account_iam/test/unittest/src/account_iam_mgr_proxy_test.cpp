/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
#define private public
#include "account_i_a_m_proxy.h"
#undef private
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "iam_common_defines.h"
#include "test_common.h"

namespace OHOS {
namespace AccountTest {

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS::UserIam::UserAuth;
namespace {
constexpr int32_t TEST_USER_ID = 200;
constexpr uint64_t TEST_CREDENTIAL_ID = 200;
} // namespace

class AccountIAMMgrProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void AccountIAMMgrProxyTest::SetUpTestCase(void)
{}

void AccountIAMMgrProxyTest::TearDownTestCase(void)
{}

void AccountIAMMgrProxyTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void AccountIAMMgrProxyTest::TearDown(void)
{}

/**
 * @tc.name: OpenSession001
 * @tc.desc: test OpenSession.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMMgrProxyTest, OpenSession001, TestSize.Level3)
{
    std::shared_ptr<AccountIAMProxy> accountIAMMgrProxy = std::make_shared<AccountIAMProxy>(nullptr);
    std::vector<uint8_t> challenge;
    int32_t ret = accountIAMMgrProxy->OpenSession(TEST_USER_ID, challenge);
    EXPECT_EQ(ERR_INVALID_DATA, ret);
}

/**
 * @tc.name: AccountIAMMgrProxy001
 * @tc.desc: test callback is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMMgrProxyTest, AccountIAMMgrProxy001, TestSize.Level3)
{
    std::shared_ptr<AccountIAMProxy> accountIAMMgrProxy = std::make_shared<AccountIAMProxy>(nullptr);
    std::vector<uint8_t> challenge;
    CredentialParametersIam credInfo;
    const std::vector<uint8_t> authToken = {0, 0};
    AccountSA::AuthParam authParam;
    authParam.userId = TEST_USER_ID;
    uint64_t contextId;
    GetPropertyRequestIam g_request;
    SetPropertyRequestIam s_request;
    accountIAMMgrProxy->AddCredential(TEST_USER_ID, credInfo, nullptr);
    accountIAMMgrProxy->UpdateCredential(TEST_USER_ID, credInfo, nullptr);
    accountIAMMgrProxy->DelCred(TEST_USER_ID, 0, authToken, nullptr);
    accountIAMMgrProxy->DelUser(TEST_USER_ID, authToken, nullptr);
    accountIAMMgrProxy->GetProperty(TEST_USER_ID, g_request, nullptr);
    std::vector<int32_t> keys= { static_cast<int32_t>(Attributes::AttributeKey::ATTR_PIN_SUB_TYPE) };
    accountIAMMgrProxy->GetPropertyByCredentialId(TEST_CREDENTIAL_ID, keys, nullptr);
    accountIAMMgrProxy->SetProperty(TEST_USER_ID, s_request, nullptr);

    std::string cmd = "hilog -x | grep 'AccountIAMFwk'";
    std::string cmdRes = RunCommand(cmd);
    ASSERT_TRUE(cmdRes.find("idmCallback is nullptr") != std::string::npos);
    ASSERT_TRUE(cmdRes.find("getSetPropCallback is nullptr") != std::string::npos);

    int32_t ret = accountIAMMgrProxy->GetCredentialInfo(TEST_USER_ID, static_cast<int32_t>(AuthType::ALL), nullptr);
    EXPECT_EQ(ERR_INVALID_DATA, ret);
    ret = accountIAMMgrProxy->AuthUser(authParam, nullptr, contextId);
    EXPECT_EQ(ERR_INVALID_DATA, ret);

    ret = accountIAMMgrProxy->PrepareRemoteAuth("testString", nullptr);
    EXPECT_EQ(ERR_INVALID_DATA, ret);
}
}  // namespace AccountTest
}  // namespace OHOS