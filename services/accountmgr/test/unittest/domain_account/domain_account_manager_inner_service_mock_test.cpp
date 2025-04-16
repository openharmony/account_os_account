/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "account_log_wrapper.h"
#define private public
#include "inner_domain_account_manager.h"
#undef private
#include "mock_domain_account_callback_stub.h"
#include "parameters.h"

namespace OHOS {
namespace {
static bool g_isSupportNetRequest = true;
const int32_t NET_REQ_ERROR = ERR_DOMAIN_ACCOUNT_NOT_SUPPORT_BACKGROUND_ACCOUNT_REQUEST;
}
namespace system {
bool GetBoolParameter(const std::string& key, bool def)
{
    return g_isSupportNetRequest;
}
}
namespace AccountSA {
using namespace testing;
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS;
using namespace AccountSA;

namespace {
static constexpr int32_t USER_UID = 100 * 200000;
static const std::string TEST_STR = "test";
}

class IInnerOsAccountManager {
public:
    ErrCode GetRealOsAccountInfoById(const int id, OsAccountInfo &osAccountInfo);
};

ErrCode IInnerOsAccountManager::GetRealOsAccountInfoById(const int id, OsAccountInfo &osAccountInfo)
{
    DomainAccountInfo info(TEST_STR, TEST_STR, TEST_STR);
    osAccountInfo.SetDomainInfo(info);
    return ERR_OK;
}

class DomainAccountManagerInnerServiceMockTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DomainAccountManagerInnerServiceMockTest::SetUpTestCase(void)
{}

void DomainAccountManagerInnerServiceMockTest::TearDownTestCase(void)
{}

void DomainAccountManagerInnerServiceMockTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void DomainAccountManagerInnerServiceMockTest::TearDown(void)
{}

/**
 * @tc.name: IsSupportNetRequest001
 * @tc.desc: Test IsSupportNetRequest all branchs.
 * @tc.type: FUNC
 * @tc.require: issueI64KAM
 */
HWTEST_F(DomainAccountManagerInnerServiceMockTest, IsSupportNetRequest001, TestSize.Level1)
{
    g_isSupportNetRequest = true;
    DomainAccountInfo domainInfo;
    DomainServerConfig config;
    bool isExpired;
    std::vector<DomainServerConfig> configs;
    std::vector<uint8_t> password;
    std::string policy;
    auto instance = std::make_shared<InnerDomainAccountManager>();
    std::string testStr = "test", rightPath = "/rightPath/", rightSoName = "right.z.so";
    // LoadLib success
    instance->LoaderLib(rightPath, rightSoName);
    setuid(USER_UID);
    EXPECT_EQ(instance->SetAccountPolicy(domainInfo, policy), NET_REQ_ERROR);
    EXPECT_EQ(instance->GetAccountPolicy(domainInfo, policy), NET_REQ_ERROR);
    EXPECT_EQ(instance->AddServerConfig(testStr, config), NET_REQ_ERROR);
    EXPECT_EQ(instance->RemoveServerConfig(testStr), NET_REQ_ERROR);
    EXPECT_EQ(instance->UpdateServerConfig(testStr, testStr, config), NET_REQ_ERROR);
    EXPECT_EQ(instance->GetServerConfig(testStr, config), NET_REQ_ERROR);
    EXPECT_EQ(instance->GetAllServerConfigs(configs), NET_REQ_ERROR);
    EXPECT_EQ(instance->GetAccountServerConfig(domainInfo, config), NET_REQ_ERROR);
    EXPECT_EQ(instance->Auth(domainInfo, password, nullptr), NET_REQ_ERROR);
    EXPECT_EQ(instance->AuthUser(0, password, nullptr), NET_REQ_ERROR);
    EXPECT_EQ(instance->AuthWithPopup(0, nullptr), NET_REQ_ERROR);
    EXPECT_EQ(instance->AuthWithToken(0, password), NET_REQ_ERROR);
    EXPECT_EQ(instance->IsAuthenticationExpired(domainInfo, isExpired), NET_REQ_ERROR);
    EXPECT_EQ(instance->CheckUserToken(password, isExpired, domainInfo), NET_REQ_ERROR);
    EXPECT_EQ(instance->GetAuthStatusInfo(domainInfo, nullptr), NET_REQ_ERROR);
    EXPECT_EQ(instance->HasDomainAccount(domainInfo, nullptr), NET_REQ_ERROR);
    EXPECT_EQ(instance->OnAccountBound(domainInfo, 0, nullptr), NET_REQ_ERROR);
    EXPECT_EQ(instance->OnAccountUnBound(domainInfo, nullptr, 0), NET_REQ_ERROR);
    EXPECT_EQ(instance->GetDomainAccountInfo(domainInfo, nullptr), NET_REQ_ERROR);
    EXPECT_EQ(instance->IsAccountTokenValid(domainInfo, password, nullptr), NET_REQ_ERROR);
    EXPECT_EQ(instance->UpdateAccountInfo(domainInfo, domainInfo), NET_REQ_ERROR);
    auto callback = std::make_shared<MockDomainAccountCallback>();
    ASSERT_NE(callback, nullptr);
    sptr<MockDomainAccountCallbackStub> testCallback = new (std::nothrow) MockDomainAccountCallbackStub(callback);
    AAFwk::WantParams parameters;
    EXPECT_EQ(instance->GetAccessToken(domainInfo, parameters, testCallback), NET_REQ_ERROR);
    setuid(0);
    EXPECT_NE(instance->SetAccountPolicy(domainInfo, policy), NET_REQ_ERROR);
    instance.reset();
}

/**
 * @tc.name: GetAllServerConfigs001
 * @tc.desc: Test IsSupportNetRequest return false.
 * @tc.type: FUNC
 * @tc.require: issueI64KAM
 */
HWTEST_F(DomainAccountManagerInnerServiceMockTest, GetAllServerConfigs001, TestSize.Level3)
{
    g_isSupportNetRequest = true;
    std::vector<DomainServerConfig> configs;
    InnerDomainAccountManager *instance = new (std::nothrow) InnerDomainAccountManager();
    std::string rightPath = "/rightPath/";
    std::string rightSoName = "right.z.so";
    // LoadLib success
    instance->LoaderLib(rightPath, rightSoName);
    setuid(USER_UID);
    EXPECT_EQ(instance->GetAllServerConfigs(configs),
        ERR_DOMAIN_ACCOUNT_NOT_SUPPORT_BACKGROUND_ACCOUNT_REQUEST);
}

/**
 * @tc.name: InnerAuth001
 * @tc.desc: test InnerAuth branches when plugin_ is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountManagerInnerServiceMockTest, InnerAuth001, TestSize.Level3)
{
    InnerDomainAccountManager *instance = new (std::nothrow) InnerDomainAccountManager();
    sptr<IDomainAccountCallback> innerCallback = new (std::nothrow) InnerDomainAuthCallback(100, nullptr);
    ASSERT_NE(innerCallback, nullptr);
    const std::vector<uint8_t> authData;
    instance->plugin_ = nullptr;
    ASSERT_EQ(instance->InnerAuth(100, authData, innerCallback, AuthMode::AUTH_WITH_CREDENTIAL_MODE), ERR_OK);
    ASSERT_EQ(instance->InnerAuth(100, authData, innerCallback, AuthMode::AUTH_WITH_POPUP_MODE), ERR_OK);
    ASSERT_EQ(instance->InnerAuth(100, authData, innerCallback, AuthMode::AUTH_WITH_TOKEN_MODE), ERR_OK);
    ASSERT_EQ(instance->InnerAuth(100, authData, innerCallback, AuthMode::AUTH_INVALID_MODE), ERR_OK);
}
} // AccountSA
} // OHOS