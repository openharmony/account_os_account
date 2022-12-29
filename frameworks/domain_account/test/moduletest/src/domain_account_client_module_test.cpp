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

#include <cerrno>
#include <gtest/gtest.h>
#include <thread>
#include <unistd.h>
#include "accesstoken_kit.h"
#include "account_log_wrapper.h"
#include "domain_account_client.h"
#include "mock_domain_auth_callback.h"
#include "mock_domain_plugin.h"
#include "os_account_manager.h"
#include "token_setproc.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;
using namespace OHOS::Security::AccessToken;

namespace {
const std::string STRING_NAME = "zhangsan";
const std::string INVALID_STRING_NAME = "lisi";
const std::string STRING_DOMAIN = "china.example.com";
const std::string INVALID_STRING_DOMAIN = "global.example.com";
const std::vector<uint8_t> VALID_PASSWORD = {49, 50, 51, 52, 53};
const std::vector<uint8_t> INVALID_PASSWORD = {1, 2, 3, 4, 5};
const int32_t DEFAULT_USER_ID = 100;
const int32_t NON_EXISTENT_USER_ID = 1000;
const uid_t TEST_UID = 100;
const uid_t ROOT_UID = 0;
std::shared_ptr<MockDomainPlugin> g_plugin = std::make_shared<MockDomainPlugin>();
}

class DomainAccountClientModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DomainAccountClientModuleTest::SetUpTestCase(void)
{
    GTEST_LOG_(INFO) << "SetUpTestCase enter";
}

void DomainAccountClientModuleTest::TearDownTestCase(void)
{
    GTEST_LOG_(INFO) << "TearDownTestCase";
}

void DomainAccountClientModuleTest::SetUp(void)
{
    DomainAccountClient::GetInstance().UnregisterPlugin();
    DomainAccountClient::GetInstance().RegisterPlugin(g_plugin);
}

void DomainAccountClientModuleTest::TearDown(void)
{}

/**
 * @tc.name: DomainAccountClientModuleTest_Plugin_001
 * @tc.desc: Register plugin successfully.
 * @tc.type: FUNC
 * @tc.require: issueI64KAG
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_Plugin_001, TestSize.Level0)
{
    ASSERT_EQ(DomainAccountClient::GetInstance().UnregisterPlugin(), ERR_OK);
    ASSERT_EQ(DomainAccountClient::GetInstance().RegisterPlugin(g_plugin), ERR_OK);
}

/**
 * @tc.name: DomainAccountClientModuleTest_Plugin_002
 * @tc.desc: Register plugin failed with invalid plugin.
 * @tc.type: FUNC
 * @tc.require: issueI64KAG
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_Plugin_002, TestSize.Level0)
{
    ASSERT_EQ(DomainAccountClient::GetInstance().UnregisterPlugin(), ERR_OK);
    ASSERT_EQ(DomainAccountClient::GetInstance().RegisterPlugin(nullptr), ERR_ACCOUNT_COMMON_INVALID_PARAMTER);
}

/**
 * @tc.name: DomainAccountClientModuleTest_Plugin_003
 * @tc.desc: Register plugin failed for repeated registeration.
 * @tc.type: FUNC
 * @tc.require: issueI64KAG
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_Plugin_003, TestSize.Level0)
{
    ASSERT_EQ(
        DomainAccountClient::GetInstance().RegisterPlugin(g_plugin), ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_ALREADY_EXIST);
}

/**
 * @tc.name: DomainAccountClientModuleTest_Plugin_004
 * @tc.desc: Register plugin failed for permission denied.
 * @tc.type: FUNC
 * @tc.require: issueI64KAG
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_Plugin_004, TestSize.Level0)
{
    setuid(TEST_UID);
    ASSERT_EQ(DomainAccountClient::GetInstance().UnregisterPlugin(), ERR_ACCOUNT_ZIDL_CHECK_PERMISSION_ERROR);
    ASSERT_EQ(DomainAccountClient::GetInstance().RegisterPlugin(g_plugin), ERR_ACCOUNT_ZIDL_CHECK_PERMISSION_ERROR);
    setuid(ROOT_UID);
}

/**
 * @tc.name: DomainAccountClientModuleTest_Plugin_005
 * @tc.desc: Register plugin successfully because permission has been applied.
 * @tc.type: FUNC
 * @tc.require: issueI64KAG
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_Plugin_005, TestSize.Level0)
{
    AccessTokenID selfTokenId = GetSelfTokenID();
    AccessTokenID tokenId = AccessTokenKit::GetNativeTokenId("accountmgr");
    SetSelfTokenID(tokenId);
    ASSERT_EQ(DomainAccountClient::GetInstance().UnregisterPlugin(), ERR_OK);
    ASSERT_EQ(DomainAccountClient::GetInstance().RegisterPlugin(g_plugin), ERR_OK);
    SetSelfTokenID(selfTokenId);
}

/**
 * @tc.name: DomainAccountClientModuleTest_Auth_001
 * @tc.desc: Auth domain account successfully.
 * @tc.type: FUNC
 * @tc.require: issueI64KAM
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_Auth_001, TestSize.Level0)
{
    DomainAccountInfo info;
    info.accountName_ = STRING_NAME;
    info.domain_ = STRING_DOMAIN;
    auto callback = std::make_shared<MockDomainAuthCallback>();
    ASSERT_NE(callback, nullptr);
    EXPECT_CALL(*callback, OnResult(0, _)).Times(Exactly(1));
    auto testCallback = std::make_shared<TestDomainAuthCallback>(callback);
    ASSERT_NE(testCallback, nullptr);
    EXPECT_EQ(
        DomainAccountClient::GetInstance().Auth(info, VALID_PASSWORD, testCallback), ERR_OK);
}

/**
 * @tc.name: DomainAccountClientModuleTest_Auth_002
 * @tc.desc: Auth domain account fail for invalid domain account.
 * @tc.type: FUNC
 * @tc.require: issueI64KAM
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_Auth_002, TestSize.Level0)
{
    DomainAccountInfo info;
    info.accountName_ = INVALID_STRING_NAME;
    info.domain_ = STRING_DOMAIN;
    auto callback = std::make_shared<MockDomainAuthCallback>();
    ASSERT_NE(callback, nullptr);
    EXPECT_CALL(*callback, OnResult(1, _)).Times(Exactly(1));
    auto testCallback = std::make_shared<TestDomainAuthCallback>(callback);
    ASSERT_NE(testCallback, nullptr);
    EXPECT_EQ(
        DomainAccountClient::GetInstance().Auth(info, VALID_PASSWORD, testCallback), ERR_OK);

    info.accountName_ = STRING_NAME;
    info.domain_ = INVALID_STRING_DOMAIN;
    auto callbackSec = std::make_shared<MockDomainAuthCallback>();
    ASSERT_NE(callbackSec, nullptr);
    EXPECT_CALL(*callbackSec, OnResult(1, _)).Times(Exactly(1));
    auto testCallbackSec = std::make_shared<TestDomainAuthCallback>(callbackSec);
    ASSERT_NE(testCallbackSec, nullptr);
    EXPECT_EQ(
        DomainAccountClient::GetInstance().Auth(info, VALID_PASSWORD, testCallbackSec), ERR_OK);
}

/**
 * @tc.name: DomainAccountClientModuleTest_Auth_003
 * @tc.desc: Auth domain account fail for invalid password.
 * @tc.type: FUNC
 * @tc.require: issueI64KAM
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_Auth_003, TestSize.Level0)
{
    DomainAccountInfo info;
    info.accountName_ = STRING_NAME;
    info.domain_ = STRING_DOMAIN;
    auto callback = std::make_shared<MockDomainAuthCallback>();
    ASSERT_NE(callback, nullptr);
    EXPECT_CALL(*callback, OnResult(1, _)).Times(Exactly(1));
    auto testCallback = std::make_shared<TestDomainAuthCallback>(callback);
    ASSERT_NE(testCallback, nullptr);
    EXPECT_EQ(
        DomainAccountClient::GetInstance().Auth(info, INVALID_PASSWORD, testCallback), ERR_OK);
}

/**
 * @tc.name: DomainAccountClientModuleTest_Auth_004
 * @tc.desc: Auth domain account failed with invalid callback.
 * @tc.type: FUNC
 * @tc.require: issueI64KAM
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_Auth_004, TestSize.Level0)
{
    DomainAccountInfo info;
    info.accountName_ = STRING_NAME;
    info.domain_ = STRING_DOMAIN;
    EXPECT_EQ(
        DomainAccountClient::GetInstance().Auth(info, VALID_PASSWORD, nullptr), ERR_ACCOUNT_COMMON_INVALID_PARAMTER);
}

/**
 * @tc.name: DomainAccountClientModuleTest_AuthUser_001
 * @tc.desc: Auth user failed with invalid user id.
 * @tc.type: FUNC
 * @tc.require: issueI64KAM
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_AuthUser_001, TestSize.Level0)
{
    auto testCallback = std::make_shared<TestDomainAuthCallback>(nullptr);
    ASSERT_NE(testCallback, nullptr);
    EXPECT_EQ(
        DomainAccountClient::GetInstance().AuthUser(
            0, VALID_PASSWORD, testCallback), ERR_ACCOUNT_COMMON_INVALID_PARAMTER);
}

/**
 * @tc.name: DomainAccountClientModuleTest_AuthUser_002
 * @tc.desc: Auth user failed when plugin not registered.
 * @tc.type: FUNC
 * @tc.require: issueI64KAM
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_AuthUser_002, TestSize.Level0)
{
    ASSERT_EQ(DomainAccountClient::GetInstance().UnregisterPlugin(), ERR_OK);
    DomainAccountInfo info;
    info.accountName_ = INVALID_STRING_NAME;
    info.domain_ = STRING_DOMAIN;
    auto callback = std::make_shared<MockDomainAuthCallback>();
    ASSERT_NE(callback, nullptr);
    EXPECT_CALL(*callback, OnResult(ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST, _)).Times(Exactly(1));
    auto testCallback = std::make_shared<TestDomainAuthCallback>(callback);
    ASSERT_NE(testCallback, nullptr);
    EXPECT_EQ(
        DomainAccountClient::GetInstance().Auth(info, VALID_PASSWORD, testCallback), ERR_OK);
}

/**
 * @tc.name: DomainAccountClientModuleTest_AuthUser_003
 * @tc.desc: Auth user failed with non-existent user.
 * @tc.type: FUNC
 * @tc.require: issueI64KAM
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_AuthUser_003, TestSize.Level0)
{
    auto testCallback = std::make_shared<TestDomainAuthCallback>(nullptr);
    ASSERT_NE(testCallback, nullptr);
    EXPECT_EQ(DomainAccountClient::GetInstance().AuthUser(NON_EXISTENT_USER_ID, VALID_PASSWORD, testCallback),
        ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR);
}

/**
 * @tc.name: DomainAccountClientModuleTest_AuthUser_004
 * @tc.desc: Auth non-domain user failed.
 * @tc.type: FUNC
 * @tc.require: issueI64KAM
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_AuthUser_004, TestSize.Level0)
{
    OsAccountInfo accountInfo;
    ErrCode errCode = OsAccountManager::CreateOsAccount(STRING_NAME, OsAccountType::NORMAL, accountInfo);
    ASSERT_EQ(errCode, ERR_OK);
    auto testCallback = std::make_shared<TestDomainAuthCallback>(nullptr);
    ASSERT_NE(testCallback, nullptr);
    EXPECT_EQ(DomainAccountClient::GetInstance().AuthUser(
        accountInfo.GetLocalId(), VALID_PASSWORD, testCallback), ERR_ACCOUNT_COMMON_INVALID_PARAMTER);
    errCode = OsAccountManager::RemoveOsAccount(accountInfo.GetLocalId());
    ASSERT_EQ(errCode, ERR_OK);
}

/**
 * @tc.name: DomainAccountClientModuleTest_AuthUser_005
 * @tc.desc: Auth domain user successfully.
 * @tc.type: FUNC
 * @tc.require: issueI64KAU
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_AuthUser_005, TestSize.Level0)
{
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = STRING_NAME;
    domainInfo.domain_ = STRING_DOMAIN;
    OsAccountInfo accountInfo;
    ErrCode errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo, accountInfo);
    ASSERT_EQ(errCode, ERR_OK);
    DomainAccountInfo newDomainInfo;
    accountInfo.GetDomainInfo(newDomainInfo);
    ASSERT_EQ(newDomainInfo.accountName_, domainInfo.accountName_);
    ASSERT_EQ(newDomainInfo.domain_, domainInfo.domain_);
    auto callback = std::make_shared<MockDomainAuthCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestDomainAuthCallback>(callback);
    ASSERT_NE(testCallback, nullptr);
    testCallback->SetOsAccountInfo(accountInfo);
    EXPECT_EQ(
        DomainAccountClient::GetInstance().AuthUser(accountInfo.GetLocalId(), VALID_PASSWORD, testCallback), ERR_OK);
}

/**
 * @tc.name: DomainAccountClientModuleTest_AuthUser_006
 * @tc.desc: Auth user failed with invalid callback.
 * @tc.type: FUNC
 * @tc.require: issueI64KAM
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_AuthUser_006, TestSize.Level0)
{
    EXPECT_EQ(DomainAccountClient::GetInstance().AuthUser(DEFAULT_USER_ID, VALID_PASSWORD, nullptr),
        ERR_ACCOUNT_COMMON_INVALID_PARAMTER);
}