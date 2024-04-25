/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include <filesystem>
#include <mutex>
#include <gtest/gtest.h>
#include <thread>
#include <unistd.h>
#include "accesstoken_kit.h"
#include "account_file_operator.h"
#include "account_log_wrapper.h"
#include "account_permission_manager.h"
#include "domain_account_callback_service.h"
#include "os_account_info.h"
#ifdef BUNDLE_ADAPTER_MOCK
#include "domain_account_manager_service.h"
#include "domain_account_proxy.h"
#endif
#define private public
#include "domain_account_client.h"
#include "inner_domain_account_manager.h"
#include "iinner_os_account_manager.h"
#include "os_account.h"
#undef private
#include "ipc_skeleton.h"
#include "mock_domain_auth_callback.h"
#include "mock_domain_auth_callback_for_listener.h"
#include "mock_domain_create_domain_account_callback.h"
#include "mock_domain_has_domain_info_callback.h"
#include "mock_domain_get_access_token_callback.h"
#include "mock_domain_plugin.h"
#include "os_account_manager.h"
#ifdef BUNDLE_ADAPTER_MOCK
#include "os_account_manager_service.h"
#include "os_account_proxy.h"
#endif
#include "token_setproc.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::AccountSA::Constants;

namespace {
const std::string STRING_NAME = "zhangsan";
const std::string STRING_NAME_NEW = "zhangsan777";
const std::string STRING_NAME_TWO = "zhangsan666";
const std::string STRING_NAME_INVALID = "zhangsan55";
const std::string STRING_NAME_BIND_INVALID = "lisi";
const std::string ACCOUNT_NAME = "zhangsan5";
const std::string INVALID_STRING_NAME = "lisi";
const std::string STRING_DOMAIN = "china.example.com";
const std::string STRING_DOMAIN_NEW = "test.example.com";
const std::string INVALID_STRING_DOMAIN = "global.example.com";
const std::string STRING_ACCOUNTID = "222";
const std::string INVALID_STRING_ACCOUNTID = "444";
const std::string STRING_ACCOUNTID_FIVE = "555";
const std::string STRING_ACCOUNTID_NEW = "3333";
const std::string CONSTRAINT_CREATE_ACCOUNT_DIRECTLY = "constraint.os.account.create.directly";
const std::vector<uint8_t> VALID_PASSWORD = {49, 50, 51, 52, 53};
const std::vector<uint8_t> INVALID_PASSWORD = {1, 2, 3, 4, 5};
const std::vector<uint8_t> DEFAULT_TOKEN = {49, 50, 51, 52, 53};
const std::vector<uint8_t> TOKEN = {1, 2, 3, 4, 5};
const int32_t DEFAULT_USER_ID = 100;
const int32_t NON_EXISTENT_USER_ID = 1000;
const int32_t WAIT_TIME = 20;
const int32_t INVALID_CODE = -1;
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
#ifdef ACCOUNT_TEST
    AccountFileOperator osAccountFileOperator;
    osAccountFileOperator.DeleteDirOrFile(USER_INFO_BASE);
    GTEST_LOG_(INFO) << "delete account test path " << USER_INFO_BASE;
#endif  // ACCOUNT_TEST
#ifdef BUNDLE_ADAPTER_MOCK
    auto servicePtr = new (std::nothrow) DomainAccountManagerService();
    ASSERT_NE(servicePtr, nullptr);
    DomainAccountClient::GetInstance().proxy_ = new (std::nothrow) DomainAccountProxy(servicePtr->AsObject());
    ASSERT_NE(DomainAccountClient::GetInstance().proxy_, nullptr);
    auto osAccountService = new (std::nothrow) OsAccountManagerService();
    ASSERT_NE(osAccountService, nullptr);
    IInnerOsAccountManager::GetInstance().Init();
    OsAccount::GetInstance().proxy_ = new (std::nothrow) OsAccountProxy(osAccountService->AsObject());
    ASSERT_NE(OsAccount::GetInstance().proxy_, nullptr);
#endif
}

void DomainAccountClientModuleTest::TearDownTestCase(void)
{
    GTEST_LOG_(INFO) << "TearDownTestCase";
#ifdef ACCOUNT_TEST
    AccountFileOperator osAccountFileOperator;
    osAccountFileOperator.DeleteDirOrFile(USER_INFO_BASE);
    GTEST_LOG_(INFO) << "delete account test path " << USER_INFO_BASE;
#endif  // ACCOUNT_TEST
}

void DomainAccountClientModuleTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());

    std::vector<OsAccountInfo> osAccountInfos;
    OsAccount::GetInstance().QueryAllCreatedOsAccounts(osAccountInfos);
    for (const auto &info : osAccountInfos) {
        if (info.GetLocalId() == START_USER_ID) {
            continue;
        }
        ACCOUNT_LOGI("[SetUp] remove account %{public}d", info.GetLocalId());
        OsAccount::GetInstance().RemoveOsAccount(info.GetLocalId());
    }
    DomainAccountClient::GetInstance().UnregisterPlugin();
    DomainAccountClient::GetInstance().RegisterPlugin(g_plugin);
#ifdef BUNDLE_ADAPTER_MOCK
    setuid(ROOT_UID);
#endif
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
    ASSERT_EQ(DomainAccountClient::GetInstance().RegisterPlugin(nullptr), ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
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
    ASSERT_EQ(DomainAccountClient::GetInstance().UnregisterPlugin(), ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    ASSERT_EQ(DomainAccountClient::GetInstance().RegisterPlugin(g_plugin), ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
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
    AccessTokenID selfTokenId = IPCSkeleton::GetSelfTokenID();
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
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
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
    {
        std::unique_lock<std::mutex> lock(testCallback->mutex);
        testCallback->cv.wait_for(
            lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
    }

    info.accountName_ = STRING_NAME;
    info.domain_ = INVALID_STRING_DOMAIN;
    auto callbackSec = std::make_shared<MockDomainAuthCallback>();
    ASSERT_NE(callbackSec, nullptr);
    EXPECT_CALL(*callbackSec, OnResult(1, _)).Times(Exactly(1));
    auto testCallbackSec = std::make_shared<TestDomainAuthCallback>(callbackSec);
    ASSERT_NE(testCallbackSec, nullptr);
    EXPECT_EQ(
        DomainAccountClient::GetInstance().Auth(info, VALID_PASSWORD, testCallbackSec), ERR_OK);
    {
        std::unique_lock<std::mutex> lock(testCallbackSec->mutex);
        testCallbackSec->cv.wait_for(lock,
            std::chrono::seconds(WAIT_TIME), [lockCallback = testCallbackSec]() { return lockCallback->isReady; });
    }
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
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
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
        DomainAccountClient::GetInstance().Auth(info, VALID_PASSWORD, nullptr), ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
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
            0, VALID_PASSWORD, testCallback), ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
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
    EXPECT_CALL(*callback,
        OnResult(ERR_JS_CAPABILITY_NOT_SUPPORTED, _)).Times(Exactly(1));
    auto testCallback = std::make_shared<TestDomainAuthCallback>(callback);
    ASSERT_NE(testCallback, nullptr);
    EXPECT_EQ(
        DomainAccountClient::GetInstance().Auth(info, VALID_PASSWORD, testCallback), ERR_OK);
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
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
        ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: DomainAccountClientModuleTest_AuthUser_004
 * @tc.desc: Auth non-domain user failed.
 * @tc.type: FUNC
 * @tc.require: issueI64KAM
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_AuthUser_004, TestSize.Level0)
{
    OsAccountInfo accountInfo;
    ErrCode errCode = OsAccountManager::CreateOsAccount(STRING_NAME, OsAccountType::NORMAL, accountInfo);
    ASSERT_EQ(errCode, ERR_OK);
    auto testCallback = std::make_shared<TestDomainAuthCallback>(nullptr);
    ASSERT_NE(testCallback, nullptr);
    EXPECT_EQ(DomainAccountClient::GetInstance().AuthUser(
        accountInfo.GetLocalId(), VALID_PASSWORD, testCallback), ERR_DOMAIN_ACCOUNT_SERVICE_NOT_DOMAIN_ACCOUNT);
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
    domainInfo.accountId_ = INVALID_STRING_ACCOUNTID;
    auto callback = std::make_shared<MockDomainCreateDomainAccountCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestCreateDomainAccountCallback>(callback);
    EXPECT_CALL(*callback, OnResult(ERR_OK, STRING_NAME, STRING_DOMAIN, _)).Times(Exactly(1));
    ASSERT_NE(testCallback, nullptr);
    ErrCode errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo, testCallback);
    {
        std::unique_lock<std::mutex> lock(testCallback->mutex);
        testCallback->cv.wait_for(
            lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
    }
    ASSERT_EQ(errCode, ERR_OK);

    auto authCallback = std::make_shared<MockDomainAuthCallback>();
    ASSERT_NE(authCallback, nullptr);
    EXPECT_CALL(*authCallback, OnResult(ERR_OK, _)).Times(Exactly(1));
    auto testAuthCallback = std::make_shared<TestDomainAuthCallback>(authCallback);
    ASSERT_NE(testAuthCallback, nullptr);
    int32_t userId = -1;
    errCode = OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, userId);
    EXPECT_EQ(errCode, ERR_OK);
    EXPECT_EQ(DomainAccountClient::GetInstance().AuthUser(userId, DEFAULT_TOKEN, testAuthCallback), ERR_OK);
    {
        std::unique_lock<std::mutex> lock(testAuthCallback->mutex);
        testAuthCallback->cv.wait_for(lock,
            std::chrono::seconds(WAIT_TIME), [lockCallback = testAuthCallback]() { return lockCallback->isReady; });
    }
    std::vector<uint8_t> resultToken;
    InnerDomainAccountManager::GetInstance().GetTokenFromMap(userId, resultToken);
    for (size_t index = 0; index < resultToken.size(); index++) {
        EXPECT_EQ(resultToken[index], TOKEN[index]);
    }
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId), ERR_OK);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: DomainAccountClientModuleTest_AuthUser_006
 * @tc.desc: Auth user failed with invalid callback.
 * @tc.type: FUNC
 * @tc.require: issueI64KAM
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_AuthUser_006, TestSize.Level0)
{
    EXPECT_EQ(DomainAccountClient::GetInstance().AuthUser(DEFAULT_USER_ID, VALID_PASSWORD, nullptr),
        ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: DomainAccountClientModuleTest_AuthWithPopup_001
 * @tc.desc: Auth domain account failed for callback is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI64KAM
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_AuthWithPopup_001, TestSize.Level0)
{
    EXPECT_EQ(DomainAccountClient::GetInstance().AuthWithPopup(DEFAULT_USER_ID, nullptr),
        ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: DomainAccountClientModuleTest_AuthWithPopup_002
 * @tc.desc: Auth domain account failed for local id is not exist.
 * @tc.type: FUNC
 * @tc.require: issueI64KAM
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_AuthWithPopup_002, TestSize.Level0)
{
    auto testCallback = std::make_shared<TestDomainAuthCallback>(nullptr);
    ASSERT_NE(testCallback, nullptr);
    EXPECT_EQ(DomainAccountClient::GetInstance().AuthWithPopup(NON_EXISTENT_USER_ID, testCallback),
        ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: DomainAccountClientModuleTest_AuthWithPopup_003
 * @tc.desc: Auth domain account failed for invalid local id.
 * @tc.type: FUNC
 * @tc.require: issueI64KAM
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_AuthWithPopup_003, TestSize.Level0)
{
    int32_t invalidId = -1;
    auto callback = std::make_shared<MockDomainAuthCallback>();
    ASSERT_NE(callback, nullptr);
    EXPECT_CALL(*callback, OnResult(0, _)).Times(Exactly(0));
    auto testCallback = std::make_shared<TestDomainAuthCallback>(callback);
    ASSERT_NE(testCallback, nullptr);
    EXPECT_EQ(DomainAccountClient::GetInstance().AuthWithPopup(invalidId, testCallback),
        ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: DomainAccountClientModuleTest_AuthWithPopup_004
 * @tc.desc: Auth domain account failed for local user has no domain info.
 * @tc.type: FUNC
 * @tc.require: issueI64KAM
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_AuthWithPopup_004, TestSize.Level0)
{
    auto callback = std::make_shared<MockDomainAuthCallback>();
    ASSERT_NE(callback, nullptr);
    EXPECT_CALL(*callback, OnResult(0, _)).Times(Exactly(0));
    auto testCallback = std::make_shared<TestDomainAuthCallback>(callback);
    ASSERT_NE(testCallback, nullptr);
    OsAccountInfo osAccountInfo;
    ErrCode errCode = OsAccountManager::CreateOsAccount(STRING_NAME_TWO, OsAccountType::NORMAL, osAccountInfo);
    EXPECT_EQ(errCode, ERR_OK);
    errCode = OsAccountManager::ActivateOsAccount(osAccountInfo.GetLocalId());
    EXPECT_EQ(errCode, ERR_OK);
    EXPECT_EQ(DomainAccountClient::GetInstance().AuthWithPopup(osAccountInfo.GetLocalId(), testCallback),
        ERR_DOMAIN_ACCOUNT_SERVICE_NOT_DOMAIN_ACCOUNT);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(osAccountInfo.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: DomainAccountClientModuleTest_AuthWithPopup_005
 * @tc.desc: Auth domain account failed for current user has no domain info.
 * @tc.type: FUNC
 * @tc.require: issueI64KAM
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_AuthWithPopup_005, TestSize.Level0)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = OsAccountManager::CreateOsAccount(STRING_NAME_TWO, OsAccountType::NORMAL, osAccountInfo);
    EXPECT_EQ(errCode, ERR_OK);
    errCode = OsAccountManager::ActivateOsAccount(osAccountInfo.GetLocalId());
    EXPECT_EQ(errCode, ERR_OK);
    auto callback = std::make_shared<MockDomainAuthCallback>();
    ASSERT_NE(callback, nullptr);
    EXPECT_CALL(*callback, OnResult(0, _)).Times(Exactly(0));
    auto testCallback = std::make_shared<TestDomainAuthCallback>(callback);
    ASSERT_NE(testCallback, nullptr);
    EXPECT_EQ(DomainAccountClient::GetInstance().AuthWithPopup(0, testCallback),
        ERR_DOMAIN_ACCOUNT_SERVICE_NOT_DOMAIN_ACCOUNT);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(osAccountInfo.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: DomainAccountClientModuleTest_AuthWithPopup_006
 * @tc.desc: Auth domain user with popup successfully.
 * @tc.type: FUNC
 * @tc.require: issueI64KAU
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_AuthWithPopup_006, TestSize.Level0)
{
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = STRING_NAME;
    domainInfo.domain_ = STRING_DOMAIN;
    domainInfo.accountId_ = INVALID_STRING_ACCOUNTID;
    auto callback = std::make_shared<MockDomainCreateDomainAccountCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestCreateDomainAccountCallback>(callback);
    EXPECT_CALL(*callback, OnResult(ERR_OK, STRING_NAME, STRING_DOMAIN, _)).Times(Exactly(1));
    ASSERT_NE(testCallback, nullptr);
    ErrCode errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo, testCallback);
    {
        std::unique_lock<std::mutex> lock(testCallback->mutex);
        testCallback->cv.wait_for(
            lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
    }
    ASSERT_EQ(errCode, ERR_OK);

    auto authCallback = std::make_shared<MockDomainAuthCallback>();
    ASSERT_NE(authCallback, nullptr);
    EXPECT_CALL(*authCallback, OnResult(ERR_OK, _)).Times(Exactly(1));
    auto testAuthCallback = std::make_shared<TestDomainAuthCallback>(authCallback);
    ASSERT_NE(testAuthCallback, nullptr);
    int32_t userId = -1;
    errCode = OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, userId);
    EXPECT_EQ(errCode, ERR_OK);
    EXPECT_EQ(DomainAccountClient::GetInstance().AuthWithPopup(userId, testAuthCallback), ERR_OK);
    {
        std::unique_lock<std::mutex> lock(testAuthCallback->mutex);
        testAuthCallback->cv.wait_for(lock,
            std::chrono::seconds(WAIT_TIME), [lockCallback = testAuthCallback]() { return lockCallback->isReady; });
    }
    std::vector<uint8_t> resultToken;
    InnerDomainAccountManager::GetInstance().GetTokenFromMap(userId, resultToken);
    for (size_t index = 0; index < resultToken.size(); index++) {
        EXPECT_EQ(resultToken[index], TOKEN[index]);
    }
}

/**
 * @tc.name: DomainAccountClientModuleTest_CreateOsAccountForDomain_001
 * @tc.desc: CreateOsAccountForDomain failed with invalid param.
 * @tc.type: FUNC
 * @tc.require: I6KNUZ
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_CreateOsAccountForDomain_001, TestSize.Level0)
{
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = STRING_NAME_INVALID;
    domainInfo.domain_ = INVALID_STRING_DOMAIN;
    domainInfo.accountId_ = STRING_ACCOUNTID_NEW;
    auto callback = std::make_shared<MockDomainCreateDomainAccountCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestCreateDomainAccountCallback>(callback);
    EXPECT_CALL(*callback, OnResult(INVALID_CODE, _, _, _)).Times(Exactly(1));
    ASSERT_NE(testCallback, nullptr);
    ErrCode errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo, testCallback);
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
    EXPECT_EQ(errCode, ERR_OK);
}

/**
 * @tc.name: DomainAccountClientModuleTest_CreateOsAccountForDomain_003
 * @tc.desc: CreateOsAccountForDomain failed with bound failed.
 * @tc.type: FUNC
 * @tc.require: I6KNUZ
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_CreateOsAccountForDomain_003, TestSize.Level0)
{
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = STRING_NAME_BIND_INVALID;
    domainInfo.domain_ = INVALID_STRING_DOMAIN;
    domainInfo.accountId_ = STRING_ACCOUNTID_NEW;
    auto callback = std::make_shared<MockDomainCreateDomainAccountCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestCreateDomainAccountCallback>(callback);
    EXPECT_CALL(*callback, OnResult(INVALID_CODE, _, _, _)).Times(Exactly(1));
    ASSERT_NE(testCallback, nullptr);
    ErrCode errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo, testCallback);
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
    EXPECT_EQ(errCode, ERR_OK);
}

/**
 * @tc.name: DomainAccountClientModuleTest_CreateOsAccountForDomain_004
 * @tc.desc: CreateOsAccountForDomain failed with not register plugin.
 * @tc.type: FUNC
 * @tc.require: I6KNUZ
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_CreateOsAccountForDomain_004, TestSize.Level0)
{
    DomainAccountClient::GetInstance().UnregisterPlugin();
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = STRING_NAME;
    domainInfo.domain_ = INVALID_STRING_DOMAIN;
    domainInfo.accountId_ = STRING_ACCOUNTID_NEW;
    auto callback = std::make_shared<MockDomainCreateDomainAccountCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestCreateDomainAccountCallback>(callback);
    ErrCode errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo, testCallback);
    EXPECT_EQ(errCode, ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST);
}

/*
 * @tc.name: DomainAccountClientModuleTest_CreateOsAccountForDomain_005
 * @tc.desc: CreateOsAccountForDomain successfully with 100 bind domain.
 * @tc.type: FUNC
 * @tc.require: I6KNUZ
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_CreateOsAccountForDomain_005, TestSize.Level0)
{
    // query if the 100 account bound
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(OsAccountManager::QueryOsAccountById(OHOS::AccountSA::Constants::START_USER_ID, osAccountInfo), ERR_OK);
    DomainAccountInfo startUserDomainInfo;
    osAccountInfo.GetDomainInfo(startUserDomainInfo);
    bool bound = !startUserDomainInfo.accountName_.empty();

    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = ACCOUNT_NAME;
    domainInfo.domain_ = STRING_DOMAIN;
    domainInfo.accountId_ = STRING_ACCOUNTID;
    std::vector<std::string> constraints;
    constraints.emplace_back(CONSTRAINT_CREATE_ACCOUNT_DIRECTLY);
    ErrCode errCode = OsAccountManager::SetOsAccountConstraints(TEST_UID, constraints, true);
    ASSERT_EQ(errCode, ERR_OK);
    auto callback = std::make_shared<MockDomainCreateDomainAccountCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestCreateDomainAccountCallback>(callback);
    if (!bound) {
        EXPECT_CALL(*callback, OnResult(ERR_OK, ACCOUNT_NAME, STRING_DOMAIN, STRING_ACCOUNTID))
        .Times(Exactly(1));
    }

    ASSERT_NE(testCallback, nullptr);
    errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo, testCallback);
    EXPECT_EQ(errCode, bound ? ERR_OSACCOUNT_SERVICE_INNER_DOMAIN_ALREADY_BIND_ERROR : ERR_OK);
    if (!bound) {
        std::unique_lock<std::mutex> lock(testCallback->mutex);
        testCallback->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME),
                                  [lockCallback = testCallback]() { return lockCallback->isReady; });
    }
    errCode = OsAccountManager::SetOsAccountConstraints(TEST_UID, constraints, false);
    EXPECT_EQ(errCode, ERR_OK);
}

/*
 * @tc.name: DomainAccountClientModuleTest_CreateOsAccountForDomain_006
 * @tc.desc: CreateOsAccountForDomain failed with domain info is already bind.
 * @tc.type: FUNC
 * @tc.require: I6KNUZ
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_CreateOsAccountForDomain_006, TestSize.Level0)
{
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = STRING_NAME;
    domainInfo.domain_ = INVALID_STRING_DOMAIN;
    domainInfo.accountId_ = STRING_ACCOUNTID_NEW;
    auto callback = std::make_shared<MockDomainCreateDomainAccountCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestCreateDomainAccountCallback>(callback);
    EXPECT_CALL(*callback, OnResult(ERR_OK,
        STRING_NAME, INVALID_STRING_DOMAIN, STRING_ACCOUNTID_NEW)).Times(Exactly(1));
    ASSERT_NE(testCallback, nullptr);
    CreateOsAccountForDomainOptions options;
    options.shortName = "shortName";
    ErrCode errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo,
        testCallback, options);
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
    EXPECT_EQ(errCode, ERR_OK);
    errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo, testCallback);
    EXPECT_EQ(errCode, ERR_OSACCOUNT_SERVICE_INNER_DOMAIN_ALREADY_BIND_ERROR);
    int32_t userId = -1;
    errCode = OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, userId);
    EXPECT_EQ(errCode, ERR_OK);
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(OsAccountManager::QueryOsAccountById(userId, osAccountInfo), ERR_OK);
    EXPECT_EQ(osAccountInfo.GetShortName(), options.shortName);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId), ERR_OK);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: DomainAccountClientModuleTest_HasDomainAccount_001
 * @tc.desc: HasAccount falied with not get domain info.
 * @tc.type: FUNC
 * @tc.require: I6AQVM
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_HasDomainAccount_001, TestSize.Level0)
{
    DomainAccountInfo info;
    info.accountName_ = STRING_NAME_INVALID;
    info.domain_ = STRING_DOMAIN;
    info.accountId_ = STRING_ACCOUNTID;
    auto callback = std::make_shared<MockDomainHasDomainInfoCallback>();
    ASSERT_NE(callback, nullptr);
    EXPECT_CALL(*callback, OnResult(INVALID_CODE, _)).Times(Exactly(1));
    auto testCallback = std::make_shared<TestHasDomainInfoCallback>(callback);
    ASSERT_NE(testCallback, nullptr);
    EXPECT_EQ(DomainAccountClient::GetInstance().HasAccount(info, testCallback), ERR_OK);
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
}

/**
 * @tc.name: DomainAccountClientModuleTest_HasDomainAccount_002
 * @tc.desc: HasAccount successfully.
 * @tc.type: FUNC
 * @tc.require: I6AQVM
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_HasDomainAccount_002, TestSize.Level0)
{
    DomainAccountInfo info;
    info.accountName_ = STRING_NAME;
    info.domain_ = STRING_DOMAIN;
    info.accountId_ = STRING_ACCOUNTID;
    auto callback = std::make_shared<MockDomainHasDomainInfoCallback>();
    ASSERT_NE(callback, nullptr);
    EXPECT_CALL(*callback, OnResult(ERR_OK, true)).Times(Exactly(1));
    auto testCallback = std::make_shared<TestHasDomainInfoCallback>(callback);
    ASSERT_NE(testCallback, nullptr);
    EXPECT_EQ(DomainAccountClient::GetInstance().HasAccount(info, testCallback), ERR_OK);
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
}

/**
 * @tc.name: DomainAccountClientModuleTest_HasDomainAccount_003
 * @tc.desc: HasAccount falied with not register plugin.
 * @tc.type: FUNC
 * @tc.require: I6AQVM
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_HasDomainAccount_003, TestSize.Level0)
{
    DomainAccountClient::GetInstance().UnregisterPlugin();
    DomainAccountInfo info;
    info.accountName_ = STRING_NAME;
    info.domain_ = STRING_DOMAIN;
    info.accountId_ = STRING_ACCOUNTID;
    auto callback = std::make_shared<MockDomainHasDomainInfoCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestHasDomainInfoCallback>(callback);
    ASSERT_NE(testCallback, nullptr);
    EXPECT_CALL(*callback, OnResult(ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST, _)).Times(Exactly(1));
    EXPECT_EQ(DomainAccountClient::GetInstance().HasAccount(info, testCallback), ERR_OK);
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
}

/**
 * @tc.name: DomainAccountClientModuleTest_HasDomainAccount_004
 * @tc.desc: HasAccount callback is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_HasDomainAccount_004, TestSize.Level0)
{
    DomainAccountClient::GetInstance().UnregisterPlugin();
    DomainAccountInfo info;
    info.accountName_ = STRING_NAME;
    info.domain_ = STRING_DOMAIN;
    info.accountId_ = STRING_ACCOUNTID;
    std::shared_ptr<DomainAccountCallback> callback = nullptr;
    EXPECT_EQ(DomainAccountClient::GetInstance().HasAccount(info, callback),
        ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: DomainAccountClientModuleTest_GetAccessToken_001
 * @tc.desc: GetAccessToken successfully.
 * @tc.type: FUNC
 * @tc.require: I6JV52
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_GetAccessToken_001, TestSize.Level0)
{
    DomainAccountInfo info;
    info.accountName_ = STRING_NAME_TWO;
    info.domain_ = STRING_DOMAIN_NEW;
    info.accountId_ = INVALID_STRING_ACCOUNTID;

    auto callbackCreate = std::make_shared<MockDomainCreateDomainAccountCallback>();
    ASSERT_NE(callbackCreate, nullptr);
    auto testCallbackCreate = std::make_shared<TestCreateDomainAccountCallback>(callbackCreate);
    EXPECT_CALL(*callbackCreate, OnResult(ERR_OK,
        STRING_NAME_TWO, STRING_DOMAIN_NEW, STRING_ACCOUNTID_FIVE)).Times(Exactly(1));
    ASSERT_NE(testCallbackCreate, nullptr);
    ErrCode errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, info, testCallbackCreate);
    {
        std::unique_lock<std::mutex> lock(testCallbackCreate->mutex);
        testCallbackCreate->cv.wait_for(lock,
            std::chrono::seconds(WAIT_TIME), [lockCallback = testCallbackCreate]() { return lockCallback->isReady; });
    }
    ASSERT_EQ(errCode, ERR_OK);

    auto callback = std::make_shared<MockDomainGetAccessTokenCallback>();
    ASSERT_NE(callback, nullptr);
    EXPECT_CALL(*callback, OnResult(ERR_OK, DEFAULT_TOKEN)).Times(Exactly(1));
    auto testCallback = std::make_shared<TestGetAccessTokenCallback>(callback);
    ASSERT_NE(testCallback, nullptr);
    EXPECT_EQ(DomainAccountClient::GetInstance().UpdateAccountToken(info, DEFAULT_TOKEN), ERR_OK);
    AAFwk::WantParams parameters;
    EXPECT_EQ(DomainAccountClient::GetInstance().GetAccessToken(info, parameters, testCallback), ERR_OK);
    {
        std::unique_lock<std::mutex> lock(testCallback->mutex);
        testCallback->cv.wait_for(
            lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
    }
    int32_t userId = -1;
    errCode = OsAccountManager::GetOsAccountLocalIdFromDomain(info, userId);
    EXPECT_EQ(errCode, ERR_OK);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId), ERR_OK);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: DomainAccountClientModuleTest_GetAccessToken_002
 * @tc.desc: GetDomainAccessToken failed with callback is nullptr.
 * @tc.type: FUNC
 * @tc.require: I6JV52
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_GetAccessToken_002, TestSize.Level0)
{
    DomainAccountInfo info;
    AAFwk::WantParams parameters;
    EXPECT_EQ(DomainAccountClient::GetInstance().GetAccessToken(info, parameters, nullptr),
        ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: DomainAccountClientModuleTest_GetAccessToken_003
 * @tc.desc: GetDomainAccessToken failed with plugin return not ok.
 * @tc.type: FUNC
 * @tc.require: I6JV52
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_GetAccessToken_003, TestSize.Level0)
{
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = STRING_NAME_NEW;
    domainInfo.domain_ = STRING_DOMAIN_NEW;
    domainInfo.accountId_ = INVALID_STRING_ACCOUNTID;
    auto callback = std::make_shared<MockDomainCreateDomainAccountCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestCreateDomainAccountCallback>(callback);
    EXPECT_CALL(*callback, OnResult(ERR_OK,
        STRING_NAME_NEW, STRING_DOMAIN_NEW, INVALID_STRING_ACCOUNTID)).Times(Exactly(1));
    ASSERT_NE(testCallback, nullptr);
    ErrCode errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo, testCallback);
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
    ASSERT_EQ(errCode, ERR_OK);

    auto getCallback = std::make_shared<MockDomainGetAccessTokenCallback>();
    ASSERT_NE(getCallback, nullptr);
    auto testGetCallback = std::make_shared<TestGetAccessTokenCallback>(getCallback);
    ASSERT_NE(testGetCallback, nullptr);
    AAFwk::WantParams parameters;
    EXPECT_EQ(DomainAccountClient::GetInstance().GetAccessToken(domainInfo, parameters, testGetCallback),
        ERR_ACCOUNT_COMMON_NOT_AUTHENTICATED);
    int32_t userId = -1;
    errCode = OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, userId);
    EXPECT_EQ(errCode, ERR_OK);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId), ERR_OK);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: DomainAccountClientModuleTest_GetAccessToken_004
 * @tc.desc: GetDomainAccessToken failed with domain account not exit.
 * @tc.type: FUNC
 * @tc.require: I6JV52
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_GetAccessToken_004, TestSize.Level0)
{
    DomainAccountInfo info;
    info.accountName_ = "test1111";
    info.domain_ = STRING_DOMAIN;
    info.accountId_ = "STRING_ACCOUNTID";
    auto callback = std::make_shared<MockDomainGetAccessTokenCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestGetAccessTokenCallback>(callback);
    ASSERT_NE(testCallback, nullptr);
    AAFwk::WantParams parameters;
    EXPECT_EQ(DomainAccountClient::GetInstance().GetAccessToken(info, parameters, testCallback),
        ERR_DOMAIN_ACCOUNT_SERVICE_NOT_DOMAIN_ACCOUNT);
}

/**
 * @tc.name: DomainAccountClientModuleTest_GetAccessToken_005
 * @tc.desc: GetDomainAccessToken failed with plugin is nullptr.
 * @tc.type: FUNC
 * @tc.require: I6JV52
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_GetAccessToken_005, TestSize.Level0)
{
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = STRING_NAME_NEW;
    domainInfo.domain_ = STRING_DOMAIN_NEW;
    domainInfo.accountId_ = INVALID_STRING_ACCOUNTID;
    auto callback = std::make_shared<MockDomainCreateDomainAccountCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestCreateDomainAccountCallback>(callback);
    EXPECT_CALL(*callback, OnResult(ERR_OK,
        STRING_NAME_NEW, STRING_DOMAIN_NEW, INVALID_STRING_ACCOUNTID)).Times(Exactly(1));
    ASSERT_NE(testCallback, nullptr);
    ErrCode errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo, testCallback);
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
    ASSERT_EQ(errCode, ERR_OK);

    DomainAccountClient::GetInstance().UnregisterPlugin();
    auto getAccessTokencallback = std::make_shared<MockDomainGetAccessTokenCallback>();
    ASSERT_NE(getAccessTokencallback, nullptr);
    auto testGetTokenCallback = std::make_shared<TestGetAccessTokenCallback>(getAccessTokencallback);
    ASSERT_NE(testGetTokenCallback, nullptr);
    AAFwk::WantParams parameters;
    EXPECT_EQ(DomainAccountClient::GetInstance().GetAccessToken(domainInfo, parameters, testGetTokenCallback),
        ERR_ACCOUNT_COMMON_NOT_AUTHENTICATED);
    int32_t userId = -1;
    errCode = OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, userId);
    EXPECT_EQ(errCode, ERR_OK);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId), ERR_OK);
}

/**
 * @tc.name: DomainAccountClientModuleTest_GetAccessToken_006
 * @tc.desc: GetAccessToken successfully with domain and accountName is invalid accountId is valid.
 * @tc.type: FUNC
 * @tc.require: I6JV52
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_GetAccessToken_006, TestSize.Level0)
{
    DomainAccountInfo info;
    info.accountName_ = STRING_NAME_TWO;
    info.domain_ = STRING_DOMAIN_NEW;
    info.accountId_ = INVALID_STRING_ACCOUNTID;

    auto callbackCreate = std::make_shared<MockDomainCreateDomainAccountCallback>();
    ASSERT_NE(callbackCreate, nullptr);
    auto testCallbackCreate = std::make_shared<TestCreateDomainAccountCallback>(callbackCreate);
    EXPECT_CALL(*callbackCreate, OnResult(ERR_OK,
        STRING_NAME_TWO, STRING_DOMAIN_NEW, STRING_ACCOUNTID_FIVE)).Times(Exactly(1));
    ASSERT_NE(testCallbackCreate, nullptr);
    ErrCode errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, info, testCallbackCreate);
    std::unique_lock<std::mutex> lock(testCallbackCreate->mutex);
    testCallbackCreate->cv.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallbackCreate]() { return lockCallback->isReady; });
    ASSERT_EQ(errCode, ERR_OK);

    auto callback = std::make_shared<MockDomainGetAccessTokenCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestGetAccessTokenCallback>(callback);
    ASSERT_NE(testCallback, nullptr);
    AAFwk::WantParams parameters;
    DomainAccountInfo info2;
    info2.accountId_ = "555";
    EXPECT_EQ(DomainAccountClient::GetInstance().GetAccessToken(info2, parameters, testCallback),
        ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
    int32_t userId = -1;
    errCode = OsAccountManager::GetOsAccountLocalIdFromDomain(info, userId);
    EXPECT_EQ(errCode, ERR_OK);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId), ERR_OK);
}

/**
 * @tc.name: DomainAccountClientModuleTest_UpdateAccountToken_001
 * @tc.desc: UpdateAccountToken successfully.
 * @tc.type: FUNC
 * @tc.require: I6JV52
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_UpdateAccountToken_001, TestSize.Level0)
{
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = STRING_NAME_NEW;
    domainInfo.domain_ = STRING_DOMAIN_NEW;
    domainInfo.accountId_ = INVALID_STRING_ACCOUNTID;
    auto callback = std::make_shared<MockDomainCreateDomainAccountCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestCreateDomainAccountCallback>(callback);
    EXPECT_CALL(*callback, OnResult(ERR_OK, STRING_NAME_NEW, STRING_DOMAIN_NEW, INVALID_STRING_ACCOUNTID))
        .Times(Exactly(1));
    ASSERT_NE(testCallback, nullptr);
    ErrCode errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo, testCallback);
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
    ASSERT_EQ(errCode, ERR_OK);

    std::vector<uint8_t> token;
    EXPECT_EQ(DomainAccountClient::GetInstance().UpdateAccountToken(domainInfo, token), ERR_OK);
    int32_t userId = -1;
    errCode = OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, userId);
    EXPECT_EQ(errCode, ERR_OK);
    std::vector<uint8_t> resultToken;
    InnerDomainAccountManager::GetInstance().GetTokenFromMap(userId, resultToken);
    EXPECT_EQ(resultToken.empty(), true);
    token = {1, 10, 100};
    EXPECT_EQ(DomainAccountClient::GetInstance().UpdateAccountToken(domainInfo, token), ERR_OK);
    InnerDomainAccountManager::GetInstance().GetTokenFromMap(userId, resultToken);
    for (size_t index = 0; index < resultToken.size(); index++) {
        EXPECT_EQ(resultToken[index], token[index]);
    }
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId), ERR_OK);
    InnerDomainAccountManager::GetInstance().GetTokenFromMap(userId, resultToken);
    EXPECT_EQ(resultToken.empty(), true);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: DomainAccountClientModuleTest_UpdateAccountToken_003
 * @tc.desc: UpdateAccountToken failed with invalid domaininfo.
 * @tc.type: FUNC
 * @tc.require: I6JV52
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_UpdateAccountToken_003, TestSize.Level0)
{
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "11";
    domainInfo.domain_ = STRING_DOMAIN_NEW;
    domainInfo.accountId_ = "testid";

    std::vector<uint8_t> token = {1};
    EXPECT_EQ(DomainAccountClient::GetInstance().UpdateAccountToken(domainInfo, token),
        ERR_DOMAIN_ACCOUNT_SERVICE_NOT_DOMAIN_ACCOUNT);
}

/**
 * @tc.name: DomainAccountClientModuleTest_UpdateAccountToken_004
 * @tc.desc: UpdateAccountToken failed with plugin is nullptr.
 * @tc.type: FUNC
 * @tc.require: I6JV52
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_UpdateAccountToken_004, TestSize.Level0)
{
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "11";
    domainInfo.domain_ = STRING_DOMAIN_NEW;
    domainInfo.accountId_ = "testid";
    DomainAccountClient::GetInstance().UnregisterPlugin();
    std::vector<uint8_t> token = {1};
    EXPECT_EQ(DomainAccountClient::GetInstance().UpdateAccountToken(domainInfo, token),
        ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST);
}

/**
 * @tc.name: DomainAccountClientModuleTest_GetAccountStatus_001
 * @tc.desc: GetAccountStatus with invalid domain_.
 * @tc.type: FUNC
 * @tc.require: issueI64KAM
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_GetAccountStatus_001, TestSize.Level0)
{
    DomainAccountStatus status;
    DomainAccountInfo domainInfo;
    EXPECT_EQ(DomainAccountClient::GetInstance().GetAccountStatus(domainInfo, status),
        ERR_DOMAIN_ACCOUNT_SERVICE_NOT_DOMAIN_ACCOUNT);
}

/**
 * @tc.name: DomainAccountClientModuleTest_GetAccountStatus_002
 * @tc.desc: GetAccountStatus when plugin is null.
 * @tc.type: FUNC
 * @tc.require: issueI64KAM
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_GetAccountStatus_002, TestSize.Level0)
{
    setuid(TEST_UID);
    DomainAccountStatus status;
    DomainAccountInfo domainInfo(STRING_DOMAIN, STRING_NAME);
    EXPECT_EQ(DomainAccountClient::GetInstance().GetAccountStatus(domainInfo, status),
        ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    setuid(ROOT_UID);
}

/**
 * @tc.name: DomainAccountClientModuleTest_GetAccountStatus_003
 * @tc.desc: GetAccountStatus when plugin is null.
 * @tc.type: FUNC
 * @tc.require: issueI64KAM
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_GetAccountStatus_003, TestSize.Level0)
{
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = STRING_NAME_TWO;
    domainInfo.domain_ = STRING_DOMAIN_NEW;
    domainInfo.accountId_ = INVALID_STRING_ACCOUNTID;
    auto callback = std::make_shared<MockDomainCreateDomainAccountCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestCreateDomainAccountCallback>(callback);
    EXPECT_CALL(*callback, OnResult(ERR_OK, STRING_NAME_TWO, STRING_DOMAIN_NEW, _)).Times(Exactly(1));
    ASSERT_NE(testCallback, nullptr);
    ErrCode errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo, testCallback);
    {
        std::unique_lock<std::mutex> lock(testCallback->mutex);
        testCallback->cv.wait_for(
            lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
    }
    ASSERT_EQ(errCode, ERR_OK);

    int32_t localId = testCallback->GetLocalId();
    auto authCallback = std::make_shared<MockDomainAuthCallback>();
    ASSERT_NE(authCallback, nullptr);
    EXPECT_CALL(*authCallback, OnResult(ERR_OK, _)).Times(Exactly(1));
    auto testAuthCallback = std::make_shared<TestDomainAuthCallback>(authCallback);
    ASSERT_NE(testAuthCallback, nullptr);
    EXPECT_EQ(DomainAccountClient::GetInstance().AuthUser(localId, DEFAULT_TOKEN, testAuthCallback), ERR_OK);
    {
        std::unique_lock<std::mutex> lock(testAuthCallback->mutex);
        testAuthCallback->cv.wait_for(lock,
            std::chrono::seconds(WAIT_TIME), [lockCallback = testAuthCallback]() { return lockCallback->isReady; });
    }

    std::vector<uint8_t> nullToken;
    DomainAccountClient::GetInstance().UpdateAccountToken(domainInfo, nullToken);
    DomainAccountStatus status;
    EXPECT_EQ(DomainAccountClient::GetInstance().GetAccountStatus(domainInfo, status), ERR_OK);

    std::vector<uint8_t> invalidToken = {1, 2, 5, 8}; // {1, 2, 5, 8} means invalid token vector.
    InnerDomainAccountManager::GetInstance().InsertTokenToMap(localId, invalidToken);
    DomainAccountClient::GetInstance().UpdateAccountToken(domainInfo, invalidToken);

    EXPECT_EQ(DomainAccountClient::GetInstance().GetAccountStatus(domainInfo, status), ERR_OK);
    EXPECT_EQ(status, DomainAccountStatus::LOGIN_BACKGROUND);

    EXPECT_EQ(OsAccountManager::RemoveOsAccount(localId), ERR_OK);
}

/**
 * @tc.name: DomainAccountClientModuleTest_GetAccountStatus_004
 * @tc.desc: GetAccountStatus when plugin is null.
 * @tc.type: FUNC
 * @tc.require: issueI64KAM
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_GetAccountStatus_004, TestSize.Level0)
{
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = STRING_NAME_TWO;
    domainInfo.domain_ = STRING_DOMAIN_NEW;
    domainInfo.accountId_ = INVALID_STRING_ACCOUNTID;
    auto callback = std::make_shared<MockDomainCreateDomainAccountCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestCreateDomainAccountCallback>(callback);
    EXPECT_CALL(*callback, OnResult(ERR_OK, domainInfo.accountName_, domainInfo.domain_, _)).Times(Exactly(1));
    ASSERT_NE(testCallback, nullptr);
    ErrCode errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo, testCallback);
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
    ASSERT_EQ(errCode, ERR_OK);

    int32_t userId = -1;
    errCode = OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, userId);
    EXPECT_EQ(errCode, ERR_OK);

    InnerDomainAccountManager::GetInstance().InsertTokenToMap(userId, DEFAULT_TOKEN);

    DomainAccountClient::GetInstance().UpdateAccountToken(domainInfo, DEFAULT_TOKEN);

    DomainAccountStatus status;
    EXPECT_EQ(DomainAccountClient::GetInstance().GetAccountStatus(domainInfo, status), ERR_OK);
    EXPECT_EQ(status, DomainAccountStatus::LOGIN_BACKGROUND);

    EXPECT_EQ(OsAccountManager::ActivateOsAccount(userId), ERR_OK);

    EXPECT_EQ(DomainAccountClient::GetInstance().GetAccountStatus(domainInfo, status), ERR_OK);

    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId), ERR_OK);
}

/**
 * @tc.name: DomainAccountClientModuleTest_GetAccountStatus_006
 * @tc.desc: GetAccountStatus.
 * @tc.type: FUNC
 * @tc.require: issueI64KAM
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_GetAccountStatus_006, TestSize.Level0)
{
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = STRING_NAME_TWO;
    domainInfo.domain_ = STRING_DOMAIN_NEW;
    domainInfo.accountId_ = INVALID_STRING_ACCOUNTID;
    auto callback = std::make_shared<MockDomainCreateDomainAccountCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestCreateDomainAccountCallback>(callback);
    EXPECT_CALL(*callback, OnResult(ERR_OK, domainInfo.accountName_, domainInfo.domain_, _)).Times(Exactly(1));
    ASSERT_NE(testCallback, nullptr);
    ErrCode errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo, testCallback);
    {
        std::unique_lock<std::mutex> lock(testCallback->mutex);
        testCallback->cv.wait_for(
            lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
    }
    ASSERT_EQ(errCode, ERR_OK);

    auto authCallback = std::make_shared<MockDomainAuthCallback>();
    ASSERT_NE(authCallback, nullptr);
    EXPECT_CALL(*authCallback, OnResult(_, _)).Times(Exactly(1));
    auto testAuthCallback = std::make_shared<TestDomainAuthCallback>(authCallback);
    ASSERT_NE(testAuthCallback, nullptr);
    int32_t userId = -1;
    errCode = OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, userId);
    EXPECT_EQ(errCode, ERR_OK);
    EXPECT_EQ(DomainAccountClient::GetInstance().AuthUser(userId, DEFAULT_TOKEN, testAuthCallback), ERR_OK);
    {
        std::unique_lock<std::mutex> lock(testAuthCallback->mutex);
        testAuthCallback->cv.wait_for(lock,
            std::chrono::seconds(WAIT_TIME), [lockCallback = testAuthCallback]() { return lockCallback->isReady; });
    }
    DomainAccountClient::GetInstance().UpdateAccountToken(domainInfo, DEFAULT_TOKEN);

    DomainAccountClient::GetInstance().UnregisterPlugin();
    DomainAccountStatus status;
    DomainAccountClient::GetInstance().GetAccountStatus(domainInfo, status);

    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId), ERR_OK);
}

/**
 * @tc.name: DomainAccountClientModuleTest_GetAccountStatus_007
 * @tc.desc: GetAccountStatus.
 * @tc.type: FUNC
 * @tc.require: issueI64KAM
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_GetAccountStatus_007, TestSize.Level0)
{
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = STRING_NAME_TWO;
    domainInfo.domain_ = STRING_DOMAIN_NEW;
    domainInfo.accountId_ = INVALID_STRING_ACCOUNTID;
    auto callback = std::make_shared<MockDomainCreateDomainAccountCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestCreateDomainAccountCallback>(callback);
    EXPECT_CALL(*callback, OnResult(ERR_OK, domainInfo.accountName_, domainInfo.domain_, _)).Times(Exactly(1));
    ASSERT_NE(testCallback, nullptr);
    ErrCode errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo, testCallback);
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
    ASSERT_EQ(errCode, ERR_OK);

    int32_t userId = -1;
    errCode = OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, userId);
    EXPECT_EQ(errCode, ERR_OK);

    DomainAccountClient::GetInstance().UpdateAccountToken(domainInfo, DEFAULT_TOKEN);
    InnerDomainAccountManager::GetInstance().InsertTokenToMap(userId, DEFAULT_TOKEN);

    DomainAccountStatus status;
    DomainAccountInfo info2;
    info2.accountId_ = "555";
    EXPECT_EQ(DomainAccountClient::GetInstance().GetAccountStatus(info2, status), ERR_OK);
    EXPECT_EQ(status, DomainAccountStatus::LOGIN_BACKGROUND);

    EXPECT_EQ(OsAccountManager::ActivateOsAccount(userId), ERR_OK);

    EXPECT_EQ(DomainAccountClient::GetInstance().GetAccountStatus(info2, status), ERR_OK);

    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId), ERR_OK);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

class ListenerLogIn final : public DomainAccountStatusListener {
public:
    ListenerLogIn()
    {}
    ~ListenerLogIn()
    {}
    virtual void OnStatusChanged(const DomainAccountEventData &data)
    {
        EXPECT_EQ(data.event, DomainAccountEvent::LOG_IN);
        EXPECT_EQ(data.status, DomainAccountStatus::LOGIN);
        EXPECT_NE(data.userId, -1);
        if (visited) {
            visitedTwice = true;
        }
        visited = true;
    }

    bool visited = false;
    bool visitedTwice = false;
};

class ListenerLogInBackGround final : public DomainAccountStatusListener {
public:
    ListenerLogInBackGround()
    {}
    ~ListenerLogInBackGround()
    {}
    virtual void OnStatusChanged(const DomainAccountEventData &data)
    {
        EXPECT_EQ(data.event, DomainAccountEvent::LOG_IN);
        EXPECT_EQ(data.status, DomainAccountStatus::LOGIN_BACKGROUND);
        EXPECT_NE(data.userId, -1);
        if (visited) {
            visitedTwice = true;
        }
        visited = true;
    }

    bool visited = false;
    bool visitedTwice = false;
};

class ListenerLogUpdate final : public DomainAccountStatusListener {
public:
    ListenerLogUpdate()
    {}
    ~ListenerLogUpdate()
    {}
    virtual void OnStatusChanged(const DomainAccountEventData &data)
    {
        EXPECT_EQ(data.event, DomainAccountEvent::TOKEN_UPDATED);
        EXPECT_EQ(data.status, DomainAccountStatus::LOGIN);
        EXPECT_NE(data.userId, -1);
        if (visited) {
            visitedTwice = true;
        }
        visited = true;
    }

    bool visited = false;
    bool visitedTwice = false;
};

class ListenerLogUpdateBackGround final : public DomainAccountStatusListener {
public:
    ListenerLogUpdateBackGround()
    {}
    ~ListenerLogUpdateBackGround()
    {}
    virtual void OnStatusChanged(const DomainAccountEventData &data)
    {
        EXPECT_EQ(data.event, DomainAccountEvent::TOKEN_UPDATED);
        EXPECT_EQ(data.status, DomainAccountStatus::LOGIN_BACKGROUND);
        EXPECT_NE(data.userId, -1);
        if (visited) {
            visitedTwice = true;
        }
        visited = true;
    }

    bool visited = false;
    bool visitedTwice = false;
};

class ListenerLogInvalid final : public DomainAccountStatusListener {
public:
    ListenerLogInvalid()
    {}
    ~ListenerLogInvalid()
    {}
    virtual void OnStatusChanged(const DomainAccountEventData &data)
    {
        EXPECT_EQ(data.event, DomainAccountEvent::TOKEN_INVALID);
        EXPECT_EQ(data.status, DomainAccountStatus::LOGOUT);
        EXPECT_NE(data.userId, -1);
        if (visited) {
            visitedTwice = true;
        }
        visited = true;
    }

    bool visited = false;
    bool visitedTwice = false;
};

class ListenerLogOut final : public DomainAccountStatusListener {
public:
    ListenerLogOut()
    {}
    ~ListenerLogOut()
    {}
    virtual void OnStatusChanged(const DomainAccountEventData &data)
    {
        EXPECT_EQ(data.event, DomainAccountEvent::LOG_OUT);
        EXPECT_EQ(data.status, DomainAccountStatus::LOGOUT);
        EXPECT_NE(data.userId, -1);
        if (visited) {
            visitedTwice = true;
        }
        visited = true;
    }

    bool visited = false;
    bool visitedTwice = false;
};

/**
 * @tc.name: RegisterAccountStatusListener_001
 * @tc.desc: GetAccountStatus.
 * @tc.type: FUNC
 * @tc.require: issueI64KAM
 */
HWTEST_F(DomainAccountClientModuleTest, RegisterAccountStatusListener_001, TestSize.Level0)
{
    setuid(TEST_UID);
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = STRING_NAME_NEW;
    domainInfo.domain_ = STRING_DOMAIN;
    domainInfo.accountId_ = STRING_ACCOUNTID;
    auto listener = std::make_shared<ListenerLogIn>();
    EXPECT_EQ(DomainAccountClient::GetInstance().RegisterAccountStatusListener(listener),
        ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    setuid(ROOT_UID);
}

/**
 * @tc.name: UnregisterAccountStatusListener_001
 * @tc.desc: RegisterAccountStatusListener.
 * @tc.type: FUNC
 * @tc.require: issueI64KAM
 */
HWTEST_F(DomainAccountClientModuleTest, UnregisterAccountStatusListener_001, TestSize.Level0)
{
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = STRING_NAME_NEW;
    domainInfo.domain_ = STRING_DOMAIN;
    domainInfo.accountId_ = STRING_ACCOUNTID;
    auto listener = std::make_shared<ListenerLogIn>();
    EXPECT_EQ(DomainAccountClient::GetInstance().UnregisterAccountStatusListener(listener), ERR_OK);
}

/**
 * @tc.name: RegisterAccountStatusListener_002
 * @tc.desc: RegisterAccountStatusListener.
 * @tc.type: FUNC
 * @tc.require: issueI64KAM
 */
HWTEST_F(DomainAccountClientModuleTest, RegisterAccountStatusListener_002, TestSize.Level0)
{
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "";
    domainInfo.domain_ = "";
    domainInfo.accountId_ = "";
    auto listener = std::make_shared<ListenerLogIn>();
    EXPECT_EQ(DomainAccountClient::GetInstance().RegisterAccountStatusListener(listener), ERR_OK);
    EXPECT_EQ(DomainAccountClient::GetInstance().UnregisterAccountStatusListener(listener), ERR_OK);
}

#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
void CreateDomainAccount(const DomainAccountInfo domainInfo)
{
    auto callback = std::make_shared<MockDomainCreateDomainAccountCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestCreateDomainAccountCallback>(callback);
    EXPECT_CALL(*callback, OnResult(ERR_OK, domainInfo.accountName_, domainInfo.domain_, _)).Times(Exactly(1));
    ASSERT_NE(testCallback, nullptr);
    ErrCode errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo, testCallback);
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
    EXPECT_EQ(errCode, ERR_OK);
}

/**
 * @tc.name: RegisterAccountStatusListener_004
 * @tc.desc: RegisterAccountStatusListener log in
 * @tc.type: FUNC
 * @tc.require: issueI64KAM
 */
HWTEST_F(DomainAccountClientModuleTest, RegisterAccountStatusListener_004, TestSize.Level0)
{
    DomainAccountInfo domainInfo(STRING_DOMAIN_NEW, STRING_NAME_TWO, INVALID_STRING_ACCOUNTID);
    CreateDomainAccount(domainInfo);

    DomainAccountInfo domainInfo1(STRING_DOMAIN_NEW, STRING_NAME_NEW, STRING_ACCOUNTID_NEW);
    CreateDomainAccount(domainInfo1);
    auto listener3 = std::make_shared<ListenerLogInBackGround>();
    EXPECT_EQ(DomainAccountClient::GetInstance().RegisterAccountStatusListener(listener3), ERR_OK);
    EXPECT_EQ(DomainAccountClient::GetInstance().RegisterAccountStatusListener(listener3), ERR_OK);

    auto authCallback = std::make_shared<MockDomainAuthCallbackForListener>();
    ASSERT_NE(authCallback, nullptr);
    EXPECT_CALL(*authCallback, OnResult(ERR_OK, _)).Times(Exactly(2));
    auto testAuthCallback = std::make_shared<TestDomainAuthCallbackForListener>(authCallback);
    ASSERT_NE(testAuthCallback, nullptr);
    int32_t userId = -1;
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, userId), ERR_OK);
    EXPECT_EQ(DomainAccountClient::GetInstance().AuthUser(userId, DEFAULT_TOKEN, testAuthCallback), ERR_OK);
    {
        std::unique_lock<std::mutex> lock1(testAuthCallback->mutex);
        testAuthCallback->cv.wait_for(lock1, std::chrono::seconds(WAIT_TIME),
                                      [lockCallback = testAuthCallback]() { return lockCallback->isReady; });
    }
    testAuthCallback->isReady = false;
    int32_t userId1 = -1;
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo1, userId1), ERR_OK);
    EXPECT_EQ(DomainAccountClient::GetInstance().AuthUser(userId1, DEFAULT_TOKEN, testAuthCallback), ERR_OK);
    {
        std::unique_lock<std::mutex> lock2(testAuthCallback->mutex);
        testAuthCallback->cv.wait_for(lock2, std::chrono::seconds(WAIT_TIME),
                                      [lockCallback = testAuthCallback]() { return lockCallback->isReady; });
    }
    EXPECT_EQ(listener3->visited, true);
    EXPECT_EQ(listener3->visitedTwice, true);
    EXPECT_EQ(DomainAccountClient::GetInstance().UnregisterAccountStatusListener(listener3), ERR_OK);

    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId), ERR_OK);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId1), ERR_OK);
}

/**
 * @tc.name: RegisterAccountStatusListener_005
 * @tc.desc: RegisterAccountStatusListener log in
 * @tc.type: FUNC
 * @tc.require: issueI64KAM
 */
HWTEST_F(DomainAccountClientModuleTest, RegisterAccountStatusListener_005, TestSize.Level0)
{
    DomainAccountInfo domainInfo(STRING_DOMAIN_NEW, STRING_NAME_TWO, INVALID_STRING_ACCOUNTID);
    CreateDomainAccount(domainInfo);

    DomainAccountInfo domainInfo1(STRING_DOMAIN_NEW, STRING_NAME_NEW, STRING_ACCOUNTID_NEW);
    CreateDomainAccount(domainInfo1);

    auto listener3 = std::make_shared<ListenerLogIn>();
    EXPECT_EQ(DomainAccountClient::GetInstance().RegisterAccountStatusListener(listener3), ERR_OK);
    int32_t userId;
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, userId), ERR_OK);
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(userId), ERR_OK);

    auto authCallback = std::make_shared<MockDomainAuthCallbackForListener>();
    ASSERT_NE(authCallback, nullptr);
    EXPECT_CALL(*authCallback, OnResult(ERR_OK, _)).Times(Exactly(2));
    auto testAuthCallback = std::make_shared<TestDomainAuthCallbackForListener>(authCallback);
    ASSERT_NE(testAuthCallback, nullptr);
    EXPECT_EQ(DomainAccountClient::GetInstance().AuthUser(userId, DEFAULT_TOKEN, testAuthCallback), ERR_OK);
    {
        std::unique_lock<std::mutex> lock1(testAuthCallback->mutex);
        testAuthCallback->cv.wait_for(lock1, std::chrono::seconds(WAIT_TIME),
                                      [lockCallback = testAuthCallback]() { return lockCallback->isReady; });
    }
    testAuthCallback->isReady = false;
    int32_t userId1;
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo1, userId1), ERR_OK);
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(userId1), ERR_OK);
    EXPECT_EQ(DomainAccountClient::GetInstance().AuthUser(userId1, DEFAULT_TOKEN, testAuthCallback), ERR_OK);
    {
        std::unique_lock<std::mutex> lock2(testAuthCallback->mutex);
        testAuthCallback->cv.wait_for(lock2, std::chrono::seconds(WAIT_TIME),
                                      [lockCallback = testAuthCallback]() { return lockCallback->isReady; });
    }

    EXPECT_EQ(listener3->visited, true);
    EXPECT_EQ(listener3->visitedTwice, true);
    EXPECT_EQ(DomainAccountClient::GetInstance().UnregisterAccountStatusListener(listener3), ERR_OK);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId), ERR_OK);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId1), ERR_OK);
}

/**
 * @tc.name: RegisterAccountStatusListener_006
 * @tc.desc: RegisterAccountStatusListener token update
 * @tc.type: FUNC
 * @tc.require: issueI64KAM
 */
HWTEST_F(DomainAccountClientModuleTest, RegisterAccountStatusListener_006, TestSize.Level0)
{
    DomainAccountInfo domainInfo(STRING_DOMAIN_NEW, STRING_NAME_TWO, INVALID_STRING_ACCOUNTID);
    CreateDomainAccount(domainInfo);

    DomainAccountInfo domainInfo1(STRING_DOMAIN_NEW, STRING_NAME_NEW, STRING_ACCOUNTID_NEW);
    CreateDomainAccount(domainInfo1);
    auto listener3 = std::make_shared<ListenerLogUpdate>();
    EXPECT_EQ(DomainAccountClient::GetInstance().RegisterAccountStatusListener(listener3), ERR_OK);
    int32_t userId = -1;
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, userId), ERR_OK);
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(userId), ERR_OK);

    std::vector<uint8_t> token = {1, 10, 100}; // {1, 10, 100} is token
    EXPECT_EQ(DomainAccountClient::GetInstance().UpdateAccountToken(domainInfo, token), ERR_OK);
    std::vector<uint8_t> resultToken;
    InnerDomainAccountManager::GetInstance().GetTokenFromMap(userId, resultToken);
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo1, userId), ERR_OK);
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(userId), ERR_OK);

    EXPECT_EQ(DomainAccountClient::GetInstance().UpdateAccountToken(domainInfo1, token), ERR_OK);
    resultToken.clear();
    InnerDomainAccountManager::GetInstance().GetTokenFromMap(userId, resultToken);
    EXPECT_EQ(listener3->visited, true);
    EXPECT_EQ(listener3->visitedTwice, true);
    EXPECT_EQ(DomainAccountClient::GetInstance().UnregisterAccountStatusListener(listener3), ERR_OK);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId), ERR_OK);
    InnerDomainAccountManager::GetInstance().GetTokenFromMap(userId, resultToken);
    EXPECT_EQ(resultToken.empty(), true);
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, userId), ERR_OK);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId), ERR_OK);
}

/**
 * @tc.name: RegisterAccountStatusListener_007
 * @tc.desc: RegisterAccountStatusListener token update
 * @tc.type: FUNC
 * @tc.require: issueI64KAM
 */
HWTEST_F(DomainAccountClientModuleTest, RegisterAccountStatusListener_007, TestSize.Level0)
{
    DomainAccountInfo domainInfo(STRING_DOMAIN_NEW, STRING_NAME_TWO, INVALID_STRING_ACCOUNTID);
    CreateDomainAccount(domainInfo);

    DomainAccountInfo domainInfo1(STRING_DOMAIN_NEW, STRING_NAME_NEW, STRING_ACCOUNTID_NEW);
    CreateDomainAccount(domainInfo1);

    auto listener3 = std::make_shared<ListenerLogUpdateBackGround>();
    EXPECT_EQ(DomainAccountClient::GetInstance().RegisterAccountStatusListener(listener3), ERR_OK);

    std::vector<uint8_t> token = {12, 10, 120}; // {12, 10, 120} is token
    EXPECT_EQ(DomainAccountClient::GetInstance().UpdateAccountToken(domainInfo, token), ERR_OK);
    std::vector<uint8_t> resultToken;
    int32_t userId = -1;
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, userId), ERR_OK);
    InnerDomainAccountManager::GetInstance().GetTokenFromMap(userId, resultToken);
    EXPECT_EQ(DomainAccountClient::GetInstance().UpdateAccountToken(domainInfo1, token), ERR_OK);
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo1, userId), ERR_OK);
    EXPECT_EQ(listener3->visited, true);
    EXPECT_EQ(listener3->visitedTwice, true);
    EXPECT_EQ(DomainAccountClient::GetInstance().UnregisterAccountStatusListener(listener3), ERR_OK);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId), ERR_OK);
    InnerDomainAccountManager::GetInstance().GetTokenFromMap(userId, resultToken);
    EXPECT_EQ(resultToken.empty(), true);
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, userId), ERR_OK);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId), ERR_OK);
}

/**
 * @tc.name: RegisterAccountStatusListener_008
 * @tc.desc: RegisterAccountStatusListener token invalid.
 * @tc.type: FUNC
 * @tc.require: issueI64KAM
 */
HWTEST_F(DomainAccountClientModuleTest, RegisterAccountStatusListener_008, TestSize.Level0)
{
    DomainAccountInfo domainInfo(STRING_DOMAIN_NEW, STRING_NAME_TWO, INVALID_STRING_ACCOUNTID);
    CreateDomainAccount(domainInfo);

    DomainAccountInfo domainInfo1(STRING_DOMAIN_NEW, STRING_NAME_NEW, STRING_ACCOUNTID_NEW);
    CreateDomainAccount(domainInfo1);

    auto listener3 = std::make_shared<ListenerLogInvalid>();
    EXPECT_EQ(DomainAccountClient::GetInstance().RegisterAccountStatusListener(listener3), ERR_OK);

    std::vector<uint8_t> token;
    EXPECT_EQ(DomainAccountClient::GetInstance().UpdateAccountToken(domainInfo, token), ERR_OK);
    int32_t userId = -1;
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, userId), ERR_OK);

    EXPECT_EQ(DomainAccountClient::GetInstance().UpdateAccountToken(domainInfo1, token), ERR_OK);
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo1, userId), ERR_OK);

    EXPECT_EQ(listener3->visited, true);
    EXPECT_EQ(listener3->visitedTwice, true);
    EXPECT_EQ(DomainAccountClient::GetInstance().UnregisterAccountStatusListener(listener3), ERR_OK);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId), ERR_OK);
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, userId), ERR_OK);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId), ERR_OK);
}

/**
 * @tc.name: RegisterAccountStatusListener_009
 * @tc.desc: RegisterAccountStatusListener log out.
 * @tc.type: FUNC
 * @tc.require: issueI64KAM
 */
HWTEST_F(DomainAccountClientModuleTest, RegisterAccountStatusListener_009, TestSize.Level0)
{
    DomainAccountInfo domainInfo(STRING_DOMAIN_NEW, STRING_NAME_TWO, INVALID_STRING_ACCOUNTID);
    CreateDomainAccount(domainInfo);

    DomainAccountInfo domainInfo1(STRING_DOMAIN_NEW, STRING_NAME_NEW, STRING_ACCOUNTID_NEW);
    CreateDomainAccount(domainInfo1);

    auto listener3 = std::make_shared<ListenerLogOut>();
    EXPECT_EQ(DomainAccountClient::GetInstance().RegisterAccountStatusListener(listener3), ERR_OK);

    int32_t userId;
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, userId), ERR_OK);
    EXPECT_EQ(listener3->visited, false);
    EXPECT_EQ(listener3->visitedTwice, false);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId), ERR_OK);
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo1, userId), ERR_OK);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId), ERR_OK);
    EXPECT_EQ(listener3->visited, true);
    EXPECT_EQ(listener3->visitedTwice, true);
    EXPECT_EQ(DomainAccountClient::GetInstance().UnregisterAccountStatusListener(listener3), ERR_OK);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: RegisterAccountStatusListener_015
 * @tc.desc: GetAccountStatus callback is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientModuleTest, RegisterAccountStatusListener_010, TestSize.Level0)
{
    std::shared_ptr<DomainAccountStatusListener> listener = nullptr;
    EXPECT_EQ(DomainAccountClient::GetInstance().RegisterAccountStatusListener(listener),
        ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: UnregisterAccountStatusListener_002
 * @tc.desc: RegisterAccountStatusListener callback is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientModuleTest, UnregisterAccountStatusListener_002, TestSize.Level0)
{
    DomainAccountInfo domainInfo;
    std::shared_ptr<DomainAccountStatusListener> listener = nullptr;
    EXPECT_EQ(DomainAccountClient::GetInstance().UnregisterAccountStatusListener(listener),
        ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AuthProxyInit_001
 * @tc.desc: AuthProxyInit callback is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientModuleTest, AuthProxyInit_001, TestSize.Level0)
{
    std::shared_ptr<DomainAccountCallback> callback = nullptr;
    sptr<DomainAccountCallbackService> callbackService;
    sptr<IDomainAccount> proxy;

    EXPECT_EQ(DomainAccountClient::GetInstance().AuthProxyInit(callback, callbackService, proxy),
        ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AuthProxyInit_002
 * @tc.desc: test AuthProxyInit.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientModuleTest, AuthProxyInit_002, TestSize.Level0)
{
    auto callback = std::make_shared<MockDomainAuthCallback>();
    ASSERT_NE(callback, nullptr);
    EXPECT_CALL(*callback, OnResult(0, _)).Times(Exactly(0));
    auto testCallback = std::make_shared<TestDomainAuthCallback>(callback);
    ASSERT_NE(testCallback, nullptr);
    sptr<DomainAccountCallbackService> callbackService = nullptr;
    sptr<IDomainAccount> proxy = nullptr;

    EXPECT_EQ(DomainAccountClient::GetInstance().AuthProxyInit(testCallback, callbackService, proxy), ERR_OK);
    EXPECT_NE(callbackService, nullptr);
    EXPECT_NE(proxy, nullptr);
}

/**
 * @tc.name: ResetDomainAccountProxy_001
 * @tc.desc: test ResetDomainAccountProxy.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientModuleTest, ResetDomainAccountProxy_001, TestSize.Level0)
{
    wptr<IRemoteObject> remote;
    ASSERT_NE(DomainAccountClient::GetInstance().GetDomainAccountProxy(), nullptr);
    DomainAccountClient::GetInstance().ResetDomainAccountProxy(remote);
    EXPECT_EQ(DomainAccountClient::GetInstance().proxy_, nullptr);

    DomainAccountClient::GetInstance().ResetDomainAccountProxy(remote);
    EXPECT_EQ(DomainAccountClient::GetInstance().proxy_, nullptr);
}

/**
 * @tc.name: DomainAccountClientModuleTest_GetDomainAccountInfo_001
 * @tc.desc: GetDomainAccountInfo falied with not get domain info.
 * @tc.type: FUNC
 * @tc.require: issueI7TJZR
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_GetDomainAccountInfo_001, TestSize.Level0)
{
    DomainAccountInfo info;
    info.accountName_ = STRING_NAME_INVALID;
    info.domain_ = STRING_DOMAIN;
    info.accountId_ = STRING_ACCOUNTID;
    auto callback = std::make_shared<MockGetDomainAccountInfoCallback>();
    ASSERT_NE(callback, nullptr);
    EXPECT_CALL(*callback, OnResult(INVALID_CODE, _)).Times(Exactly(1));
    auto testCallback = std::make_shared<TestGetDomainAccountInfoCallback>(callback);
    ASSERT_NE(testCallback, nullptr);
    EXPECT_EQ(DomainAccountClient::GetInstance().GetDomainAccountInfo(info, testCallback), ERR_OK);
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
}

/**`
 * @tc.name: DomainAccountClientModuleTest_GetDomainAccountInfo_002
 * @tc.desc: GetDomainAccountInfo successfully.
 * @tc.type: FUNC
 * @tc.require: issueI7TJZR
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_GetDomainAccountInfo_002, TestSize.Level0)
{
    DomainAccountInfo info;
    info.accountName_ = STRING_NAME;
    info.domain_ = STRING_DOMAIN;
    info.accountId_ = STRING_ACCOUNTID;
    auto callback = std::make_shared<MockGetDomainAccountInfoCallback>();
    ASSERT_NE(callback, nullptr);
    EXPECT_CALL(*callback, OnResult(ERR_OK, _)).Times(Exactly(1));
    auto testCallback = std::make_shared<TestGetDomainAccountInfoCallback>(callback);
    ASSERT_NE(testCallback, nullptr);
    EXPECT_EQ(DomainAccountClient::GetInstance().GetDomainAccountInfo(info, testCallback), ERR_OK);
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
    testing::Mock::AllowLeak(callback.get());
}

/**
 * @tc.name: DomainAccountClientModuleTest_GetDomainAccountInfo_003
 * @tc.desc: GetDomainAccountInfo falied with not register plugin.
 * @tc.type: FUNC
 * @tc.require: issueI7TJZR
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_GetDomainAccountInfo_003, TestSize.Level0)
{
    DomainAccountClient::GetInstance().UnregisterPlugin();
    DomainAccountInfo info;
    info.accountName_ = STRING_NAME;
    info.domain_ = STRING_DOMAIN;
    info.accountId_ = STRING_ACCOUNTID;
    auto callback = std::make_shared<MockGetDomainAccountInfoCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestGetDomainAccountInfoCallback>(callback);
    ASSERT_NE(testCallback, nullptr);
    EXPECT_CALL(*callback, OnResult(ERR_JS_CAPABILITY_NOT_SUPPORTED, _)).Times(Exactly(1));
    EXPECT_EQ(DomainAccountClient::GetInstance().GetDomainAccountInfo(info, testCallback), ERR_OK);
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
}

/**
 * @tc.name: DomainAccountClientModuleTest_GetDomainAccountInfo_004
 * @tc.desc: GetDomainAccountInfo callback is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI7TJZR
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_GetDomainAccountInfo_004, TestSize.Level0)
{
    DomainAccountClient::GetInstance().UnregisterPlugin();
    DomainAccountInfo info;
    info.accountName_ = STRING_NAME;
    info.domain_ = STRING_DOMAIN;
    info.accountId_ = STRING_ACCOUNTID;
    std::shared_ptr<DomainAccountCallback> callback = nullptr;
    EXPECT_EQ(DomainAccountClient::GetInstance().GetDomainAccountInfo(info, callback),
        ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: DomainAccountClientModuleTest_AddServerConfig_001
 * @tc.desc: AddServerConfig.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_AddServerConfig_001, TestSize.Level0)
{
    DomainServerConfig config;
    std::string identifier;
    DomainAccountInfo info;
    EXPECT_EQ(DomainAccountClient::GetInstance().AddServerConfig(identifier, config),
        ERR_JS_CAPABILITY_NOT_SUPPORTED);
    EXPECT_EQ(DomainAccountClient::GetInstance().GetAccountServerConfig(info, config),
        ERR_JS_CAPABILITY_NOT_SUPPORTED);
    EXPECT_EQ(DomainAccountClient::GetInstance().RemoveServerConfig(identifier),
        ERR_JS_CAPABILITY_NOT_SUPPORTED);
}

/**
 * @tc.name: DomainAccountClientModuleTest_UpdateAccountInfo_001
 * @tc.desc: UpdateAccountInfo failed for permission denied.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_UpdateAccountInfo_001, TestSize.Level0)
{
    setuid(TEST_UID);
    DomainAccountInfo oldInfo, newInfo;
    ASSERT_EQ(DomainAccountClient::GetInstance().UpdateAccountInfo(oldInfo, newInfo),
        ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    setuid(ROOT_UID);
}

/**
 * @tc.name: DomainAccountClientModuleTest_UpdateAccountInfo_002
 * @tc.desc: UpdateAccountInfo failed for oldAccount not exist.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_UpdateAccountInfo_002, TestSize.Level0)
{
    DomainAccountInfo oldInfo, newInfo;
    ASSERT_EQ(DomainAccountClient::GetInstance().UpdateAccountInfo(oldInfo, newInfo),
        ERR_DOMAIN_ACCOUNT_SERVICE_NOT_DOMAIN_ACCOUNT);
}

/**
 * @tc.name: DomainAccountClientModuleTest_UpdateAccountInfo_003
 * @tc.desc: UpdateAccountInfo failed for newAccount is invaild.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_UpdateAccountInfo_003, TestSize.Level0)
{
    DomainAccountInfo oldInfo(STRING_DOMAIN, STRING_NAME), newInfo(STRING_DOMAIN, STRING_NAME_INVALID);
    auto callback = std::make_shared<MockDomainCreateDomainAccountCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestCreateDomainAccountCallback>(callback);
    EXPECT_CALL(*callback, OnResult(ERR_OK, oldInfo.accountName_, oldInfo.domain_, _)).Times(Exactly(1));
    ASSERT_NE(testCallback, nullptr);
    ErrCode errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, oldInfo, testCallback);
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
    ASSERT_EQ(errCode, ERR_OK);

    newInfo.accountName_ = STRING_NAME_INVALID;
    ASSERT_EQ(InnerDomainAccountManager::GetInstance().UpdateAccountInfo(oldInfo, newInfo), INVALID_CODE);

    int32_t userId = -1;
    errCode = OsAccountManager::GetOsAccountLocalIdFromDomain(oldInfo, userId);
    EXPECT_EQ(errCode, ERR_OK);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId), ERR_OK);
}

/**
 * @tc.name: DomainAccountClientModuleTest_UpdateAccountInfo_004
 * @tc.desc: UpdateAccountInfo failed for newAccount already exists.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_UpdateAccountInfo_004, TestSize.Level0)
{
    DomainAccountInfo oldInfo(STRING_DOMAIN, STRING_NAME);
    auto callback = std::make_shared<MockDomainCreateDomainAccountCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestCreateDomainAccountCallback>(callback);
    EXPECT_CALL(*callback, OnResult(ERR_OK, oldInfo.accountName_, oldInfo.domain_, _)).Times(Exactly(1));
    ASSERT_NE(testCallback, nullptr);
    ErrCode errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, oldInfo, testCallback);
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
    ASSERT_EQ(errCode, ERR_OK);

    ASSERT_EQ(InnerDomainAccountManager::GetInstance().UpdateAccountInfo(oldInfo, oldInfo),
        ERR_OSACCOUNT_SERVICE_INNER_DOMAIN_ALREADY_BIND_ERROR);

    int32_t userId = -1;
    errCode = OsAccountManager::GetOsAccountLocalIdFromDomain(oldInfo, userId);
    EXPECT_EQ(errCode, ERR_OK);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(userId), ERR_OK);
}

/**
 * @tc.name: DomainAccountClientModuleTest_UpdateAccountInfo_005
 * @tc.desc: UpdateAccountInfo success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_UpdateAccountInfo_005, TestSize.Level0)
{
    DomainAccountInfo oldInfo(STRING_DOMAIN, STRING_NAME), newInfo(STRING_DOMAIN, STRING_NAME_NEW);
    auto callback = std::make_shared<MockDomainCreateDomainAccountCallback>();
    ASSERT_NE(callback, nullptr);
    auto testCallback = std::make_shared<TestCreateDomainAccountCallback>(callback);
    EXPECT_CALL(*callback, OnResult(ERR_OK, oldInfo.accountName_, oldInfo.domain_, _)).Times(Exactly(1));
    ASSERT_NE(testCallback, nullptr);
    ErrCode errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, oldInfo, testCallback);
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
    ASSERT_EQ(errCode, ERR_OK);
    int32_t oldUserId = -1;
    errCode = OsAccountManager::GetOsAccountLocalIdFromDomain(oldInfo, oldUserId);
    ASSERT_EQ(errCode, ERR_OK);
    ASSERT_EQ(InnerDomainAccountManager::GetInstance().UpdateAccountInfo(oldInfo, newInfo), ERR_OK);

    int32_t newUserId = -1;
    errCode = OsAccountManager::GetOsAccountLocalIdFromDomain(newInfo, newUserId);
    EXPECT_EQ(errCode, ERR_OK);
    EXPECT_EQ(oldUserId, newUserId);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(oldUserId), ERR_OK);
}

/**
 * @tc.name: DomainAccountClientModuleTest_UpdateAccountInfo_006
 * @tc.desc: UpdateAccountInfo failed with plugin not surport.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_UpdateAccountInfo_006, TestSize.Level0)
{
    DomainAccountClient::GetInstance().UnregisterPlugin();
    DomainAccountInfo oldInfo(STRING_DOMAIN, STRING_NAME), newInfo(STRING_DOMAIN, STRING_NAME_NEW);
    EXPECT_EQ(DomainAccountClient::GetInstance().UpdateAccountInfo(oldInfo, newInfo),
        ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST);
}

/**
 * @tc.name: DomainAccountClientModuleTest_UpdateAccountInfo_007
 * @tc.desc: UpdateAccountInfo failed with plugin not surport.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountClientModuleTest, DomainAccountClientModuleTest_UpdateAccountInfo_007, TestSize.Level0)
{
    DomainAccountClient::GetInstance().UnregisterPlugin();
    DomainAccountInfo oldInfo(STRING_DOMAIN, STRING_NAME), newInfo(STRING_DOMAIN, STRING_NAME_NEW);
    EXPECT_EQ(DomainAccountClient::GetInstance().UpdateAccountInfo(oldInfo, newInfo),
        ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST);
}
