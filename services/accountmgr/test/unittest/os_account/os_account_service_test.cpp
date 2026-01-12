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
#include "account_test_common.h"
#include "os_account_constants.h"
#define private public
#include "os_account_manager_service.h"
#include "ipc_skeleton.h"
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
const int TEST_ACCOUNT_ID = 222;
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

    void CreateOsAccountForTest(OsAccountInfo &osAccountInfo)
    {
        osAccountInfo.SetIsCreateCompleted(true);
        osAccountService_->innerManager_.osAccountControl_->InsertOsAccount(osAccountInfo);
    }
};

void OsAccountServiceTest::SetUpTestCase(void)
{
    ASSERT_TRUE(MockTokenId("accountmgr"));
}

void OsAccountServiceTest::TearDownTestCase(void)
{}

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

#ifdef SUPPORT_DOMAIN_ACCOUNTS
ErrCode InnerDomainAccountManager::GetAccountServerConfig(const std::string &accountName,
    const std::string &configId, DomainServerConfig &config)
{
    if (accountName == "fail") {
        return false;
    }
    return true;
}
#endif // SUPPORT_DOMAIN_ACCOUNTS

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

#ifdef SUPPORT_DOMAIN_ACCOUNTS
/*
 * @tc.name: GetServerConfigInfo001
 * @tc.desc: Test GetServerConfigInfo with valid userid.
 * @tc.type: FUNC
 * @tc.require: #I6JV5X
 */
HWTEST_F(OsAccountServiceTest, GetServerConfigInfo001, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    osAccountInfo.SetIsCreateCompleted(false);
    ErrCode errCode = osAccountService_->GetServerConfigInfo(osAccountInfo);
    EXPECT_EQ(errCode, ERR_OK);
    osAccountInfo.SetIsCreateCompleted(true);
    osAccountInfo.SetToBeRemoved(true);
    errCode = osAccountService_->GetServerConfigInfo(osAccountInfo);
    EXPECT_EQ(errCode, ERR_OK);
    osAccountInfo.SetToBeRemoved(false);
    errCode = osAccountService_->GetServerConfigInfo(osAccountInfo);
    EXPECT_EQ(errCode, ERR_OK);
    DomainAccountInfo info;
    info.accountName_ = "test";
    osAccountInfo.SetDomainInfo(info);
    errCode = osAccountService_->GetServerConfigInfo(osAccountInfo);
    EXPECT_EQ(errCode, ERR_OK);
    info.serverConfigId_ = "test";
    osAccountInfo.SetDomainInfo(info);
    EXPECT_EQ(errCode, ERR_OK);
}

/*
 * @tc.name: GetServerConfigInfo001
 * @tc.desc: Test GetServerConfigInfo with valid userid.
 * @tc.type: FUNC
 * @tc.require: #I6JV5X
 */
HWTEST_F(OsAccountServiceTest, GetServerConfigInfo002, TestSize.Level1)
{
    OsAccountInfo accountInfo(TEST_ACCOUNT_ID, "QueryOsAccountInfo001", OsAccountType::NORMAL, 0);
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "fail";
    domainInfo.domain_ = "test.example.com";
    domainInfo.accountId_ = "testid";
    domainInfo.serverConfigId_ = "test";
    accountInfo.SetIsCreateCompleted(true);
    accountInfo.SetDomainInfo(domainInfo);
    OsAccountControlFileManager *controlManager = new (std::nothrow) OsAccountControlFileManager();
    EXPECT_EQ(ERR_OK, controlManager->InsertOsAccount(accountInfo));
    OsAccountInfo info;
    EXPECT_EQ(osAccountService_->QueryOsAccountById(TEST_ACCOUNT_ID, info), ERR_OK);
#if defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
    EXPECT_EQ(osAccountService_->GetOsAccountFromDatabase("os_account_info", TEST_ACCOUNT_ID, info), ERR_OK);
    std::vector<OsAccountInfo> osAccountList;
    EXPECT_EQ(osAccountService_->GetOsAccountListFromDatabase("os_account_info", osAccountList), ERR_OK);
#endif // defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
    domainInfo.accountName_ = "tets";
    accountInfo.SetDomainInfo(domainInfo);
    EXPECT_EQ(ERR_OK, controlManager->UpdateOsAccount(accountInfo));
    EXPECT_EQ(osAccountService_->QueryOsAccountById(TEST_ACCOUNT_ID, info), ERR_OK);
#if defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
    EXPECT_EQ(osAccountService_->GetOsAccountFromDatabase("os_account_info", TEST_ACCOUNT_ID, info), ERR_OK);
    EXPECT_EQ(osAccountService_->GetOsAccountListFromDatabase("os_account_info", osAccountList), ERR_OK);
#endif // defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
    EXPECT_EQ(controlManager->DelOsAccount(TEST_ACCOUNT_ID), ERR_OK);
}
#endif //SUPPORT_DOMAIN_ACCOUNTS
#ifndef SUPPORT_AUTHORIZATION
/**
 * @tc.name: SetOsAccountType001
 * @tc.desc: Test SetOsAccountType with invalid ID parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountServiceTest, SetOsAccountType001, TestSize.Level1)
{
    SetOsAccountTypeOptions options;

    // Test 1: Negative ID - should fail in CheckLocalId
    ErrCode result = osAccountService_->SetOsAccountType(-100,
        static_cast<int32_t>(OsAccountType::NORMAL), options);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);

    // Test 2: ADMIN_LOCAL_ID - should fail in CheckLocalIdRestricted
    result = osAccountService_->SetOsAccountType(Constants::ADMIN_LOCAL_ID,
        static_cast<int32_t>(OsAccountType::NORMAL), options);
    EXPECT_EQ(result, ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR);

    // Test 3: START_USER_ID - should return ERR_ACCOUNT_COMMON_ACCOUNT_IS_RESTRICTED
    result = osAccountService_->SetOsAccountType(Constants::START_USER_ID,
        static_cast<int32_t>(OsAccountType::NORMAL), options);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_ACCOUNT_IS_RESTRICTED);

    // Test 4: Non-existent account ID
    const int32_t nonExistentId = 99999;
    result = osAccountService_->SetOsAccountType(nonExistentId,
        static_cast<int32_t>(OsAccountType::GUEST), options);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: SetOsAccountType002
 * @tc.desc: Test SetOsAccountType with invalid type parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountServiceTest, SetOsAccountType002, TestSize.Level1)
{
    // Create a test account
    OsAccountInfo osAccountInfo(102, "SetTypeTest002", OsAccountType::NORMAL, 0);
    CreateOsAccountForTest(osAccountInfo);
    int32_t localId = osAccountInfo.GetLocalId();

    uint64_t oldToken = IPCSkeleton::GetCallingTokenID();
    uint64_t newToken = 0;
    ASSERT_TRUE(AllocPermission({"ohos.permission.MANAGE_LOCAL_ACCOUNTS"}, newToken, true));

    SetOsAccountTypeOptions options;

    // Test 1: type = END
    ErrCode result = osAccountService_->SetOsAccountType(localId,
        static_cast<int32_t>(OsAccountType::END), options);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);

    // Test 2: type < ADMIN
    result = osAccountService_->SetOsAccountType(localId, -1, options);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);

    // Test 3: type > valid range
    result = osAccountService_->SetOsAccountType(localId, 9999, options);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);

    ASSERT_TRUE(RecoveryPermission(newToken, oldToken));

    // Clean up: remove the test account
    osAccountService_->innerManager_.osAccountControl_->DelOsAccount(localId);
}

/**
 * @tc.name: SetOsAccountType003
 * @tc.desc: Test SetOsAccountType permission checks.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountServiceTest, SetOsAccountType003, TestSize.Level1)
{
    // Create a test account
    OsAccountInfo osAccountInfo(103, "SetTypeTest003", OsAccountType::NORMAL, 0);
    CreateOsAccountForTest(osAccountInfo);
    int32_t localId = osAccountInfo.GetLocalId();

    SetOsAccountTypeOptions options;

    // Test 1: Non-system app
    uint64_t oldToken = IPCSkeleton::GetCallingTokenID();
    uint64_t newToken = 0;
    ASSERT_TRUE(AllocPermission({}, newToken, false));
    ErrCode result = osAccountService_->SetOsAccountType(localId,
        static_cast<int32_t>(OsAccountType::NORMAL), options);
    EXPECT_NE(result, ERR_OK);
    ASSERT_TRUE(RecoveryPermission(newToken, oldToken));

    // Test 2: Missing MANAGE_LOCAL_ACCOUNTS permission
    oldToken = IPCSkeleton::GetCallingTokenID();
    newToken = 0;
    ASSERT_TRUE(AllocPermission({"ohos.permission.GET_LOCAL_ACCOUNTS"}, newToken, true));
    
    // Simulate non-root UID to bypass root check in PermissionCheck
    setuid(TEST_USER_ID * UID_TRANSFORM_DIVISOR);
    result = osAccountService_->SetOsAccountType(localId,
        static_cast<int32_t>(OsAccountType::NORMAL), options);
    setuid(0);

    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    ASSERT_TRUE(RecoveryPermission(newToken, oldToken));

    // Clean up: remove the test account
    osAccountService_->innerManager_.osAccountControl_->DelOsAccount(localId);
}

/**
 * @tc.name: SetOsAccountType004
 * @tc.desc: Test SetOsAccountType with invalid token parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountServiceTest, SetOsAccountType004, TestSize.Level1)
{
    // Create a test account
    OsAccountInfo osAccountInfo(104, "SetTypeTest004", OsAccountType::NORMAL, 0);
    CreateOsAccountForTest(osAccountInfo);
    int32_t localId = osAccountInfo.GetLocalId();

    uint64_t oldToken = IPCSkeleton::GetCallingTokenID();
    uint64_t newToken = 0;
    ASSERT_TRUE(AllocPermission({"ohos.permission.MANAGE_LOCAL_ACCOUNTS"}, newToken, true));

    SetOsAccountTypeOptions options;

    // Test: token is nullopt by default in non-authorization mode
    ErrCode result = osAccountService_->SetOsAccountType(localId,
        static_cast<int32_t>(OsAccountType::NORMAL), options);
    EXPECT_EQ(result, ERR_OK);

    ASSERT_TRUE(RecoveryPermission(newToken, oldToken));

    // Clean up: remove the test account
    osAccountService_->innerManager_.osAccountControl_->DelOsAccount(localId);
}

/**
 * @tc.name: SetOsAccountType005
 * @tc.desc: Test SetOsAccountType normal scenarios.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountServiceTest, SetOsAccountType005, TestSize.Level1)
{
    // Create a NORMAL account
    OsAccountInfo osAccountInfo(105, "SetTypeTest005", OsAccountType::NORMAL, 0);
    CreateOsAccountForTest(osAccountInfo);
    int32_t localId = osAccountInfo.GetLocalId();

    uint64_t oldToken = IPCSkeleton::GetCallingTokenID();
    uint64_t newToken = 0;
    ASSERT_TRUE(AllocPermission({"ohos.permission.MANAGE_LOCAL_ACCOUNTS"}, newToken, true));

    // Test: Set to same type (NORMAL -> NORMAL), should succeed without modification
    SetOsAccountTypeOptions options;
    ErrCode result = osAccountService_->SetOsAccountType(localId,
        static_cast<int32_t>(OsAccountType::NORMAL), options);
    EXPECT_EQ(result, ERR_OK);

    ASSERT_TRUE(RecoveryPermission(newToken, oldToken));

    // Clean up: remove the test account
    osAccountService_->innerManager_.osAccountControl_->DelOsAccount(localId);
}
#endif
}  // namespace AccountSA
}  // namespace OHOS