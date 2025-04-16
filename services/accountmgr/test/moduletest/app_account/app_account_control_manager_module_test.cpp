/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "account_log_wrapper.h"
#include "app_account_constants.h"
#define private public
#include "app_account_control_manager.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string STRING_NAME = "name";
const std::string STRING_NAME_BACK = "end";
const std::string STRING_EXTRA_INFO = "extra_info";
const std::string STRING_OWNER = "com.example.owner";
const std::string AUTHORIZED_APP = "authorizedApp";
const std::string BUNDLE_NAME = "bundlename";

const std::size_t ACCOUNT_MAX_SIZE = 1000;

constexpr std::int32_t UID = 10000;
}  // namespace

class AppAccountControlManagerModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void AppAccountControlManagerModuleTest::SetUpTestCase(void)
{}

void AppAccountControlManagerModuleTest::TearDownTestCase(void)
{
    GTEST_LOG_(INFO) << "TearDownTestCase enter";
}

void AppAccountControlManagerModuleTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void AppAccountControlManagerModuleTest::TearDown(void)
{}

/**
 * @tc.name: AppAccountControlManager_AccountMaxSize_0100
 * @tc.desc: Check account max size with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleTest, AppAccountControlManager_AccountMaxSize_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountControlManager_AccountMaxSize_0100");
    EXPECT_EQ(AppAccountControlManager::GetInstance().ACCOUNT_MAX_SIZE, ACCOUNT_MAX_SIZE);
}

/**
 * @tc.name: AppAccountControlManager_AccountMaxSize_0200
 * @tc.desc: Check account max size with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleTest, AppAccountControlManager_AccountMaxSize_0200, TestSize.Level1)
{
    ErrCode result;
    AppAccountInfo appAccountInfo(STRING_NAME, STRING_OWNER+"max");
    result = AppAccountControlManager::GetInstance().AddAccount(
        STRING_NAME, STRING_EXTRA_INFO, UID, STRING_OWNER+"max", appAccountInfo);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_ACCOUNT_MAX_SIZE);
}

/**
 * @tc.name: AppAccountControlManager_dataStoragePtrIsNull_0100
 * @tc.desc: dataStoragePtrIsNull test app account control manager dataStoragePtr is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountControlManagerModuleTest, AppAccountControlManager_dataStoragePtrIsNull_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountControlManager_RemoveAuthorizedAccountFromDataStorage_0100");
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = nullptr;
    AppAccountInfo appAccountInfo;
    ErrCode result =
        AppAccountControlManager::GetInstance().RemoveAuthorizedAccountFromDataStorage(
            AUTHORIZED_APP, appAccountInfo, dataStoragePtr);
    ASSERT_EQ(result, ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR);

    result = AppAccountControlManager::GetInstance().SaveAuthorizedAccountIntoDataStorage(
        AUTHORIZED_APP, appAccountInfo, dataStoragePtr);
    ASSERT_EQ(result, ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR);

    result = AppAccountControlManager::GetInstance().RemoveAuthorizedAccount(
        BUNDLE_NAME, appAccountInfo, dataStoragePtr, UID);
    ASSERT_EQ(result, ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR);

    result = AppAccountControlManager::GetInstance().SaveAuthorizedAccount(
        BUNDLE_NAME, appAccountInfo, dataStoragePtr, UID);
    ASSERT_EQ(result, ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR);

    result = AppAccountControlManager::GetInstance().DeleteAccountInfoFromDataStorage(
        appAccountInfo, dataStoragePtr, UID);
    ASSERT_EQ(result, ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR);

    result = AppAccountControlManager::GetInstance().SaveAccountInfoIntoDataStorage(
        appAccountInfo, dataStoragePtr, UID);
    ASSERT_EQ(result, ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR);

    result = AppAccountControlManager::GetInstance().AddAccountInfoIntoDataStorage(
        appAccountInfo, dataStoragePtr, UID);
    ASSERT_EQ(result, ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR);

    result = AppAccountControlManager::GetInstance().GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    ASSERT_EQ(result, ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR);

    std::vector<AppAccountInfo> appAccounts;
    result = AppAccountControlManager::GetInstance().GetAllAccessibleAccountsFromDataStorage(
        appAccounts, BUNDLE_NAME, dataStoragePtr, 0);
    ASSERT_EQ(result, ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccountControlManager_NeedSyncDataStorage_0100
 * @tc.desc: NeedSyncDataStorage abnormal branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountControlManagerModuleTest, AppAccountControlManager_NeedSyncDataStorage_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountControlManager_GNeedSyncDataStorage_0100");
    AppAccountInfo appAccountInfo;
    bool syncEnable = false;
    appAccountInfo.SetSyncEnable(syncEnable);
    syncEnable = true;
    appAccountInfo.GetSyncEnable(syncEnable);
    ASSERT_EQ(syncEnable, false);
    bool result = AppAccountControlManager::GetInstance().NeedSyncDataStorage(appAccountInfo);
    ASSERT_EQ(result, false);
}

/**
 * @tc.name: AppAccountControlManager_GetAllOAuthTokens_0100
 * @tc.desc: GetAllOAuthTokens abnormal branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountControlManagerModuleTest, AppAccountControlManager_GetAllOAuthTokens_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountControlManager_GetAllOAuthTokens_0100");
    AuthenticatorSessionRequest request;
    request.name = STRING_NAME;
    request.owner = STRING_OWNER;
    request.callerBundleName = BUNDLE_NAME;
    request.appIndex = 0;
    request.callerUid = 0;
    std::vector<OAuthTokenInfo> tokenInfos;
    AppAccountInfo appAccountInfo(request.name, request.owner);
    std::string authTypeOne = "test_authType1";
    std::string authTokenOne = "test_authToken1";
    std::string authTypeTwo = "test_authType2";
    std::string authTokenTwo = "test_authToken2";
    std::string authTypeThree = "test_authType3";
    std::string authTokenThree = "";
    appAccountInfo.SetOAuthToken(authTypeOne, authTokenOne);
    appAccountInfo.SetOAuthToken(authTypeTwo, authTokenTwo);
    appAccountInfo.SetOAuthToken(authTypeThree, authTokenThree);
    appAccountInfo.SetOAuthTokenVisibility(authTypeOne, BUNDLE_NAME, true, Constants::API_VERSION8);
    appAccountInfo.SetSyncEnable(true);
    bool isSyncEnable = false;
    appAccountInfo.GetSyncEnable(isSyncEnable);
    ASSERT_NE(isSyncEnable, false);
    auto dataStoragePtr = AppAccountControlManager::GetInstance().GetDataStorage(request.callerUid, false);
    ASSERT_NE(dataStoragePtr, nullptr);
    ErrCode result = AppAccountControlManager::GetInstance().AddAccountInfoIntoDataStorage(
        appAccountInfo, dataStoragePtr, request.callerUid);
    ASSERT_EQ(result, ERR_OK);
    result = AppAccountControlManager::GetInstance().GetAllOAuthTokens(request, tokenInfos);
    ASSERT_EQ(result, ERR_OK);
    EXPECT_EQ(tokenInfos.size(), 1);
}

#ifndef SQLITE_DLCLOSE_ENABLE
/**
 * @tc.name: AppAccountControlManager_MoveData_0100
 * @tc.desc: MoveData abnormal branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountControlManagerModuleTest, AppAccountControlManager_MoveData_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountControlManager_MoveData_0100");
    AppAccountControlManager::GetInstance().migratedAccounts_.insert(111);
    EXPECT_EQ(AppAccountControlManager::GetInstance().migratedAccounts_.empty(), false);
    AppAccountControlManager::GetInstance().MoveData();
    EXPECT_EQ(AppAccountControlManager::GetInstance().migratedAccounts_.empty(), true);
    AppAccountControlManager::GetInstance().MoveData();
}
#endif // SQLITE_DLCLOSE_ENABLE

/**
 * @tc.name: AppAccountControlManager_DeleteOAuthToken_0100
 * @tc.desc: DeleteOAuthToken abnormal branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountControlManagerModuleTest, AppAccountControlManager_DeleteOAuthToken_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountControlManager_DeleteOAuthToken_0100");
    AuthenticatorSessionRequest request = {
        .name = "name",
        .owner = "com.example.ownermax"
    };
    
    ErrCode result = AppAccountControlManager::GetInstance().DeleteOAuthToken(request, 8);
    EXPECT_EQ(ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST, result);
}

/**
 * @tc.name: AppAccountControlManager_DeleteOAuthToken_0200
 * @tc.desc: DeleteOAuthToken abnormal branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountControlManagerModuleTest, AppAccountControlManager_DeleteOAuthToken_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountControlManager_DeleteOAuthToken_0200");
    AuthenticatorSessionRequest request = {
        .name = "invalidAppName",
    };
    ErrCode result = AppAccountControlManager::GetInstance().DeleteOAuthToken(request, 8);
    EXPECT_EQ(ERR_OK, result);
}

/**
 * @tc.name: AppAccountControlManager_DeleteOAuthToken_0300
 * @tc.desc: DeleteOAuthToken abnormal branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountControlManagerModuleTest, AppAccountControlManager_DeleteOAuthToken_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountControlManager_DeleteOAuthToken_0300");
    AuthenticatorSessionRequest request = {
        .name = "invalidAppName",
    };
    ErrCode result = AppAccountControlManager::GetInstance().DeleteOAuthToken(request, 11);
    EXPECT_EQ(ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST, result);
}

/**
 * @tc.name: AppAccountControlManager_DeleteOAuthToken_0400
 * @tc.desc: DeleteOAuthToken abnormal branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountControlManagerModuleTest, AppAccountControlManager_DeleteOAuthToken_0400, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountControlManager_DeleteOAuthToken_0400");
    AuthenticatorSessionRequest request = {
        .name = "invalidAppName",
        .callerBundleName = "invalidcallerBundleName",
        .authType = "invalidauthType"
    };
    ErrCode result = AppAccountControlManager::GetInstance().DeleteOAuthToken(request, 10);
    EXPECT_EQ(ERR_ACCOUNT_COMMON_PERMISSION_DENIED, result);
}

/**
 * @tc.name: AppAccountControlManager_GetAllAccounts_0100
 * @tc.desc: GetAllAccounts GetAccountInfoById failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountControlManagerModuleTest, AppAccountControlManager_GetAllAccounts_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountControlManager_GetAllAccounts_0100");
    uid_t tddUid = getuid();
    setuid(20000000);
    std::string owner = "com.example.ownermax";
    std::vector<AppAccountInfo> appAccounts;
    uid_t uid = 12345;
    std::string bundleName = "name";
    uint32_t appIndex = 0;
    ErrCode result = AppAccountControlManager::GetInstance().GetAllAccounts(
        owner, appAccounts, uid, bundleName, appIndex);
    EXPECT_EQ(ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID, result);
    setuid(tddUid);
}

/**
 * @tc.name: AppAccountControlManager_GetAllAccounts_0200
 * @tc.desc: GetAllAccounts GetAccountInfoById ok, appAccountInfo.GetOwner() == owner failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountControlManagerModuleTest, AppAccountControlManager_GetAllAccounts_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountControlManager_GetAllAccounts_0200");
    uid_t tddUid = getuid();
    setuid(20000000);
    std::string owner = "owner";
    std::vector<AppAccountInfo> appAccounts;
    uid_t uid = 12345;
    std::string bundleName = "bundleName";
    uint32_t appIndex = 0;
    ErrCode result = AppAccountControlManager::GetInstance().GetAllAccounts(
        owner, appAccounts, uid, bundleName, appIndex);
    EXPECT_EQ(ERR_OK, result);
    setuid(tddUid);
}
