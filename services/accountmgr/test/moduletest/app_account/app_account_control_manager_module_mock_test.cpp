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
#include <thread>
#include "account_log_wrapper.h"
#include "account_data_storage.h"
#include "app_account_constants.h"
#include "app_account_control_manager.h"
#include "app_account_info.h"
#include "app_account_info_error.h"

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

const std::string STRING_KEY = "key";
const std::string STRING_VALUE = "value";

constexpr std::int32_t UID = 10000;
}  // namespace

class AppAccountControlManagerModuleMockTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void AppAccountControlManagerModuleMockTest::SetUpTestCase(void)
{}

void AppAccountControlManagerModuleMockTest::TearDownTestCase(void)
{
    GTEST_LOG_(INFO) << "TearDownTestCase enter";
}

void AppAccountControlManagerModuleMockTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void AppAccountControlManagerModuleMockTest::TearDown(void)
{}

/**
 * @tc.name: CreateAccount001
 * @tc.desc: Func CreateAccount with InitCustomData error.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleMockTest, CreateAccount001, TestSize.Level1)
{
    CreateAccountOptions options;
    AppAccountInfo appAccountInfo(STRING_NAME, STRING_OWNER + "max");
    ErrCode errCode = AppAccountControlManager::GetInstance().CreateAccount(
        STRING_NAME, options, 0, BUNDLE_NAME, appAccountInfo);
    EXPECT_EQ(errCode, ERR_APPACCOUNT_SERVICE_SET_ASSOCIATED_DATA);
}

/**
 * @tc.name: CreateAccount002
 * @tc.desc: Func CreateAccount with AddAccountInfoIntoDataStorage error.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleMockTest, CreateAccount002, TestSize.Level1)
{
    g_accountDataStorageErrType = ERR_ACCOUNTDATASTORAGE_LOADDATA;
    CreateAccountOptions options;
    options.customData.emplace(STRING_NAME, STRING_OWNER);
    AppAccountInfo appAccountInfo(STRING_NAME, STRING_OWNER + "max");
    ErrCode errCode = AppAccountControlManager::GetInstance().CreateAccount(
        STRING_NAME, options, 0, BUNDLE_NAME, appAccountInfo);
    EXPECT_EQ(errCode, ERR_ACCOUNTDATASTORAGE_FAILED);
}

/**
 * @tc.name: DeleteAccount001
 * @tc.desc: Func DeleteAccount with StartDbTransaction error.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleMockTest, DeleteAccount001, TestSize.Level1)
{
    g_accountDataStorageErrType = ERR_ACCOUNTDATASTORAGE_STARTDB;
    AppAccountInfo appAccountInfo("0", STRING_OWNER + "max");
    ErrCode errCode = AppAccountControlManager::GetInstance().DeleteAccount(
        "0", 0, BUNDLE_NAME, appAccountInfo);
    EXPECT_EQ(errCode, ERR_ACCOUNTDATASTORAGE_FAILED);
}

/**
 * @tc.name: DeleteAccount002
 * @tc.desc: Func DeleteAccount with DeleteAccountInfoFromDataStorage error.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleMockTest, DeleteAccount002, TestSize.Level1)
{
    g_accountDataStorageErrType = 0;
    AppAccountInfo appAccountInfo(STRING_NAME, STRING_OWNER + "max");
    ErrCode errCode = AppAccountControlManager::GetInstance().DeleteAccount(
        STRING_NAME, 0, BUNDLE_NAME, appAccountInfo);
    EXPECT_EQ(errCode, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
}

/**
 * @tc.name: DeleteAccount003
 * @tc.desc: Func DeleteAccount with DeleteAccountInfoFromDataStorage error.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleMockTest, DeleteAccount003, TestSize.Level1)
{
    g_accountDataStorageErrType = ERR_ACCOUNTDATASTORAGE_PUTVALUEKVSTORE;
    AppAccountInfo appAccountInfo("0", STRING_OWNER + "max");
    appAccountInfo.EnableAppAccess(AUTHORIZED_APP);
    ErrCode errCode = AppAccountControlManager::GetInstance().DeleteAccount(
        "0", 0, BUNDLE_NAME, appAccountInfo);
    EXPECT_EQ(errCode, ERR_ACCOUNTDATASTORAGE_FAILED);
}

/**
 * @tc.name: DeleteAccount004
 * @tc.desc: Func DeleteAccount with CommitDbTransaction error.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleMockTest, DeleteAccount004, TestSize.Level1)
{
    g_accountDataStorageErrType = ERR_ACCOUNTDATASTORAGE_COMMITDB;
    AppAccountInfo appAccountInfo("0", STRING_OWNER + "max");
    ErrCode errCode = AppAccountControlManager::GetInstance().DeleteAccount(
        "0", 0, BUNDLE_NAME, appAccountInfo);
    EXPECT_EQ(errCode, ERR_ACCOUNTDATASTORAGE_FAILED);
}

/**
 * @tc.name: SetAccountExtraInfo004
 * @tc.desc: Func SetAccountExtraInfo with SaveAccountInfoIntoDataStorage error.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleMockTest, SetAccountExtraInfo004, TestSize.Level1)
{
    g_accountDataStorageErrType = ERR_ACCOUNTDATASTORAGE_SAVEINFO;
    AppAccountInfo appAccountInfo("0", STRING_OWNER + "max");
    ErrCode errCode = AppAccountControlManager::GetInstance().SetAccountExtraInfo(
        STRING_NAME, STRING_EXTRA_INFO, 0, BUNDLE_NAME, appAccountInfo);
    EXPECT_EQ(errCode, ERR_ACCOUNTDATASTORAGE_FAILED);
}

/**
 * @tc.name: EnableAppAccess001
 * @tc.desc: Func EnableAppAccess with StartDbTransaction error.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleMockTest, EnableAppAccess001, TestSize.Level1)
{
    g_accountDataStorageErrType = ERR_ACCOUNTDATASTORAGE_STARTDB;
    AppAccountInfo appAccountInfo("0", STRING_OWNER + "max");
    AppAccountCallingInfo appAccountCallingInfo;
    appAccountCallingInfo.callingUid = UID;
    appAccountCallingInfo.bundleName = STRING_OWNER + "max";
    ErrCode errCode = AppAccountControlManager::GetInstance().EnableAppAccess(
        STRING_NAME, STRING_EXTRA_INFO, appAccountCallingInfo, appAccountInfo);
    EXPECT_EQ(errCode, ERR_ACCOUNTDATASTORAGE_FAILED);
}

/**
 * @tc.name: EnableAppAccess002
 * @tc.desc: Func EnableAppAccess with SaveAccountInfoIntoDataStorage error.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleMockTest, EnableAppAccess002, TestSize.Level1)
{
    g_accountDataStorageErrType = ERR_ACCOUNTDATASTORAGE_SAVEINFO;
    AppAccountInfo appAccountInfo("0", STRING_OWNER + "max");
    AppAccountCallingInfo appAccountCallingInfo;
    appAccountCallingInfo.callingUid = UID;
    appAccountCallingInfo.bundleName = STRING_OWNER + "max";
    ErrCode errCode = AppAccountControlManager::GetInstance().EnableAppAccess(
        STRING_NAME, STRING_EXTRA_INFO, appAccountCallingInfo, appAccountInfo);
    EXPECT_EQ(errCode, ERR_ACCOUNTDATASTORAGE_FAILED);
}

/**
 * @tc.name: EnableAppAccess003
 * @tc.desc: Func EnableAppAccess with SaveAuthorizedAccount error.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleMockTest, EnableAppAccess003, TestSize.Level1)
{
    g_accountDataStorageErrType = ERR_ACCOUNTDATASTORAGE_PUTVALUEKVSTORE;
    AppAccountInfo appAccountInfo("0", STRING_OWNER + "max");
    AppAccountCallingInfo appAccountCallingInfo;
    appAccountCallingInfo.callingUid = UID;
    appAccountCallingInfo.bundleName = STRING_OWNER + "max";
    ErrCode errCode = AppAccountControlManager::GetInstance().EnableAppAccess(
        STRING_NAME, STRING_EXTRA_INFO, appAccountCallingInfo, appAccountInfo);
    EXPECT_EQ(errCode, ERR_ACCOUNTDATASTORAGE_FAILED);
}

/**
 * @tc.name: EnableAppAccess004
 * @tc.desc: Func EnableAppAccess with CommitDbTransaction error.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleMockTest, EnableAppAccess004, TestSize.Level1)
{
    g_accountDataStorageErrType = ERR_ACCOUNTDATASTORAGE_COMMITDB;
    AppAccountInfo appAccountInfo("0", STRING_OWNER + "max");
    AppAccountCallingInfo appAccountCallingInfo;
    appAccountCallingInfo.callingUid = UID;
    appAccountCallingInfo.bundleName = STRING_OWNER + "max";
    ErrCode errCode = AppAccountControlManager::GetInstance().EnableAppAccess(
        STRING_NAME, STRING_EXTRA_INFO, appAccountCallingInfo, appAccountInfo);
    EXPECT_EQ(errCode, ERR_ACCOUNTDATASTORAGE_FAILED);
}

/**
 * @tc.name: DisableAppAccess001
 * @tc.desc: Func DisableAppAccess with StartDbTransaction error.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleMockTest, DisableAppAccess001, TestSize.Level1)
{
    g_accountDataStorageErrType = ERR_ACCOUNTDATASTORAGE_STARTDB;
    AppAccountInfo appAccountInfo("0", STRING_OWNER + "max");
    AppAccountCallingInfo appAccountCallingInfo;
    appAccountCallingInfo.callingUid = UID;
    appAccountCallingInfo.bundleName = STRING_OWNER + "max";
    ErrCode errCode = AppAccountControlManager::GetInstance().DisableAppAccess(
        STRING_NAME, STRING_OWNER, appAccountCallingInfo, appAccountInfo);
    EXPECT_EQ(errCode, ERR_ACCOUNTDATASTORAGE_FAILED);
}

/**
 * @tc.name: DisableAppAccess002
 * @tc.desc: Func DisableAppAccess with SaveAccountInfoIntoDataStorage error.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleMockTest, DisableAppAccess002, TestSize.Level1)
{
    g_accountDataStorageErrType = ERR_ACCOUNTDATASTORAGE_SAVEINFO;
    AppAccountInfo appAccountInfo("0", STRING_OWNER + "max");
    AppAccountCallingInfo appAccountCallingInfo;
    appAccountCallingInfo.callingUid = UID;
    appAccountCallingInfo.bundleName = STRING_OWNER + "max";
    ErrCode errCode = AppAccountControlManager::GetInstance().DisableAppAccess(
        STRING_NAME, STRING_OWNER, appAccountCallingInfo, appAccountInfo);
    EXPECT_EQ(errCode, ERR_ACCOUNTDATASTORAGE_FAILED);
}

/**
 * @tc.name: DisableAppAccess003
 * @tc.desc: Func DisableAppAccess with RemoveAuthorizedAccount error.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleMockTest, DisableAppAccess003, TestSize.Level1)
{
    g_accountDataStorageErrType = ERR_ACCOUNTDATASTORAGE_PUTVALUEKVSTORE;
    AppAccountInfo appAccountInfo("0", STRING_OWNER + "max");
    AppAccountCallingInfo appAccountCallingInfo;
    appAccountCallingInfo.callingUid = UID;
    appAccountCallingInfo.bundleName = STRING_OWNER + "max";
    ErrCode errCode = AppAccountControlManager::GetInstance().DisableAppAccess(
        STRING_NAME, STRING_OWNER, appAccountCallingInfo, appAccountInfo);
    EXPECT_EQ(errCode, ERR_ACCOUNTDATASTORAGE_FAILED);
}

/**
 * @tc.name: DisableAppAccess004
 * @tc.desc: Func DisableAppAccess with CommitDbTransaction error.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleMockTest, DisableAppAccess004, TestSize.Level1)
{
    g_accountDataStorageErrType = ERR_ACCOUNTDATASTORAGE_COMMITDB;
    AppAccountInfo appAccountInfo("0", STRING_OWNER + "max");
    AppAccountCallingInfo appAccountCallingInfo;
    appAccountCallingInfo.callingUid = UID;
    appAccountCallingInfo.bundleName = STRING_OWNER + "max";
    ErrCode errCode = AppAccountControlManager::GetInstance().DisableAppAccess(
        STRING_NAME, STRING_OWNER, appAccountCallingInfo, appAccountInfo);
    EXPECT_EQ(errCode, ERR_ACCOUNTDATASTORAGE_FAILED);
}

/**
 * @tc.name: CheckAppAccountSyncEnable001
 * @tc.desc: Func CheckAppAccountSyncEnable with GetAccountInfoFromDataStorage error.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleMockTest, CheckAppAccountSyncEnable001, TestSize.Level1)
{
    g_accountDataStorageErrType = 0;
    bool syncEnable = true;
    ErrCode errCode = AppAccountControlManager::GetInstance().CheckAppAccountSyncEnable(
        STRING_NAME, syncEnable, 0, STRING_OWNER + "max", 0);
    EXPECT_EQ(errCode, ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID);
}

/**
 * @tc.name: SetAppAccountSyncEnable001
 * @tc.desc: Func SetAppAccountSyncEnable with SaveAccountInfoIntoDataStorage error.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleMockTest, SetAppAccountSyncEnable001, TestSize.Level1)
{
    g_accountDataStorageErrType = ERR_ACCOUNTDATASTORAGE_SAVEINFO;
    bool syncEnable = true;
    AppAccountInfo appAccountInfo("0", STRING_OWNER + "max");
    ErrCode errCode = AppAccountControlManager::GetInstance().SetAppAccountSyncEnable(
        STRING_NAME, syncEnable, 0, BUNDLE_NAME, appAccountInfo);
    EXPECT_EQ(errCode, ERR_ACCOUNTDATASTORAGE_FAILED);
}

/**
 * @tc.name: SetAssociatedData001
 * @tc.desc: Func SetAssociatedData with appAccountInfo.SetAssociatedData error.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleMockTest, SetAssociatedData001, TestSize.Level1)
{
    g_accountDataStorageErrType = 0;
    AppAccountCallingInfo appAccountCallingInfo;
    appAccountCallingInfo.bundleName = STRING_OWNER;
    ErrCode errCode = AppAccountControlManager::GetInstance().SetAssociatedData(
        STRING_NAME, "", "", appAccountCallingInfo);
    EXPECT_EQ(errCode, ERR_ACCOUNTDATASTORAGE_FAILED);
}

/**
 * @tc.name: SetAssociatedData002
 * @tc.desc: Func SetAssociatedData with SaveAccountInfoIntoDataStorage error.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleMockTest, SetAssociatedData002, TestSize.Level1)
{
    g_accountDataStorageErrType = ERR_ACCOUNTDATASTORAGE_SAVEINFO;
    AppAccountCallingInfo appAccountCallingInfo;
    appAccountCallingInfo.bundleName = STRING_OWNER;
    ErrCode errCode = AppAccountControlManager::GetInstance().SetAssociatedData(
        STRING_NAME, STRING_KEY, STRING_VALUE, appAccountCallingInfo);
    EXPECT_EQ(errCode, ERR_ACCOUNTDATASTORAGE_FAILED);
}

/**
 * @tc.name: SetAccountCredential001
 * @tc.desc: Func SetAccountCredential with appAccountInfo.SetAccountCredential error.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleMockTest, SetAccountCredential001, TestSize.Level1)
{
    g_accountDataStorageErrType = 0;
    AppAccountCallingInfo appAccountCallingInfo;
    appAccountCallingInfo.bundleName = STRING_OWNER;
    ErrCode errCode = AppAccountControlManager::GetInstance().SetAccountCredential(
        STRING_NAME, "", "", appAccountCallingInfo);
    EXPECT_EQ(errCode, ERR_ACCOUNTDATASTORAGE_FAILED);
}

/**
 * @tc.name: SetAccountCredential002
 * @tc.desc: Func SetAccountCredential with SaveAccountInfoIntoDataStorage error.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleMockTest, SetAccountCredential002, TestSize.Level1)
{
    g_accountDataStorageErrType = ERR_ACCOUNTDATASTORAGE_SAVEINFO;
    AppAccountCallingInfo appAccountCallingInfo;
    appAccountCallingInfo.bundleName = STRING_OWNER;
    ErrCode errCode = AppAccountControlManager::GetInstance().SetAccountCredential(
        STRING_NAME, STRING_KEY, STRING_VALUE, appAccountCallingInfo);
    EXPECT_EQ(errCode, ERR_ACCOUNTDATASTORAGE_FAILED);
}

/**
 * @tc.name: DeleteAccountCredential001
 * @tc.desc: Func DeleteAccountCredential with SaveAccountInfoIntoDataStorage error.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleMockTest, DeleteAccountCredential001, TestSize.Level1)
{
    g_accountDataStorageErrType = ERR_ACCOUNTDATASTORAGE_SAVEINFO;
    AppAccountCallingInfo appAccountCallingInfo;
    appAccountCallingInfo.bundleName = STRING_OWNER;
    ErrCode errCode = AppAccountControlManager::GetInstance().DeleteAccountCredential(
        STRING_NAME, STRING_KEY, appAccountCallingInfo);
    EXPECT_EQ(errCode, ERR_ACCOUNTDATASTORAGE_FAILED);
}

/**
 * @tc.name: GetOAuthToken001
 * @tc.desc: Func GetOAuthToken with appAccountInfo.CheckOAuthTokenVisibility error.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleMockTest, GetOAuthToken001, TestSize.Level1)
{
    g_accountDataStorageErrType = 0;
    AuthenticatorSessionRequest request;
    request.name = STRING_NAME;
    request.owner = STRING_OWNER;
    request.callerBundleName = BUNDLE_NAME;
    request.appIndex = 0;
    request.callerUid = 0;

    std::string token = "";
    uint32_t apiVersion = 0;
    ErrCode errCode = AppAccountControlManager::GetInstance().GetOAuthToken(
        request, token, apiVersion);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
}

/**
 * @tc.name: GetOAuthToken002
 * @tc.desc: Func GetOAuthToken with appAccountInfo.CheckOAuthTokenVisibility error.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleMockTest, GetOAuthToken002, TestSize.Level1)
{
    g_accountDataStorageErrType = 0;
    AuthenticatorSessionRequest request;
    request.name = STRING_NAME;
    request.owner = STRING_OWNER;
    request.callerBundleName = BUNDLE_NAME;
    request.appIndex = 0;
    request.callerUid = 0;

    std::string token = "";
    uint32_t apiVersion = 1;
    ErrCode errCode = AppAccountControlManager::GetInstance().GetOAuthToken(
        request, token, apiVersion);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
}

/**
 * @tc.name: SetOAuthToken001
 * @tc.desc: Func SetOAuthToken with appAccountInfo.SetOAuthToken error.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleMockTest, SetOAuthToken001, TestSize.Level1)
{
    g_accountDataStorageErrType = 0;
    AuthenticatorSessionRequest request;
    request.name = STRING_NAME;
    request.owner = STRING_OWNER;
    request.callerBundleName = BUNDLE_NAME;
    request.appIndex = 0;
    request.callerUid = 0;
    request.authType = "";

    ErrCode errCode = AppAccountControlManager::GetInstance().SetOAuthToken(request);
    EXPECT_EQ(errCode, ERR_ACCOUNTDATASTORAGE_FAILED);
}

/**
 * @tc.name: SetOAuthToken002
 * @tc.desc: Func SetOAuthToken with SaveAccountInfoIntoDataStorage error.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleMockTest, SetOAuthToken002, TestSize.Level1)
{
    g_accountDataStorageErrType = ERR_ACCOUNTDATASTORAGE_SAVEINFO;
    AuthenticatorSessionRequest request;
    request.name = STRING_NAME;
    request.owner = STRING_OWNER;
    request.callerBundleName = BUNDLE_NAME;
    request.appIndex = 0;
    request.callerUid = 0;
    request.authType = "type";

    ErrCode errCode = AppAccountControlManager::GetInstance().SetOAuthToken(request);
    EXPECT_EQ(errCode, ERR_ACCOUNTDATASTORAGE_FAILED);
}

/**
 * @tc.name: DeleteOAuthToken001
 * @tc.desc: Func DeleteOAuthToken with appAccountInfo.CheckOAuthTokenVisibility error.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleMockTest, DeleteOAuthToken001, TestSize.Level1)
{
    g_accountDataStorageErrType = 0;
    AuthenticatorSessionRequest request;
    request.name = STRING_NAME;
    request.owner = STRING_OWNER;
    request.callerBundleName = BUNDLE_NAME;
    request.appIndex = 0;
    request.callerUid = 0;
    uint32_t apiVersion = 1;

    ErrCode errCode = AppAccountControlManager::GetInstance().DeleteOAuthToken(request, apiVersion);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
}

/**
 * @tc.name: DeleteOAuthToken002
 * @tc.desc: Func DeleteOAuthToken with appAccountInfo.DeleteAuthToken error.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleMockTest, DeleteOAuthToken002, TestSize.Level1)
{
    g_accountDataStorageErrType = 0;
    AuthenticatorSessionRequest request;
    request.name = STRING_NAME;
    request.owner = STRING_OWNER;
    request.callerBundleName = BUNDLE_NAME;
    request.appIndex = 0;
    request.callerUid = 0;
    request.authType = "";
    uint32_t apiVersion = 9;

    ErrCode errCode = AppAccountControlManager::GetInstance().DeleteOAuthToken(request, apiVersion);
    EXPECT_EQ(errCode, ERR_ACCOUNTDATASTORAGE_FAILED);
}

/**
 * @tc.name: DeleteOAuthToken003
 * @tc.desc: Func DeleteOAuthToken with appAccountInfo.DeleteOAuthToken error.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleMockTest, DeleteOAuthToken003, TestSize.Level1)
{
    g_accountDataStorageErrType = 0;
    AuthenticatorSessionRequest request;
    request.name = STRING_NAME;
    request.owner = STRING_OWNER;
    request.callerBundleName = BUNDLE_NAME;
    request.appIndex = 0;
    request.callerUid = 0;
    request.authType = "";
    uint32_t apiVersion = 8;

    ErrCode errCode = AppAccountControlManager::GetInstance().DeleteOAuthToken(request, apiVersion);
    EXPECT_EQ(errCode, ERR_OK);
}

/**
 * @tc.name: DeleteOAuthToken004
 * @tc.desc: Func DeleteOAuthToken with SaveAccountInfoIntoDataStorage error.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleMockTest, DeleteOAuthToken004, TestSize.Level1)
{
    g_accountDataStorageErrType = ERR_ACCOUNTDATASTORAGE_SAVEINFO;
    AuthenticatorSessionRequest request;
    request.name = STRING_NAME;
    request.owner = STRING_OWNER;
    request.callerBundleName = BUNDLE_NAME;
    request.appIndex = 0;
    request.callerUid = 0;
    request.authType = "type";
    uint32_t apiVersion = 9;

    ErrCode errCode = AppAccountControlManager::GetInstance().DeleteOAuthToken(request, apiVersion);
    EXPECT_EQ(errCode, ERR_ACCOUNTDATASTORAGE_FAILED);
}

/**
 * @tc.name: SetOAuthTokenVisibility001
 * @tc.desc: Func SetOAuthTokenVisibility with SaveAccountInfoIntoDataStorage error.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleMockTest, SetOAuthTokenVisibility001, TestSize.Level1)
{
    g_accountDataStorageErrType = ERR_ACCOUNTDATASTORAGE_SAVEINFO;
    AuthenticatorSessionRequest request;
    request.name = STRING_NAME;
    request.owner = STRING_OWNER;
    request.callerBundleName = BUNDLE_NAME;
    request.appIndex = 0;
    request.callerUid = 0;
    uint32_t apiVersion = 8;

    ErrCode errCode = AppAccountControlManager::GetInstance().SetOAuthTokenVisibility(request, apiVersion);
    EXPECT_EQ(errCode, ERR_ACCOUNTDATASTORAGE_FAILED);
}

/**
 * @tc.name: GetAllOAuthTokens001
 * @tc.desc: Func GetAllOAuthTokens with appAccountInfo.GetAllOAuthTokens error.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleMockTest, GetAllOAuthTokens001, TestSize.Level1)
{
    g_accountDataStorageErrType = ERR_ACCOUNTDATASTORAGE_SAVEINFO;
    AuthenticatorSessionRequest request;
    request.name = STRING_NAME;
    request.owner = STRING_OWNER;
    request.callerBundleName = BUNDLE_NAME;
    request.appIndex = 0;
    request.callerUid = 0;
    std::vector<OAuthTokenInfo> tokenInfos;

    ErrCode errCode = AppAccountControlManager::GetInstance().GetAllOAuthTokens(request, tokenInfos);
    EXPECT_EQ(errCode, ERR_ACCOUNTDATASTORAGE_FAILED);
}

/**
 * @tc.name: GetAllAccounts001
 * @tc.desc: Func GetAllAccounts with GetAllAccountsFromDataStorage error.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleMockTest, GetAllAccounts001, TestSize.Level1)
{
    g_accountDataStorageErrType = ERR_ACCOUNTDATASTORAGE_LOADDATA;
    const std::string owner = "";
    std::vector<AppAccountInfo> appAccounts;
    const uid_t uid = 0;
    const std::string bundleName = "";
    const uint32_t appIndex = 0;

    ErrCode errCode = AppAccountControlManager::GetInstance().GetAllAccounts(
        owner, appAccounts, uid, bundleName, appIndex);
    EXPECT_EQ(errCode, ERR_ACCOUNTDATASTORAGE_FAILED);
}
