/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "account_log_wrapper.h"
#define private public
#include "app_account_authenticator_callback_stub.h"
#include "app_account_manager_service.h"
#include "app_account_stub.h"
#undef private
#include "parcel.h"
#include "want.h"
using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
DECLARE_INTERFACE_DESCRIPTOR(u"ohos.accountfwk.IAppAccount");
const std::string STRING_NAME = "name";
const int32_t LIMIT_CODE = 42;
const int32_t CLEAR_OAUTH_TOKEN = 29;
const int32_t SUBSCRIBE_ACCOUNT = 33;
const int32_t GET_ALL_ACCESSIBLE_ACCOUNTS = 31;
const int32_t QUERY_ALL_ACCESSIBLE_ACCOUNTS = 32;
const int32_t UNSUBSCRIBE_ACCOUNT = 34;
sptr<AppAccountManagerService> g_servicePtr;
} // namespace

class MockAuthenticatorCallback final : public AccountSA::AppAccountAuthenticatorCallbackStub {
public:
    void OnResult(int32_t resultCode, const AAFwk::Want &result)
    {}
    void OnRequestRedirected(AAFwk::Want &request)
    {}
    void OnRequestContinued()
    {}
};

class AppAccountStubModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AppAccountStubModuleTest::SetUpTestCase(void)
{
    g_servicePtr = new (std::nothrow) AppAccountManagerService();
    ASSERT_NE(g_servicePtr, nullptr);
}

void AppAccountStubModuleTest::TearDownTestCase(void)
{}

void AppAccountStubModuleTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void AppAccountStubModuleTest::TearDown(void)
{}

/**
 * @tc.name: AppAccountStubModuleTest_OnRemoteRequest_001
 * @tc.desc: OnRemoteRequest with invalid code.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_OnRemoteRequest_001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    EXPECT_NE(data.WriteInterfaceToken(GetDescriptor()), false);
    EXPECT_NE(g_servicePtr->OnRemoteRequest(-1, data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_OnRemoteRequest_002
 * @tc.desc: OnRemoteRequest with no interface token.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_OnRemoteRequest_002, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    EXPECT_NE(g_servicePtr->OnRemoteRequest(-1, data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_OnRemoteRequest_003
 * @tc.desc: OnRemoteRequest success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_OnRemoteRequest_003, TestSize.Level0)
{
    for (int code = 0; code <= LIMIT_CODE; code++) {
        MessageParcel data;
        MessageParcel reply;
        MessageOption option;
        EXPECT_NE(data.WriteInterfaceToken(GetDescriptor()), false);
        if ((code == CLEAR_OAUTH_TOKEN) || (code == SUBSCRIBE_ACCOUNT) || (code == UNSUBSCRIBE_ACCOUNT)) {
            EXPECT_NE(g_servicePtr->OnRemoteRequest(
                static_cast<uint32_t>(static_cast<uint32_t>(code)), data, reply, option), ERR_NONE);
        } else {
            EXPECT_EQ(g_servicePtr->OnRemoteRequest(
                static_cast<uint32_t>(static_cast<uint32_t>(code)), data, reply, option), ERR_NONE);
        }
    }
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_001
 * @tc.desc: ProcAddAccount success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_001, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(data.WriteInterfaceToken(GetDescriptor()), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_EQ(g_servicePtr->ProcAddAccount(static_cast<uint32_t>(static_cast<uint32_t>(0)),
        data, reply), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_002
 * @tc.desc: ProcAddAccountImplicitly success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_002, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(data.WriteInterfaceToken(GetDescriptor()), false);
    AAFwk::Want options;
    sptr<IAppAccountAuthenticatorCallback> callback = new (std::nothrow) MockAuthenticatorCallback();
    EXPECT_NE(callback, nullptr);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_NE(data.WriteParcelable(&options), false);
    EXPECT_NE(data.WriteRemoteObject(callback->AsObject()), false);
    EXPECT_EQ(g_servicePtr->ProcAddAccountImplicitly(static_cast<uint32_t>(static_cast<uint32_t>(0)),
        data, reply), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_003
 * @tc.desc: CreateAccount success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_003, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(data.WriteInterfaceToken(GetDescriptor()), false);
    AAFwk::Want options;
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_NE(data.WriteParcelable(&options), false);
    EXPECT_EQ(g_servicePtr->ProcCreateAccount(static_cast<uint32_t>(static_cast<uint32_t>(0)),
        data, reply), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_004
 * @tc.desc: ProcCreateAccountImplicitly success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_004, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(data.WriteInterfaceToken(GetDescriptor()), false);
    AAFwk::Want options;
    sptr<IAppAccountAuthenticatorCallback> callback = new (std::nothrow) MockAuthenticatorCallback();
    EXPECT_NE(callback, nullptr);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_NE(data.WriteParcelable(&options), false);
    EXPECT_NE(data.WriteRemoteObject(callback->AsObject()), false);
    EXPECT_EQ(g_servicePtr->ProcCreateAccountImplicitly(static_cast<uint32_t>(static_cast<uint32_t>(0)),
        data, reply), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_005
 * @tc.desc: ProcDeleteAccount success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_005, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(data.WriteInterfaceToken(GetDescriptor()), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_EQ(g_servicePtr->ProcDeleteAccount(static_cast<uint32_t>(static_cast<uint32_t>(0)),
        data, reply), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_006
 * @tc.desc: ProcGetAccountExtraInfo success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_006, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(data.WriteInterfaceToken(GetDescriptor()), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_EQ(g_servicePtr->ProcGetAccountExtraInfo(static_cast<uint32_t>(static_cast<uint32_t>(0)),
        data, reply), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_007
 * @tc.desc: ProcSetAccountExtraInfo success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_007, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(data.WriteInterfaceToken(GetDescriptor()), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_EQ(g_servicePtr->ProcSetAccountExtraInfo(static_cast<uint32_t>(static_cast<uint32_t>(0)),
        data, reply), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_008
 * @tc.desc: ProcSetAppAccess success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_008, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(data.WriteInterfaceToken(GetDescriptor()), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_EQ(g_servicePtr->ProcSetAppAccess(static_cast<uint32_t>(static_cast<uint32_t>(0)),
        data, reply), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_009
 * @tc.desc: ProcCheckAppAccountSyncEnable success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_009, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(data.WriteInterfaceToken(GetDescriptor()), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_EQ(g_servicePtr->ProcCheckAppAccountSyncEnable(static_cast<uint32_t>(static_cast<uint32_t>(0)),
        data, reply), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_010
 * @tc.desc: ProcSetAppAccountSyncEnable success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_010, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    bool syncEnable = false;
    EXPECT_NE(data.WriteInterfaceToken(GetDescriptor()), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_NE(data.WriteBool(syncEnable), false);
    EXPECT_EQ(g_servicePtr->ProcSetAppAccountSyncEnable(static_cast<uint32_t>(static_cast<uint32_t>(0)),
        data, reply), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_011
 * @tc.desc: ProcGetAssociatedData success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_011, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(data.WriteInterfaceToken(GetDescriptor()), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_EQ(g_servicePtr->ProcGetAssociatedData(static_cast<uint32_t>(static_cast<uint32_t>(0)),
        data, reply), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_012
 * @tc.desc: ProcSetAssociatedData success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_012, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(data.WriteInterfaceToken(GetDescriptor()), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_EQ(g_servicePtr->ProcSetAssociatedData(static_cast<uint32_t>(static_cast<uint32_t>(0)),
        data, reply), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_013
 * @tc.desc: ProcGetAccountCredential success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_013, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(data.WriteInterfaceToken(GetDescriptor()), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_EQ(g_servicePtr->ProcGetAccountCredential(static_cast<uint32_t>(static_cast<uint32_t>(0)),
        data, reply), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_014
 * @tc.desc: ProcGetAccountCredential success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_014, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(data.WriteInterfaceToken(GetDescriptor()), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_EQ(g_servicePtr->ProcSetAccountCredential(static_cast<uint32_t>(static_cast<uint32_t>(0)),
        data, reply), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_015
 * @tc.desc: ProcAuthenticate success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_015, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(data.WriteInterfaceToken(GetDescriptor()), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    AAFwk::Want options;
    sptr<IAppAccountAuthenticatorCallback> callback = new (std::nothrow) MockAuthenticatorCallback();
    EXPECT_NE(callback, nullptr);
    EXPECT_NE(data.WriteParcelable(&options), false);
    EXPECT_NE(data.WriteRemoteObject(callback->AsObject()), false);
    EXPECT_EQ(g_servicePtr->ProcAuthenticate(static_cast<uint32_t>(static_cast<uint32_t>(0)),
        data, reply), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_016
 * @tc.desc: ProcGetAuthToken success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_016, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(data.WriteInterfaceToken(GetDescriptor()), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_EQ(g_servicePtr->ProcGetAuthToken(static_cast<uint32_t>(static_cast<uint32_t>(0)),
        data, reply), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_017
 * @tc.desc: ProcSetOAuthToken success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_017, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(data.WriteInterfaceToken(GetDescriptor()), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_EQ(g_servicePtr->ProcSetOAuthToken(static_cast<uint32_t>(static_cast<uint32_t>(0)),
        data, reply), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_018
 * @tc.desc: ProcDeleteAuthToken success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_018, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(data.WriteInterfaceToken(GetDescriptor()), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_EQ(g_servicePtr->ProcDeleteAuthToken(static_cast<uint32_t>(static_cast<uint32_t>(0)),
        data, reply), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_019
 * @tc.desc: ProcSetAuthTokenVisibility success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_019, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(data.WriteInterfaceToken(GetDescriptor()), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_EQ(g_servicePtr->ProcSetAuthTokenVisibility(static_cast<uint32_t>(static_cast<uint32_t>(0)),
        data, reply), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_020
 * @tc.desc: ProcCheckAuthTokenVisibility success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_020, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(data.WriteInterfaceToken(GetDescriptor()), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_EQ(g_servicePtr->ProcCheckAuthTokenVisibility(static_cast<uint32_t>(static_cast<uint32_t>(0)),
        data, reply), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_021
 * @tc.desc: ProcGetAuthenticatorInfo success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_021, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(data.WriteInterfaceToken(GetDescriptor()), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_EQ(g_servicePtr->ProcGetAuthenticatorInfo(static_cast<uint32_t>(static_cast<uint32_t>(0)),
        data, reply), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_022
 * @tc.desc: ProcGetAllOAuthTokens success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_022, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(data.WriteInterfaceToken(GetDescriptor()), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_EQ(g_servicePtr->ProcGetAllOAuthTokens(static_cast<uint32_t>(static_cast<uint32_t>(0)),
        data, reply), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_023
 * @tc.desc: ProcGetAuthList success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_023, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(data.WriteInterfaceToken(GetDescriptor()), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_EQ(g_servicePtr->ProcGetAuthList(static_cast<uint32_t>(static_cast<uint32_t>(0)),
        data, reply), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_024
 * @tc.desc: ProcGetAuthenticatorCallback success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_024, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(data.WriteInterfaceToken(GetDescriptor()), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_EQ(g_servicePtr->ProcGetAuthenticatorCallback(static_cast<uint32_t>(static_cast<uint32_t>(0)),
        data, reply), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_025
 * @tc.desc: ProcGetAllAccounts success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_025, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(data.WriteInterfaceToken(GetDescriptor()), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_EQ(g_servicePtr->ProcGetAllAccounts(static_cast<uint32_t>(static_cast<uint32_t>(0)),
        data, reply), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_026
 * @tc.desc: ProcGetAllAccessibleAccounts success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_026, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(data.WriteInterfaceToken(GetDescriptor()), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_EQ(g_servicePtr->ProcGetAllAccessibleAccounts(
        static_cast<uint32_t>(static_cast<uint32_t>(GET_ALL_ACCESSIBLE_ACCOUNTS)), data, reply), ERR_NONE);
    EXPECT_EQ(g_servicePtr->ProcGetAllAccessibleAccounts(
        static_cast<uint32_t>(static_cast<uint32_t>(QUERY_ALL_ACCESSIBLE_ACCOUNTS)), data, reply), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_027
 * @tc.desc: ProcCheckAppAccess success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_027, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(data.WriteInterfaceToken(GetDescriptor()), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_EQ(g_servicePtr->ProcCheckAppAccess(static_cast<uint32_t>(static_cast<uint32_t>(0)),
        data, reply), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_028
 * @tc.desc: ProcDeleteAccountCredential success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_028, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(data.WriteInterfaceToken(GetDescriptor()), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_EQ(g_servicePtr->ProcDeleteAccountCredential(static_cast<uint32_t>(static_cast<uint32_t>(0)),
        data, reply), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_029
 * @tc.desc: ProcSelectAccountsByOptions success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_029, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(data.WriteInterfaceToken(GetDescriptor()), false);
    AAFwk::Want options;
    sptr<IAppAccountAuthenticatorCallback> callback = new (std::nothrow) MockAuthenticatorCallback();
    EXPECT_NE(callback, nullptr);
    EXPECT_NE(data.WriteParcelable(&options), false);
    EXPECT_NE(data.WriteRemoteObject(callback->AsObject()), false);
    EXPECT_EQ(g_servicePtr->ProcSelectAccountsByOptions(static_cast<uint32_t>(static_cast<uint32_t>(0)),
        data, reply), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_030
 * @tc.desc: ProcVerifyCredential success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_030, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(data.WriteInterfaceToken(GetDescriptor()), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    AAFwk::Want options;
    sptr<IAppAccountAuthenticatorCallback> callback = new (std::nothrow) MockAuthenticatorCallback();
    EXPECT_NE(callback, nullptr);
    EXPECT_NE(data.WriteParcelable(&options), false);
    EXPECT_NE(data.WriteRemoteObject(callback->AsObject()), false);
    EXPECT_EQ(g_servicePtr->ProcVerifyCredential(static_cast<uint32_t>(static_cast<uint32_t>(0)),
        data, reply), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_031
 * @tc.desc: ProcCheckAccountLabels success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_031, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(data.WriteInterfaceToken(GetDescriptor()), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    std::vector<std::string> labels;
    EXPECT_NE(data.WriteStringVector(labels), false);
    sptr<IAppAccountAuthenticatorCallback> callback = new (std::nothrow) MockAuthenticatorCallback();
    EXPECT_NE(callback, nullptr);
    EXPECT_NE(data.WriteRemoteObject(callback->AsObject()), false);
    EXPECT_EQ(g_servicePtr->ProcCheckAccountLabels(static_cast<uint32_t>(static_cast<uint32_t>(0)),
        data, reply), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_032
 * @tc.desc: ProcSetAuthenticatorProperties success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_032, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(data.WriteInterfaceToken(GetDescriptor()), false);
    EXPECT_NE(data.WriteString(STRING_NAME), false);
    AAFwk::Want options;
    EXPECT_NE(data.WriteParcelable(&options), false);
    sptr<IAppAccountAuthenticatorCallback> callback = new (std::nothrow) MockAuthenticatorCallback();
    EXPECT_NE(callback, nullptr);
    EXPECT_NE(data.WriteRemoteObject(callback->AsObject()), false);
    EXPECT_EQ(g_servicePtr->ProcSetAuthenticatorProperties(static_cast<uint32_t>(static_cast<uint32_t>(0)),
        data, reply), ERR_NONE);
}