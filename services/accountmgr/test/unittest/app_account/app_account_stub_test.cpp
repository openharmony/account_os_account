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

#include <cerrno>
#include <gtest/gtest.h>
#include <thread>
#include "account_log_wrapper.h"
#define private public
#include "app_account_authenticator_callback_stub.h"
#include "app_account_event_listener.h"
#include "app_account_manager_service.h"
#include "app_account_stub.h"
#include "app_account_subscriber.h"
#undef private
#include "parcel.h"
#include "want.h"
using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.AccountSA.IAppAccount");
const std::string STRING_NAME = "name";
sptr<AppAccountManagerService> g_servicePtr;
} // namespace

class MockAuthenticatorCallback final : public AccountSA::AppAccountAuthenticatorCallbackStub {
public:
    ErrCode OnResult(int32_t resultCode, const AAFwk::Want &result)
    {
        return ERR_OK;
    }
    ErrCode OnRequestRedirected(const AAFwk::Want &request)
    {
        return ERR_OK;
    }
    ErrCode OnRequestContinued()
    {
        return ERR_OK;
    }
    ErrCode CallbackEnter([[maybe_unused]] uint32_t code)
    {
        return ERR_OK;
    }
    ErrCode CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
    {
        return ERR_OK;
    }
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
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_OnRemoteRequest_001, TestSize.Level3)
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
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_OnRemoteRequest_002, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    EXPECT_NE(g_servicePtr->OnRemoteRequest(-1, data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_001
 * @tc.desc: AddAccount success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_001, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_ADD_ACCOUNT),
        data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_002
 * @tc.desc: AddAccountImplicitly success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_002, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    AAFwk::Want options;
    sptr<IAppAccountAuthenticatorCallback> callback = new (std::nothrow) MockAuthenticatorCallback();
    EXPECT_NE(callback, nullptr);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_NE(data.WriteParcelable(&options), false);
    EXPECT_NE(data.WriteRemoteObject(callback->AsObject()), false);
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_ADD_ACCOUNT_IMPLICITLY),
        data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_003
 * @tc.desc: CreateAccount success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_003, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    CreateAccountOptions options;
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_NE(data.WriteParcelable(&options), false);
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_CREATE_ACCOUNT),
        data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_004
 * @tc.desc: CreateAccountImplicitly success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_004, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    CreateAccountImplicitlyOptions options;
    sptr<IAppAccountAuthenticatorCallback> callback = new (std::nothrow) MockAuthenticatorCallback();
    EXPECT_NE(callback, nullptr);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_NE(data.WriteParcelable(&options), false);
    EXPECT_NE(data.WriteRemoteObject(callback->AsObject()), false);
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(
        IAppAccountIpcCode::COMMAND_CREATE_ACCOUNT_IMPLICITLY), data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_005
 * @tc.desc: DeleteAccount success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_005, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_DELETE_ACCOUNT),
        data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_006
 * @tc.desc: GetAccountExtraInfo success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_006, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_GET_ACCOUNT_EXTRA_INFO),
        data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_007
 * @tc.desc: SetAccountExtraInfo success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_007, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_SET_ACCOUNT_EXTRA_INFO),
        data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_008
 * @tc.desc: SetAppAccess with invalid code.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_008, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_NE(data.WriteInt32(1), false);
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_SET_APP_ACCESS),
        data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_009
 * @tc.desc: CheckAppAccountSyncEnable success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_009, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(
        IAppAccountIpcCode::COMMAND_CHECK_APP_ACCOUNT_SYNC_ENABLE), data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_010
 * @tc.desc: SetAppAccountSyncEnable success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_010, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    bool syncEnable = false;
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_NE(data.WriteBool(syncEnable), false);
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(
        IAppAccountIpcCode::COMMAND_SET_APP_ACCOUNT_SYNC_ENABLE), data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_011
 * @tc.desc: GetAssociatedData success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_011, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_GET_ASSOCIATED_DATA),
        data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_012
 * @tc.desc: SetAssociatedData success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_012, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_SET_ASSOCIATED_DATA),
        data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_013
 * @tc.desc: GetAccountCredential success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_013, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_GET_ACCOUNT_CREDENTIAL),
        data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_014
 * @tc.desc: GetAccountCredential success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_014, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_SET_ACCOUNT_CREDENTIAL),
        data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_015
 * @tc.desc: Authenticate success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_015, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    AppAccountStringInfo stringInfo;
    stringInfo.name = STRING_NAME;
    stringInfo.owner = STRING_NAME;
    stringInfo.authType = STRING_NAME;
    EXPECT_NE(data.WriteParcelable(&stringInfo), false);
    AAFwk::Want options;
    sptr<IAppAccountAuthenticatorCallback> callback = new (std::nothrow) MockAuthenticatorCallback();
    EXPECT_NE(callback, nullptr);
    EXPECT_NE(data.WriteParcelable(&options), false);
    EXPECT_NE(data.WriteRemoteObject(callback->AsObject()), false);
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_AUTHENTICATE),
        data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_016
 * @tc.desc: GetAuthToken success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_016, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_GET_AUTH_TOKEN),
        data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_017
 * @tc.desc: SetOAuthToken success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_017, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_SET_O_AUTH_TOKEN),
        data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_018
 * @tc.desc: DeleteAuthToken success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_018, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_DELETE_AUTH_TOKEN),
        data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_019
 * @tc.desc: SetAuthTokenVisibility success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_019, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(
        IAppAccountIpcCode::COMMAND_SET_AUTH_TOKEN_VISIBILITY), data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_020
 * @tc.desc: CheckAuthTokenVisibility success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_020, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(
        IAppAccountIpcCode::COMMAND_CHECK_AUTH_TOKEN_VISIBILITY), data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_021
 * @tc.desc: GetAuthenticatorInfo success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_021, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_GET_AUTHENTICATOR_INFO),
        data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_022
 * @tc.desc: GetAllOAuthTokens success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_022, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_GET_ALL_O_AUTH_TOKENS),
        data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_023
 * @tc.desc: GetAuthList success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_023, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_GET_AUTH_LIST),
        data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_024
 * @tc.desc: GetAuthenticatorCallback success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_024, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(
        IAppAccountIpcCode::COMMAND_GET_AUTHENTICATOR_CALLBACK), data, reply, option), ERR_INVALID_DATA);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_025
 * @tc.desc: GetAllAccounts success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_025, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_GET_ALL_ACCOUNTS),
        data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_026
 * @tc.desc: GetAllAccessibleAccounts success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_026, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(
        IAppAccountIpcCode::COMMAND_GET_ALL_ACCESSIBLE_ACCOUNTS), data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_027
 * @tc.desc: CheckAppAccess success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_027, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_CHECK_APP_ACCESS),
        data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_028
 * @tc.desc: DeleteAccountCredential success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_028, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(
        IAppAccountIpcCode::COMMAND_DELETE_ACCOUNT_CREDENTIAL), data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_029
 * @tc.desc: SelectAccountsByOptions success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_029, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    SelectAccountsOptions options;
    sptr<IAppAccountAuthenticatorCallback> callback = new (std::nothrow) MockAuthenticatorCallback();
    EXPECT_NE(callback, nullptr);
    EXPECT_NE(data.WriteParcelable(&options), false);
    EXPECT_NE(data.WriteRemoteObject(callback->AsObject()), false);
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(
        IAppAccountIpcCode::COMMAND_SELECT_ACCOUNTS_BY_OPTIONS), data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_030
 * @tc.desc: VerifyCredential success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_030, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    VerifyCredentialOptions options;
    sptr<IAppAccountAuthenticatorCallback> callback = new (std::nothrow) MockAuthenticatorCallback();
    EXPECT_NE(callback, nullptr);
    EXPECT_NE(data.WriteParcelable(&options), false);
    EXPECT_NE(data.WriteRemoteObject(callback->AsObject()), false);
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_VERIFY_CREDENTIAL),
        data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_031
 * @tc.desc: CheckAccountLabels success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_031, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    std::vector<std::string> labels = { STRING_NAME };
    data.WriteInt32(labels.size());
    for (auto it = labels.begin(); it != labels.end(); ++it) {
        EXPECT_NE(data.WriteString16(Str8ToStr16((*it))), false);
    }
    sptr<IAppAccountAuthenticatorCallback> callback = new (std::nothrow) MockAuthenticatorCallback();
    EXPECT_NE(callback, nullptr);
    EXPECT_NE(data.WriteRemoteObject(callback->AsObject()), false);
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_CHECK_ACCOUNT_LABELS),
        data, reply, option), ERR_NONE);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_032
 * @tc.desc: SetAuthenticatorProperties success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_032, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    EXPECT_NE(data.WriteString16(Str8ToStr16(STRING_NAME)), false);
    SetPropertiesOptions options;
    EXPECT_NE(data.WriteParcelable(&options), false);
    sptr<IAppAccountAuthenticatorCallback> callback = new (std::nothrow) MockAuthenticatorCallback();
    EXPECT_NE(callback, nullptr);
    EXPECT_NE(data.WriteRemoteObject(callback->AsObject()), false);
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(
        IAppAccountIpcCode::COMMAND_SET_AUTHENTICATOR_PROPERTIES), data, reply, option), ERR_NONE);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_033
 * @tc.desc: SetAppAccess with right code, would not pass caller check.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_033, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_SET_APP_ACCESS),
        data, reply, option), ERR_NONE);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_034
 * @tc.desc: SetAppAccess with right code, would not pass caller check.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_034, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_SET_APP_ACCESS),
        data, reply, option), ERR_NONE);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_035
 * @tc.desc: SetAppAccess with right code, would not pass caller check.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_035, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_SET_APP_ACCESS),
        data, reply, option), ERR_NONE);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_036
 * @tc.desc: GetAuthToken with right code, would not pass caller check.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_036, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_GET_O_AUTH_TOKEN),
        data, reply, option), ERR_NONE);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_EQ(reply.ReadString16(), u"");
    EXPECT_EQ(reply.ReadInt32(), ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_037
 * @tc.desc: GetAuthToken with right code, would not pass caller check.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_037, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_GET_AUTH_TOKEN),
        data, reply, option), ERR_NONE);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_EQ(reply.ReadString16(), u"");
    EXPECT_EQ(reply.ReadInt32(), ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
* @tc.name: AppAccountStubModuleTest_AppStubCov_038
* @tc.desc: DeleteAuthToken with right code, would not pass caller check.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_038, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_DELETE_AUTH_TOKEN),
        data, reply, option), ERR_NONE);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
* @tc.name: AppAccountStubModuleTest_AppStubCov_039
* @tc.desc: DeleteAuthToken with right code, would not pass caller check.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_039, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_DELETE_AUTH_TOKEN),
        data, reply, option), ERR_NONE);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
* @tc.name: AppAccountStubModuleTest_AppStubCov_040
* @tc.desc: DeleteAuthToken with right code, would not pass caller check.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_040, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(
        IAppAccountIpcCode::COMMAND_SET_AUTH_TOKEN_VISIBILITY), data, reply, option), ERR_NONE);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
* @tc.name: AppAccountStubModuleTest_AppStubCov_041
* @tc.desc: DeleteAuthToken with right code, would not pass caller check.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_041, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(
        IAppAccountIpcCode::COMMAND_SET_AUTH_TOKEN_VISIBILITY), data, reply, option), ERR_NONE);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_042
 * @tc.desc: CheckAuthTokenVisibility with right code.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_042, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(
        IAppAccountIpcCode::COMMAND_CHECK_AUTH_TOKEN_VISIBILITY), data, reply, option), ERR_NONE);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
    EXPECT_EQ(reply.ReadInt32(), ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_043
 * @tc.desc: CheckAuthTokenVisibility with right code.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_043, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(
        static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_CHECK_AUTH_TOKEN_VISIBILITY), data, reply, option), ERR_NONE);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
    EXPECT_EQ(reply.ReadInt32(), ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_044
 * @tc.desc: GetAuthList with right code.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_044, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_GET_AUTH_LIST),
        data, reply, option), ERR_NONE);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
    EXPECT_EQ(reply.ReadInt32(), ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_045
 * @tc.desc: GetAuthList with right code.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_045, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    ASSERT_TRUE(data.WriteString16(Str8ToStr16(STRING_NAME)));
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_GET_AUTH_LIST),
        data, reply, option), ERR_NONE);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
    EXPECT_EQ(reply.ReadInt32(), ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

namespace {
class MockAppAccountSubsriber : public AppAccountSubscriber {
public:
    MockAppAccountSubsriber() : AppAccountSubscriber() {};
    ~MockAppAccountSubsriber() {};
    void OnAccountsChanged(const std::vector<AppAccountInfo> &accounts) override {};
};
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_046
 * @tc.desc: SubscribeAccount with get bundle name error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_046, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    AppAccountSubscribeInfo info;
    info.SetOwners(std::vector<std::string>({STRING_NAME, STRING_NAME}));
    ASSERT_TRUE(data.WriteParcelable(&info));
    std::shared_ptr<MockAppAccountSubsriber> subscriber = std::make_shared<MockAppAccountSubsriber>();
    ASSERT_TRUE(data.WriteRemoteObject(AppAccountEventListener::GetInstance()->AsObject()));
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_SUBSCRIBE_APP_ACCOUNT),
        data, reply, option), ERR_NONE);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_047
 * @tc.desc: GetAuthList with right code.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_047, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    std::shared_ptr<MockAppAccountSubsriber> subscriber = std::make_shared<MockAppAccountSubsriber>();
    ASSERT_TRUE(data.WriteRemoteObject(AppAccountEventListener::GetInstance()->AsObject()));
    std::vector<std::string> owners(5, STRING_NAME);
    ASSERT_TRUE(data.WriteInt32(owners.size()));
    for (auto it8 = owners.begin(); it8 != owners.end(); ++it8) {
        ASSERT_TRUE(data.WriteString16(Str8ToStr16((*it8))));
    }
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(IAppAccountIpcCode::COMMAND_UNSUBSCRIBE_APP_ACCOUNT),
        data, reply, option), ERR_NONE);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
}

/**
 * @tc.name: AppAccountStubModuleTest_AppStubCov_048
 * @tc.desc: QueryAllAccessibleAccounts success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountStubModuleTest, AppAccountStubModuleTest_AppStubCov_048, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(data.WriteInterfaceToken(AppAccountStub::GetDescriptor()), true);
    ASSERT_EQ(data.WriteString16(Str8ToStr16(STRING_NAME)), true);
    EXPECT_EQ(g_servicePtr->OnRemoteRequest(static_cast<uint32_t>(
        IAppAccountIpcCode::COMMAND_QUERY_ALL_ACCESSIBLE_ACCOUNTS), data, reply, option), ERR_NONE);
}