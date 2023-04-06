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

#include <gmock/gmock.h>
#include "accesstoken_kit.h"
#include "account_iam_client.h"
#include "account_iam_client_test_callback.h"
#include "account_log_wrapper.h"
#include "account_iam_callback_stub.h"
#include "account_iam_callback_service.h"
#include "token_setproc.h"
#include "iam_common_defines.h"

namespace OHOS {
namespace AccountTest {
namespace {
    const int32_t TEST_USER_ID = 200;
    const uint32_t INVALID_IPC_CODE = 1000;
    const uint64_t TEST_CONTEXT_ID = 122;
    const std::vector<uint8_t> TEST_CHALLENGE = {1, 2, 3, 4};
}

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::UserIam::UserAuth;

class MockIInputer : public OHOS::AccountSA::IInputer {
public:
    virtual ~MockIInputer() {}
    void OnGetData(int32_t authSubType, std::shared_ptr<IInputerData> inputerData) override
    {
        return;
    }
};

class AccountIAMClientTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void AccountIAMClientTest::SetUpTestCase(void)
{
    AccessTokenID tokenId = AccessTokenKit::GetNativeTokenId("accountmgr");
    SetSelfTokenID(tokenId);
}

void AccountIAMClientTest::TearDownTestCase(void)
{}

void AccountIAMClientTest::SetUp(void)
{}

void AccountIAMClientTest::TearDown(void)
{}

/**
 * @tc.name: AccountIAMClient_OpenSession_0100
 * @tc.desc: Open Session.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_OpenSession_0100, TestSize.Level0)
{
    std::vector<uint8_t> challenge;
    AccountIAMClient::GetInstance().OpenSession(0, challenge);
    EXPECT_TRUE(challenge.size() != 0);
    AccountIAMClient::GetInstance().CloseSession(0);
}

/**
 * @tc.name: AccountIAMClient_AddCredential_0100
 * @tc.desc: Add credential.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_AddCredential_0100, TestSize.Level0)
{
    CredentialParameters testPara = {};
    auto testCallback = std::make_shared<MockIDMCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(Exactly(1));
    AccountIAMClient::GetInstance().AddCredential(TEST_USER_ID, testPara, testCallback);
}

/**
 * @tc.name: AccountIAMClient_AddCredential_0200
 * @tc.desc: Add credential.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_AddCredential_0200, TestSize.Level0)
{
    CredentialParameters testPara = {};
    testPara.authType = AuthType::PIN;
    auto testCallback = std::make_shared<MockIDMCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(Exactly(2));
    AccountIAMClient::GetInstance().AddCredential(0, testPara, testCallback);
    AccountIAMClient::GetInstance().AddCredential(TEST_USER_ID, testPara, nullptr);
    AccountIAMClient::GetInstance().AddCredential(TEST_USER_ID, testPara, testCallback);
}

/**
 * @tc.name: AccountIAMClient_UpdateCredential_0100
 * @tc.desc: Update credential.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_UpdateCredential_0100, TestSize.Level0)
{
    CredentialParameters testPara = {};
    auto testCallback = std::make_shared<MockIDMCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(Exactly(1));
    AccountIAMClient::GetInstance().UpdateCredential(TEST_USER_ID, testPara, testCallback);
}

/**
 * @tc.name: AccountIAMClient_UpdateCredential_200
 * @tc.desc: Update credential.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_UpdateCredential_200, TestSize.Level0)
{
    CredentialParameters testPara = {};
    testPara.authType = AuthType::PIN;
    auto testCallback = std::make_shared<MockIDMCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(Exactly(2));
    AccountIAMClient::GetInstance().UpdateCredential(TEST_USER_ID, testPara, nullptr);
    AccountIAMClient::GetInstance().UpdateCredential(0, testPara, testCallback);
    AccountIAMClient::GetInstance().UpdateCredential(TEST_USER_ID, testPara, testCallback);
}

/**
 * @tc.name: AccountIAMClient_Cancel_0100
 * @tc.desc: Cancel.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_Cancel_0100, TestSize.Level0)
{
    int32_t ret = AccountIAMClient::GetInstance().Cancel(TEST_USER_ID);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: AccountIAMClient_DelCred_0100
 * @tc.desc: Delete credential.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_DelCred_0100, TestSize.Level0)
{
    uint64_t testCredentialId = 111;
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    auto testCallback = std::make_shared<MockIDMCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(Exactly(2));
    AccountIAMClient::GetInstance().DelCred(TEST_USER_ID, testCredentialId, testAuthToken, nullptr);
    AccountIAMClient::GetInstance().DelCred(0, testCredentialId, testAuthToken, testCallback);
    AccountIAMClient::GetInstance().DelCred(TEST_USER_ID, testCredentialId, testAuthToken, testCallback);
}

/**
 * @tc.name: AccountIAMClient_DelUser_0100
 * @tc.desc: Delete user.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_DelUser_0100, TestSize.Level0)
{
    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    auto testCallback = std::make_shared<MockIDMCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(Exactly(2));
    AccountIAMClient::GetInstance().DelUser(TEST_USER_ID, testAuthToken, nullptr);
    AccountIAMClient::GetInstance().DelUser(0, testAuthToken, testCallback);
    AccountIAMClient::GetInstance().DelUser(TEST_USER_ID, testAuthToken, testCallback);
}

/**
 * @tc.name: AccountIAMClient_GetCredentialInfo_0100
 * @tc.desc: Get credential info.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_GetCredentialInfo_0100, TestSize.Level0)
{
    auto testCallback = std::make_shared<MockGetCredInfoCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnCredentialInfo(_, _)).Times(Exactly(1));
    AccountIAMClient::GetInstance().GetCredentialInfo(TEST_USER_ID, AuthType::PIN, testCallback);
}

/**
 * @tc.name: AccountIAMClient_GetAvailableStatus_0100
 * @tc.desc: Get available status.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_GetAvailableStatus_0100, TestSize.Level0)
{
    int32_t status;
    AccountIAMClient::GetInstance().GetAvailableStatus(AuthType::FACE, AuthTrustLevel::ATL1, status);
    EXPECT_NE(status, 0);
}

/**
 * @tc.name: AccountIAMClient_GetAvailableStatus_0200
 * @tc.desc: Get available status.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_GetAvailableStatus_0200, TestSize.Level0)
{
    int32_t status;
    AuthTrustLevel level = static_cast<AuthTrustLevel>(0);
    int32_t ret = AccountIAMClient::GetInstance().GetAvailableStatus(AuthType::FACE, level, status);
    EXPECT_EQ(ERR_ACCOUNT_IAM_KIT_PARAM_INVALID_ERROR, ret);
}

/**
 * @tc.name: AccountIAMClient_GetProperty_0100
 * @tc.desc: Get property.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_GetProperty_0100, TestSize.Level0)
{
    GetPropertyRequest testRequest = {};
    auto testCallback = std::make_shared<MockGetSetPropCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    AccountIAMClient::GetInstance().GetProperty(TEST_USER_ID, testRequest, nullptr);
    AccountIAMClient::GetInstance().GetProperty(TEST_USER_ID, testRequest, testCallback);
}

/**
 * @tc.name: AccountIAMClient_SetProperty_0100
 * @tc.desc: Set property.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_SetProperty_0100, TestSize.Level0)
{
    SetPropertyRequest testRequest = {};
    auto testCallback = std::make_shared<MockGetSetPropCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    AccountIAMClient::GetInstance().SetProperty(TEST_USER_ID, testRequest, nullptr);
    AccountIAMClient::GetInstance().SetProperty(TEST_USER_ID, testRequest, testCallback);
}

/**
 * @tc.name: AccountIAMClient_AuthUser_0100
 * @tc.desc: Auth user.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_AuthUser_0100, TestSize.Level0)
{
    SetPropertyRequest testRequest = {};
    auto testCallback = std::make_shared<MockIDMCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(2);
    AccountIAMClient::GetInstance().AuthUser(0, TEST_CHALLENGE, AuthType::PIN, AuthTrustLevel::ATL1, testCallback);
    AccountIAMClient::GetInstance().AuthUser(
        TEST_USER_ID, TEST_CHALLENGE, AuthType::PIN, AuthTrustLevel::ATL1, testCallback);
}

/**
 * @tc.name: AccountIAMClient_Auth_0100
 * @tc.desc: Auth current user.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_Auth_0100, TestSize.Level0)
{
    SetPropertyRequest testRequest = {};
    auto testCallback = std::make_shared<MockIDMCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(1);
    AccountIAMClient::GetInstance().Auth(TEST_CHALLENGE, AuthType::PIN, AuthTrustLevel::ATL1, testCallback);
}

/**
 * @tc.name: AccountIAMClient_CancelAuth_0100
 * @tc.desc: Cancel authentication.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_CancelAuth_0100, TestSize.Level0)
{
    EXPECT_NE(ERR_OK, AccountIAMClient::GetInstance().CancelAuth(TEST_CONTEXT_ID));
}

class TestIInputer : public OHOS::AccountSA::IInputer {
public:
    void OnGetData(int32_t authSubType, std::shared_ptr<IInputerData> inputerData)override {}
    virtual ~TestIInputer() = default;
};

/**
 * @tc.name: AccountIAMClient_RegisterPINInputer_0100
 * @tc.desc: Register inputer.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_RegisterPINInputer_0100, TestSize.Level0)
{
    std::shared_ptr<IInputer> inputer = std::make_shared<TestIInputer>();
    EXPECT_NE(nullptr, inputer);
    EXPECT_EQ(ERR_OK, AccountIAMClient::GetInstance().RegisterPINInputer(inputer));
    EXPECT_EQ(ERR_ACCOUNT_IAM_KIT_INPUTER_ALREADY_REGISTERED,
        AccountIAMClient::GetInstance().RegisterPINInputer(inputer));

    AccountIAMClient::GetInstance().UnregisterPINInputer();
}

/**
 * @tc.name: AccountIAMClient_RegisterInputer_0100
 * @tc.desc: Unregister/Register inputer failed for unsupported auth type.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_RegisterInputer_0100, TestSize.Level0)
{
    std::shared_ptr<IInputer> inputer = std::make_shared<TestIInputer>();
    EXPECT_NE(nullptr, inputer);
    EXPECT_EQ(ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE,
        AccountIAMClient::GetInstance().RegisterInputer(AuthType::PIN, inputer));
    EXPECT_EQ(ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE, AccountIAMClient::GetInstance().UnregisterInputer(AuthType::PIN));
}

/**
 * @tc.name: AccountIAMClient_GetAccountState_0100
 * @tc.desc: Get account state.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_GetAccountState_0100, TestSize.Level0)
{
    int32_t userId = 1111; // 1111: invalid userId
    EXPECT_EQ(IDLE, AccountIAMClient::GetInstance().GetAccountState(userId));

    userId = 100; // 100: userId
    EXPECT_NE(IDLE, AccountIAMClient::GetInstance().GetAccountState(userId));
}

/**
 * @tc.name: AccountIAMClient_SetCredential_0100
 * @tc.desc: SetCredential.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_SetCredential_0100, TestSize.Level0)
{
    int32_t userId = 1111; // 1111: userId
    std::vector<uint8_t> cred1(10, 'a');
    CredentialItem credItem;
    AccountIAMClient::GetInstance().SetCredential(userId, cred1);
    AccountIAMClient::GetInstance().GetCredential(userId, credItem);
    EXPECT_TRUE(credItem.oldCredential.empty());
    EXPECT_FALSE(credItem.credential.empty());

    std::vector<uint8_t> cred2(10, 'b');
    AccountIAMClient::GetInstance().SetCredential(userId, cred2);
    AccountIAMClient::GetInstance().GetCredential(userId, credItem);
    EXPECT_FALSE(credItem.oldCredential.empty());
    EXPECT_FALSE(credItem.credential.empty());

    AccountIAMClient::GetInstance().ClearCredential(userId);
}

/**
 * @tc.name: AccountIAMClient_SetAuthSubType_0100
 * @tc.desc: SetAuthSubType.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_SetAuthSubType_0100, TestSize.Level0)
{
    int32_t userId = 1111; // 1111: userId
    int32_t type = 11;
    EXPECT_EQ(0, AccountIAMClient::GetInstance().GetAuthSubType(userId));
    AccountIAMClient::GetInstance().SetAuthSubType(userId, type);
    EXPECT_EQ(type, AccountIAMClient::GetInstance().GetAuthSubType(userId));

    AccountIAMClient::GetInstance().SetAuthSubType(userId, type + 1);
    EXPECT_EQ(type, AccountIAMClient::GetInstance().GetAuthSubType(userId));

    AccountIAMClient::GetInstance().ClearCredential(userId);
}

/**
 * @tc.name: IDMCallbackStub_OnRemoteRequest_0100
 * @tc.desc: OnRemoteRequest with wrong message code.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMClientTest, IDMCallbackStub_OnRemoteRequest_0100, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    data.WriteInterfaceToken(IDMCallbackStub::GetDescriptor());

    sptr<IDMCallbackStub> stub = new (std::nothrow) IDMCallbackService(TEST_USER_ID, nullptr);
    ASSERT_NE(nullptr, stub);
    int32_t ret = stub->OnRemoteRequest(INVALID_IPC_CODE, data, reply, option);
    EXPECT_EQ(IPC_STUB_UNKNOW_TRANS_ERR, ret);
}

/**
 * @tc.name: IDMCallbackStub_ProcOnAcquireInfo_0100
 * @tc.desc: ProcOnAcquireInfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMClientTest, IDMCallbackStub_ProcOnAcquireInfo_0100, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    
    int32_t module = 0;
    int32_t acquireInfo = 0;
    std::vector<uint8_t> buffer;
    data.WriteInterfaceToken(IDMCallbackStub::GetDescriptor());
    data.WriteInt32(module);
    data.WriteInt32(acquireInfo);
    data.WriteUInt8Vector(buffer);

    sptr<IDMCallbackStub> stub = new (std::nothrow) IDMCallbackService(TEST_USER_ID, nullptr);
    ASSERT_NE(nullptr, stub);
    int32_t ret = stub->OnRemoteRequest(static_cast<uint32_t>(IIDMCallback::Message::ON_ACQUIRE_INFO), data, reply,
        option);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: GetCredInfoCallbackStub_OnRemoteRequest_0100
 * @tc.desc: OnRemoteRequest with wrong message code.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMClientTest, GetCredInfoCallbackStub_OnRemoteRequest_0100, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    data.WriteInterfaceToken(GetCredInfoCallbackStub::GetDescriptor());

    sptr<GetCredInfoCallbackStub> stub = new (std::nothrow) GetCredInfoCallbackService(nullptr);
    ASSERT_NE(nullptr, stub);
    int32_t ret = stub->OnRemoteRequest(INVALID_IPC_CODE, data, reply, option);
    EXPECT_EQ(IPC_STUB_UNKNOW_TRANS_ERR, ret);
}

/**
 * @tc.name: GetCredInfoCallbackStub_ProcOnCredentialInfo_0100
 * @tc.desc: ProcOnCredentialInfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMClientTest, GetCredInfoCallbackStub_ProcOnCredentialInfo_0100, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    
    uint32_t vectorSize = 1;
    CredentialInfo info;
    std::vector<CredentialInfo> infoList = {info};
    data.WriteInterfaceToken(GetCredInfoCallbackStub::GetDescriptor());
    data.WriteUint32(vectorSize);
    for (const auto &info : infoList) {
        data.WriteUint64(info.credentialId);
        data.WriteInt32(info.authType);
        PinSubType pinType = info.pinType.value_or(PinSubType::PIN_MAX);
        data.WriteInt32(pinType);
        data.WriteUint64(info.templateId);
    }

    sptr<GetCredInfoCallbackStub> stub = new (std::nothrow) GetCredInfoCallbackService(nullptr);
    ASSERT_NE(nullptr, stub);
    int32_t ret = stub->OnRemoteRequest(static_cast<uint32_t>(IGetCredInfoCallback::Message::ON_CREDENTIAL_INFO), data,
        reply, option);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: GetSetPropCallbackStub_OnRemoteRequest_0100
 * @tc.desc: OnRemoteRequest with wrong message code.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMClientTest, GetSetPropCallbackStub_OnRemoteRequest_0100, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option = {MessageOption::TF_SYNC};
    data.WriteInterfaceToken(GetSetPropCallbackStub::GetDescriptor());

    sptr<GetSetPropCallbackStub> stub = new (std::nothrow) GetSetPropCallbackService(nullptr);
    ASSERT_NE(nullptr, stub);
    int32_t ret = stub->OnRemoteRequest(INVALID_IPC_CODE, data, reply, option);
    EXPECT_EQ(IPC_STUB_UNKNOW_TRANS_ERR, ret);
}
}  // namespace AccountTest
}  // namespace OHOS