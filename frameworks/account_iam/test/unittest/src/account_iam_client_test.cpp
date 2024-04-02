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
#define private public
#include "account_iam_client.h"
#undef private
#include "account_iam_client_test_callback.h"
#include "account_log_wrapper.h"
#include "account_iam_callback_stub.h"
#include "account_iam_callback_service.h"
#ifdef PROXY_MOCK
#define private public
#include "account_iam_service.h"
#undef private
#endif
#include "account_iam_mgr_proxy.h"
#include "token_setproc.h"
#include "iam_common_defines.h"
#include "ipc_skeleton.h"
#include "test_common.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::UserIam::UserAuth;

static uint64_t g_selfTokenID = -1;
namespace OHOS {
namespace AccountTest {
namespace {
const int32_t TEST_USER_ID = 200;
const int32_t DEFAULT_API_VERSION = 8;
const uint32_t INVALID_IPC_CODE = 1000;
const uint32_t INVALID_TOKEN_ID = 0;
const uint64_t TEST_CONTEXT_ID = 122;
const std::vector<uint8_t> TEST_CHALLENGE = {1, 2, 3, 4};

static PermissionDef INFO_MANAGER_TEST_PERM_DEF1 = {
    .permissionName = "ohos.permission.open_door",
    .bundleName = "account_iam_client_test",
    .grantMode = 1,
    .availableLevel = APL_NORMAL,
    .provisionEnable = true,
    .distributedSceneEnable = false,
    .label = "label",
    .labelId = 1,
    .description = "open the door",
    .descriptionId = 1
};

static PermissionDef INFO_MANAGER_TEST_PERM_DEF2 = {
    .permissionName = "ohos.permission.break_door",
    .bundleName = "account_iam_client_test",
    .grantMode = 1,
    .availableLevel = APL_NORMAL,
    .provisionEnable = true,
    .distributedSceneEnable = false,
    .label = "label",
    .labelId = 1,
    .description = "break the door",
    .descriptionId = 1
};

static PermissionStateFull INFO_MANAGER_TEST_STATE1 = {
    .permissionName = "ohos.permission.open_door",
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {1},
    .grantFlags = {1}
};

static PermissionStateFull INFO_MANAGER_TEST_STATE2 = {
    .permissionName = "ohos.permission.open_door",
    .isGeneral = true,
    .resDeviceID = {"device 0", "device 1"},
    .grantStatus = {1, 3},
    .grantFlags = {1, 2}
};

static HapPolicyParams INFO_MANAGER_TEST_POLICY_PRAMS = {
    .apl = APL_NORMAL,
    .domain = "account_iam",
    .permList = {INFO_MANAGER_TEST_PERM_DEF1, INFO_MANAGER_TEST_PERM_DEF2},
    .permStateList = {INFO_MANAGER_TEST_STATE1, INFO_MANAGER_TEST_STATE2}
};

HapInfoParams infoManagerTestNormalInfoParms = {
    .userID = 1,
    .bundleName = "account_iam_client_test",
    .instIndex = 0,
    .appIDDesc = "test",
    .apiVersion = DEFAULT_API_VERSION,
    .isSystemApp = false
};

HapInfoParams infoManagerTestSystemInfoParms = {
    .userID = 1,
    .bundleName = "account_iam_client_test",
    .instIndex = 0,
    .appIDDesc = "test",
    .apiVersion = DEFAULT_API_VERSION,
    .isSystemApp = true
};
} // namespace

#ifdef HAS_PIN_AUTH_PART
class MockIInputer : public OHOS::AccountSA::IInputer {
public:
    virtual ~MockIInputer() {}
    void OnGetData(int32_t authSubType, std::shared_ptr<IInputerData> inputerData) override
    {
        return;
    }
};
#endif

class AccountIAMClientTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

class CheckResultGetSetPropCallback final : public AccountSA::GetSetPropCallback {
public:
    void OnResult(int32_t result, const Attributes &extraInfo)
    {
        code_ = result;
    }
    int GetResult()
    {
        if (code_ != ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR) {
            return ERR_OK;
        }
        return code_;
    }

private:
    int code_;
};

class CheckResultIDMCallback final : public AccountSA::IDMCallback {
public:
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo)
    {
        return;
    }
    void OnResult(int32_t result, const Attributes &extraInfo)
    {
        code_ = result;
    }
    int GetResult()
    {
        if (code_ != ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR) {
            return ERR_OK;
        }
        return code_;
    }

private:
    int code_;
};

#ifdef HAS_PIN_AUTH_PART
class TestIInputer : public OHOS::AccountSA::IInputer {
public:
    void OnGetData(int32_t authSubType, std::shared_ptr<IInputerData> inputerData) override
    {
        if (inputerData != nullptr) {
            inputerData->OnSetData(authSubType, {0, 0, 0, 0, 0, 0});
        }
    }

    virtual ~TestIInputer() = default;
};
#endif

void AccountIAMClientTest::SetUpTestCase(void)
{
    AccessTokenID tokenId = AccessTokenKit::GetNativeTokenId("accountmgr");
    SetSelfTokenID(tokenId);
    g_selfTokenID = tokenId;
#ifdef PROXY_MOCK
    sptr<IAccountIAM> service = new (std::nothrow) AccountIAMService();
    ASSERT_NE(service, nullptr);
    AccountIAMClient::GetInstance().proxy_ = new (std::nothrow) AccountIAMMgrProxy(service->AsObject());
    ASSERT_NE(AccountIAMClient::GetInstance().proxy_, nullptr);
#endif
}

void AccountIAMClientTest::TearDownTestCase(void)
{}

void AccountIAMClientTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

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
#ifdef PROXY_MOCK
    EXPECT_FALSE(challenge.size() != 0);
#else // BUNDLE_ADAPTER_MOCK
    EXPECT_TRUE(challenge.size() != 0);
#endif
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
#ifdef PROXY_MOCK
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(Exactly(0));
#else
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(Exactly(1));
#endif
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
#ifdef PROXY_MOCK
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(Exactly(0));
#else
    EXPECT_CALL(*testCallback, OnResult(_, _)).Times(Exactly(2));
#endif
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
    AccountIAMClient::AccountIAMDeathRecipient recipient;
    recipient.OnRemoteDied(nullptr);
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
    EXPECT_EQ(ERR_ACCOUNT_COMMON_INVALID_PARAMETER, ret);
}

/**
 * @tc.name: AccountIAMClient_GetAvailableStatus_0300
 * @tc.desc: AuthType is err.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_GetAvailableStatus_0300, TestSize.Level0)
{
    int32_t status;
    AuthTrustLevel level = static_cast<AuthTrustLevel>(20000);
    AuthType authType = static_cast<AuthType>(-1);
    int32_t ret = AccountIAMClient::GetInstance().GetAvailableStatus(authType, level, status);
    EXPECT_EQ(ERR_ACCOUNT_COMMON_INVALID_PARAMETER, ret);
}

/**
 * @tc.name: AccountIAMClient_GetProperty_0100
 * @tc.desc: Get property.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_GetProperty_0100, TestSize.Level0)
{
    GetPropertyRequest testRequest = {
        .keys = { Attributes::AttributeKey::ATTR_PIN_SUB_TYPE }
    };
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
 * @tc.name: AccountIAMClient_AuthUser_0200
 * @tc.desc: Auth callback is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI5N90O
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient_AuthUser_0200, TestSize.Level0)
{
    uint64_t ret = AccountIAMClient::GetInstance().AuthUser(
        0, TEST_CHALLENGE, AuthType::PIN, AuthTrustLevel::ATL1, nullptr);
    EXPECT_EQ(ret, 0);
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

#ifdef HAS_PIN_AUTH_PART
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
#endif

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
    int32_t ret = stub->OnRemoteRequest(static_cast<uint32_t>(IDMCallbackInterfaceCode::ON_ACQUIRE_INFO), data, reply,
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
    int32_t ret = stub->OnRemoteRequest(static_cast<uint32_t>(GetCredInfoCallbackInterfaceCode::ON_CREDENTIAL_INFO),
        data, reply, option);
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

/**
 * @tc.name: AccountIAMClient001
 * @tc.desc: Test the interface of the accountIAM calling the server not pass system applicaiton verify.
 * @tc.type: FUNC
 * @tc.require: issueI66BG5
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient001, TestSize.Level0)
{
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(infoManagerTestNormalInfoParms, INFO_MANAGER_TEST_POLICY_PRAMS);
    ASSERT_NE(INVALID_TOKEN_ID, tokenIdEx.tokenIDEx);
    SetSelfTokenID(tokenIdEx.tokenIDEx);

    int32_t status;
    int result = AccountIAMClient::GetInstance().GetAvailableStatus(AuthType::FACE, AuthTrustLevel::ATL1, status);
    ASSERT_EQ(ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR, result);

    ASSERT_EQ(ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR, AccountIAMClient::GetInstance().CancelAuth(TEST_CONTEXT_ID));

#ifdef HAS_PIN_AUTH_PART
    std::shared_ptr<IInputer> inputer = std::make_shared<TestIInputer>();
    ASSERT_NE(nullptr, inputer);
    ASSERT_EQ(ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR, AccountIAMClient::GetInstance().RegisterPINInputer(inputer));

    ASSERT_EQ(ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR, AccountIAMClient::GetInstance().UnregisterPINInputer());

    std::shared_ptr<IInputer> inputerTwo = std::make_shared<TestIInputer>();
    ASSERT_NE(nullptr, inputerTwo);
    ASSERT_EQ(ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR,
        AccountIAMClient::GetInstance().RegisterInputer(AuthType::PIN, inputerTwo));
    ASSERT_EQ(
        ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR, AccountIAMClient::GetInstance().UnregisterInputer(AuthType::PIN));
#endif

    std::vector<uint8_t> challenge;
    ASSERT_EQ(AccountIAMClient::GetInstance().OpenSession(0, challenge), ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);

    ASSERT_EQ(ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR, AccountIAMClient::GetInstance().CloseSession(TEST_USER_ID));

    ASSERT_EQ(AccountIAMClient::GetInstance().Cancel(TEST_USER_ID), ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);

    auto testCallback = std::make_shared<MockGetCredInfoCallback>();
    ASSERT_NE(testCallback, nullptr);
    ASSERT_EQ(AccountIAMClient::GetInstance().GetCredentialInfo(TEST_USER_ID, AuthType::PIN, testCallback),
        ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);

    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(infoManagerTestNormalInfoParms.userID,
        infoManagerTestNormalInfoParms.bundleName, infoManagerTestNormalInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);
    SetSelfTokenID(g_selfTokenID);
}

/**
 * @tc.name: AccountIAMClient002
 * @tc.desc: Test accountIAM interface call server which result returned by the callback not pass system app verify.
 * @tc.type: FUNC
 * @tc.require: issueI66BG5
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient002, TestSize.Level0)
{
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(infoManagerTestNormalInfoParms, INFO_MANAGER_TEST_POLICY_PRAMS);
    ASSERT_NE(INVALID_TOKEN_ID, tokenIdEx.tokenIDEx);
    SetSelfTokenID(tokenIdEx.tokenIDEx);

    GetPropertyRequest testRequestGet = {};
    auto testCallback = std::make_shared<MockGetSetPropCallback>();
    ASSERT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnResult(ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR, _)).Times(1);
    AccountIAMClient::GetInstance().GetProperty(TEST_USER_ID, testRequestGet, testCallback);

    SetPropertyRequest testRequestSet = {};
    EXPECT_CALL(*testCallback, OnResult(ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR, _)).Times(1);
    AccountIAMClient::GetInstance().SetProperty(TEST_USER_ID, testRequestSet, testCallback);

    CredentialParameters testPara = {};
    auto testIDMCallback = std::make_shared<MockIDMCallback>();
    ASSERT_NE(testIDMCallback, nullptr);
    EXPECT_CALL(*testIDMCallback, OnResult(ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR, _)).Times(Exactly(1));
    AccountIAMClient::GetInstance().AddCredential(TEST_USER_ID, testPara, testIDMCallback);

    EXPECT_CALL(*testIDMCallback, OnResult(ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR, _)).Times(Exactly(1));
    AccountIAMClient::GetInstance().UpdateCredential(TEST_USER_ID, testPara, testIDMCallback);

    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    uint64_t testCredentialId = 111;
    EXPECT_CALL(*testIDMCallback, OnResult(ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR, _)).Times(Exactly(1));
    AccountIAMClient::GetInstance().DelUser(TEST_USER_ID, testAuthToken, testIDMCallback);

    EXPECT_CALL(*testIDMCallback, OnResult(ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR, _)).Times(Exactly(1));
    AccountIAMClient::GetInstance().DelCred(TEST_USER_ID, testCredentialId, testAuthToken, testIDMCallback);

    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(infoManagerTestNormalInfoParms.userID,
        infoManagerTestNormalInfoParms.bundleName, infoManagerTestNormalInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);
    SetSelfTokenID(g_selfTokenID);
}

/**
 * @tc.name: AccountIAMClient003
 * @tc.desc: Test the interface of the accountIAM calling the server pass system applicaiton verify.
 * @tc.type: FUNC
 * @tc.require: issueI66BG5
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient003, TestSize.Level0)
{
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(infoManagerTestSystemInfoParms, INFO_MANAGER_TEST_POLICY_PRAMS);
    ASSERT_NE(INVALID_TOKEN_ID, tokenIdEx.tokenIDEx);
    SetSelfTokenID(tokenIdEx.tokenIDEx);

    int32_t status;
    int result = AccountIAMClient::GetInstance().GetAvailableStatus(AuthType::FACE, AuthTrustLevel::ATL1, status);
    ASSERT_NE(ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR, result);

    ASSERT_NE(ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR, AccountIAMClient::GetInstance().CancelAuth(TEST_CONTEXT_ID));

#ifdef HAS_PIN_AUTH_PART
    std::shared_ptr<IInputer> inputer = std::make_shared<TestIInputer>();
    ASSERT_NE(nullptr, inputer);
    ASSERT_NE(ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR, AccountIAMClient::GetInstance().RegisterPINInputer(inputer));

    ASSERT_NE(ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR, AccountIAMClient::GetInstance().UnregisterPINInputer());

    std::shared_ptr<IInputer> inputerTwo = std::make_shared<TestIInputer>();
    ASSERT_NE(nullptr, inputerTwo);
    ASSERT_NE(ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR,
        AccountIAMClient::GetInstance().RegisterInputer(AuthType::PIN, inputerTwo));
    ASSERT_NE(
        ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR, AccountIAMClient::GetInstance().UnregisterInputer(AuthType::PIN));
#endif

    std::vector<uint8_t> challenge;
    ASSERT_NE(AccountIAMClient::GetInstance().OpenSession(0, challenge), ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);

    ASSERT_NE(ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR, AccountIAMClient::GetInstance().CloseSession(TEST_USER_ID));

    ASSERT_NE(AccountIAMClient::GetInstance().Cancel(TEST_USER_ID), ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);

    auto testCallback = std::make_shared<MockGetCredInfoCallback>();
    ASSERT_NE(testCallback, nullptr);
    ASSERT_NE(AccountIAMClient::GetInstance().GetCredentialInfo(TEST_USER_ID, AuthType::PIN, testCallback),
        ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);

    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(infoManagerTestSystemInfoParms.userID,
        infoManagerTestSystemInfoParms.bundleName, infoManagerTestSystemInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);
    SetSelfTokenID(g_selfTokenID);
}

/**
 * @tc.name: AccountIAMClient004
 * @tc.desc: Test accountIAM interface call server which result returned by the callback pass system app verify.
 * @tc.type: FUNC
 * @tc.require: issueI66BG5
 */
HWTEST_F(AccountIAMClientTest, AccountIAMClient004, TestSize.Level0)
{
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(infoManagerTestSystemInfoParms, INFO_MANAGER_TEST_POLICY_PRAMS);
    ASSERT_NE(INVALID_TOKEN_ID, tokenIdEx.tokenIDEx);
    SetSelfTokenID(tokenIdEx.tokenIDEx);

    GetPropertyRequest testRequestGet = {};
    auto testCallback = std::make_shared<CheckResultGetSetPropCallback>();
    ASSERT_NE(testCallback, nullptr);
    AccountIAMClient::GetInstance().GetProperty(TEST_USER_ID, testRequestGet, testCallback);
    ASSERT_EQ(testCallback->GetResult(), ERR_OK);

    SetPropertyRequest testRequestSet = {};
    AccountIAMClient::GetInstance().SetProperty(TEST_USER_ID, testRequestSet, testCallback);
    ASSERT_EQ(testCallback->GetResult(), ERR_OK);

    CredentialParameters testPara = {};
    auto testIDMCallback = std::make_shared<CheckResultIDMCallback>();
    ASSERT_NE(testIDMCallback, nullptr);
    AccountIAMClient::GetInstance().AddCredential(TEST_USER_ID, testPara, testIDMCallback);
    ASSERT_EQ(testCallback->GetResult(), ERR_OK);

    AccountIAMClient::GetInstance().UpdateCredential(TEST_USER_ID, testPara, testIDMCallback);
    ASSERT_EQ(testCallback->GetResult(), ERR_OK);

    std::vector<uint8_t> testAuthToken = {1, 2, 3, 4};
    uint64_t testCredentialId = 111;
    AccountIAMClient::GetInstance().DelUser(TEST_USER_ID, testAuthToken, testIDMCallback);
    ASSERT_EQ(testCallback->GetResult(), ERR_OK);

    AccountIAMClient::GetInstance().DelCred(TEST_USER_ID, testCredentialId, testAuthToken, testIDMCallback);
    ASSERT_EQ(testCallback->GetResult(), ERR_OK);

    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(infoManagerTestSystemInfoParms.userID,
        infoManagerTestSystemInfoParms.bundleName, infoManagerTestSystemInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);
    SetSelfTokenID(g_selfTokenID);
}

#ifdef HAS_PIN_AUTH_PART
/**
 * @tc.name: StartDomainAuth001
 * @tc.desc: test StartDomainAuth.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMClientTest, StartDomainAuth001, TestSize.Level0)
{
    auto testCallback = std::make_shared<MockIDMCallback>();
    EXPECT_CALL(*testCallback, OnResult(ERR_ACCOUNT_IAM_KIT_INPUTER_NOT_REGISTERED, _)).Times(Exactly(1));
    AccountIAMClient::GetInstance().domainInputer_ = nullptr;
    uint64_t ret = AccountIAMClient::GetInstance().StartDomainAuth(TEST_USER_ID, testCallback);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: StartDomainAuth002
 * @tc.desc: test StartDomainAuth.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMClientTest, StartDomainAuth002, TestSize.Level0)
{
    auto testCallback = std::make_shared<MockIDMCallback>();
    std::shared_ptr<IInputer> inputer = std::make_shared<TestIInputer>();
    EXPECT_CALL(*testCallback, OnResult(ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR, _)).Times(Exactly(1));
    AccountIAMClient::GetInstance().domainInputer_ = inputer;
    uint64_t ret = AccountIAMClient::GetInstance().StartDomainAuth(TEST_USER_ID, testCallback);
    EXPECT_EQ(0, ret);
    testing::Mock::AllowLeak(testCallback.get());
}
#endif

/**
 * @tc.name: ResetAccountIAMProxy001
 * @tc.desc: test ResetAccountIAMProxy.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMClientTest, ResetAccountIAMProxy001, TestSize.Level0)
{
    wptr<IRemoteObject> remote;
    AccountIAMClient::GetInstance().proxy_ = nullptr;
    AccountIAMClient::GetInstance().ResetAccountIAMProxy(remote);
    sptr<IAccountIAM> testIAccountIAM = new (std::nothrow) AccountIAMMgrProxy(nullptr);
    AccountIAMClient::GetInstance().proxy_ = testIAccountIAM;
    EXPECT_NE(AccountIAMClient::GetInstance().proxy_, nullptr);
    AccountIAMClient::GetInstance().ResetAccountIAMProxy(remote);
}
}  // namespace AccountTest
}  // namespace OHOS