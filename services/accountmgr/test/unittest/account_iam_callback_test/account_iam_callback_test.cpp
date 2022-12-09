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

#include <gtest/gtest.h>
#include "accesstoken_kit.h"
#define private public
#include "account_iam_callback.h"
#undef private
#include "account_iam_callback_stub.h"
#include "account_iam_client.h"
#include "account_log_wrapper.h"
#include "domain_account_client.h"
#include "inner_account_iam_manager.h"
#include "iremote_stub.h"
#include "mock_domain_plugin.h"
#include "os_account_info.h"
#include "os_account_manager.h"
#include "token_setproc.h"

namespace OHOS {
namespace AccountTest {
namespace {
const int32_t DEFAULT_USER_ID = 100;
const int32_t TEST_USER_ID = 200;
const int32_t TEST_MODULE = 5;
const int32_t TEST_ACQUIRE_INFO = 10;
} // namespace

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS::UserIam::UserAuth;
using namespace OHOS::Security::AccessToken;

class MockIInputer final : public IInputer {
public:
    virtual ~MockIInputer() {}
    void OnGetData(int32_t authSubType, std::shared_ptr<IInputerData> inputerData) override
    {
        return;
    }
};

class MockIIDMCallback : public IDMCallbackStub {
public:
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) override
    {
        module_ = module;
        acquireInfo_ = acquireInfo;
        return;
    }
    void OnResult(int32_t result, const Attributes &extraInfo) override
    {
        result_ = result;
        return;
    }

public:
    int32_t result_ = -1;
    int32_t module_ = 0;
    uint32_t acquireInfo_ = 0;
};

class MockGetCredInfoCallbackService : public GetCredInfoCallbackStub {
public:
    void OnCredentialInfo(const std::vector<CredentialInfo> &infoList)override
    {
        infoList_ = infoList;
        return;
    }
public:
    std::vector<CredentialInfo> infoList_;
};

class AccountIamCallbackTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void AccountIamCallbackTest::SetUpTestCase(void)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(DEFAULT_USER_ID, "com.ohos.settings", 0);
    SetSelfTokenID(tokenId);
}

void AccountIamCallbackTest::TearDownTestCase(void)
{}

void AccountIamCallbackTest::SetUp(void)
{}

void AccountIamCallbackTest::TearDown(void)
{}

/**
 * @tc.name: AuthCallback_OnResult_0100
 * @tc.desc: OnResult with nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, AuthCallback_OnResult_0100, TestSize.Level0)
{
    auto userAuthCallback = std::make_shared<AuthCallback>(TEST_USER_ID, AuthType::PIN, nullptr);
    EXPECT_TRUE(userAuthCallback->innerCallback_ == nullptr);
    Attributes extraInfo;
    userAuthCallback->OnResult(0, extraInfo);
}

/**
 * @tc.name: AuthCallback_OnResult_0200
 * @tc.desc: OnResult test with PIN.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, AuthCallback_OnResult_0200, TestSize.Level0)
{
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    auto userAuthCallback = std::make_shared<AuthCallback>(TEST_USER_ID, AuthType::PIN, callback);
    EXPECT_TRUE(userAuthCallback->innerCallback_ != nullptr);
    Attributes extraInfo;
    int32_t errCode = 0;
    userAuthCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(ResultCode::FAIL, callback->result_);
    errCode = 10; // result != 0
    userAuthCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(errCode, callback->result_);
}

/**
 * @tc.name: AuthCallback_OnResult_0300
 * @tc.desc: OnResult test with not PIN.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, AuthCallback_OnResult_0300, TestSize.Level0)
{
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    auto userAuthCallback = std::make_shared<AuthCallback>(TEST_USER_ID, AuthType::FACE, callback);
    EXPECT_TRUE(userAuthCallback->innerCallback_ != nullptr);
    Attributes extraInfo;
    int32_t errCode = 0;
    userAuthCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(errCode, callback->result_);
    errCode = 10; // result != 0 && authType_ != AuthType::PIN
    userAuthCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(errCode, callback->result_);
}

/**
 * @tc.name: AuthCallback_OnAcquireInfo_0100
 * @tc.desc: OnAcquireInfo with nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, AuthCallback_OnAcquireInfo_0100, TestSize.Level0)
{
    auto userAuthCallback = std::make_shared<AuthCallback>(TEST_USER_ID, AuthType::PIN, nullptr);
    EXPECT_TRUE(userAuthCallback->innerCallback_ == nullptr);
    Attributes extraInfo;
    userAuthCallback->OnAcquireInfo(0, 0, extraInfo);
}

/**
 * @tc.name: AuthCallback_OnAcquireInfo_0200
 * @tc.desc: OnAcquireInfo with not nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, AuthCallback_OnAcquireInfo_0200, TestSize.Level0)
{
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    auto userAuthCallback = std::make_shared<AuthCallback>(TEST_USER_ID, AuthType::PIN, callback);
    EXPECT_TRUE(userAuthCallback->innerCallback_ != nullptr);
    Attributes extraInfo;
    userAuthCallback->OnAcquireInfo(TEST_MODULE, TEST_ACQUIRE_INFO, extraInfo);
    EXPECT_EQ(TEST_MODULE, callback->module_);
    EXPECT_EQ(TEST_ACQUIRE_INFO, callback->acquireInfo_);
}

/**
 * @tc.name: IDMAuthCallback_OnResult_0100
 * @tc.desc: OnResult with nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, IDMAuthCallback_OnResult_0100, TestSize.Level0)
{
    CredentialParameters credInfo = {};
    Attributes extraInfo;
    auto idmAuthCallback = std::make_shared<IDMAuthCallback>(TEST_USER_ID, credInfo, 0, extraInfo, nullptr);
    EXPECT_TRUE(idmAuthCallback->idmCallback_ == nullptr);
    idmAuthCallback->OnResult(0, extraInfo);
}

/**
 * @tc.name: IDMAuthCallback_OnResult_0200
 * @tc.desc: OnResult with not nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, IDMAuthCallback_OnResult_0200, TestSize.Level0)
{
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    CredentialParameters credInfo = {};
    Attributes extraInfo;
    auto idmAuthCallback = std::make_shared<IDMAuthCallback>(TEST_USER_ID, credInfo, 0, extraInfo, callback);
    EXPECT_TRUE(idmAuthCallback->idmCallback_ != nullptr);
    int32_t errCode = 0;
    idmAuthCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(0, callback->result_);
    errCode = 10;
    idmAuthCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(ResultCode::FAIL, callback->result_);
}

/**
 * @tc.name: IDMAuthCallback_OnAcquireInfo_0100
 * @tc.desc: OnAcquireInfo with not nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, IDMAuthCallback_OnAcquireInfo_0100, TestSize.Level0)
{
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    CredentialParameters credInfo = {};
    Attributes extraInfo;
    auto idmAuthCallback = std::make_shared<IDMAuthCallback>(TEST_USER_ID, credInfo, 0, extraInfo, callback);
    EXPECT_TRUE(idmAuthCallback->idmCallback_ != nullptr);
    idmAuthCallback->OnAcquireInfo(TEST_MODULE, TEST_MODULE, extraInfo);
    EXPECT_EQ(0, callback->module_);
    EXPECT_EQ(0, callback->acquireInfo_);
}

/**
 * @tc.name: AddCredCallback_OnResult_0100
 * @tc.desc: OnResult with nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, AddCredCallback_OnResult_0100, TestSize.Level0)
{
    CredentialParameters credInfo = {};
    Attributes extraInfo;
    auto addCredCallback = std::make_shared<AddCredCallback>(TEST_USER_ID, credInfo, nullptr);
    EXPECT_TRUE(addCredCallback->innerCallback_ == nullptr);
    addCredCallback->OnResult(0, extraInfo);
}

/**
 * @tc.name: AddCredCallback_OnResult_0200
 * @tc.desc: OnResult with PIN.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, AddCredCallback_OnResult_0200, TestSize.Level0)
{
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    CredentialParameters credInfo = {};
    credInfo.authType = AuthType::PIN;
    Attributes extraInfo;
    auto addCredCallback = std::make_shared<AddCredCallback>(TEST_USER_ID, credInfo, callback);
    EXPECT_TRUE(addCredCallback->innerCallback_ != nullptr);
    int32_t errCode = 0;
    addCredCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(ResultCode::FAIL, callback->result_);
    errCode = 10;
    addCredCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(errCode, callback->result_);
}

/**
 * @tc.name: AddCredCallback_OnResult_0300
 * @tc.desc: OnResult with not PIN.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, AddCredCallback_OnResult_0300, TestSize.Level0)
{
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    CredentialParameters credInfo = {};
    credInfo.authType = AuthType::FACE;
    Attributes extraInfo;
    auto addCredCallback = std::make_shared<AddCredCallback>(TEST_USER_ID, credInfo, callback);
    EXPECT_TRUE(addCredCallback->innerCallback_ != nullptr);
    int32_t errCode = 0;
    addCredCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(errCode, callback->result_);
    errCode = 10;
    addCredCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(errCode, callback->result_);
}

/**
 * @tc.name: AddCredCallback_OnAcquireInfo_0100
 * @tc.desc: OnAcquireInfo with nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, AddCredCallback_OnAcquireInfo_0100, TestSize.Level0)
{
    CredentialParameters credInfo = {};
    Attributes extraInfo;
    auto addCredCallback = std::make_shared<AddCredCallback>(TEST_USER_ID, credInfo, nullptr);
    EXPECT_TRUE(addCredCallback->innerCallback_ == nullptr);
    addCredCallback->OnAcquireInfo(0, 0, extraInfo);
}

/**
 * @tc.name: AddCredCallback_OnAcquireInfo_0200
 * @tc.desc: OnAcquireInfo with not nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, AddCredCallback_OnAcquireInfo_0200, TestSize.Level0)
{
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    CredentialParameters credInfo = {};
    Attributes extraInfo;
    auto addCredCallback = std::make_shared<AddCredCallback>(TEST_USER_ID, credInfo, callback);
    EXPECT_TRUE(addCredCallback->innerCallback_ != nullptr);
    addCredCallback->OnAcquireInfo(TEST_MODULE, TEST_ACQUIRE_INFO, extraInfo);
    EXPECT_EQ(TEST_MODULE, callback->module_);
    EXPECT_EQ(TEST_ACQUIRE_INFO, callback->acquireInfo_);
}

/**
 * @tc.name: UpdateCredCallback_OnResult_0100
 * @tc.desc: OnResult with nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, UpdateCredCallback_OnResult_0100, TestSize.Level0)
{
    CredentialParameters credInfo = {};
    Attributes extraInfo;
    auto updateCredCallback = std::make_shared<UpdateCredCallback>(TEST_USER_ID, credInfo, nullptr);
    EXPECT_TRUE(updateCredCallback->innerCallback_ == nullptr);
    updateCredCallback->OnResult(0, extraInfo);
}

/**
 * @tc.name: UpdateCredCallback_OnResult_0200
 * @tc.desc: OnResult with PIN.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, UpdateCredCallback_OnResult_0200, TestSize.Level0)
{
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    CredentialParameters credInfo = {};
    credInfo.authType = AuthType::PIN;
    Attributes extraInfo;
    auto updateCredCallback = std::make_shared<UpdateCredCallback>(TEST_USER_ID, credInfo, callback);
    EXPECT_TRUE(updateCredCallback->innerCallback_ != nullptr);
    IAMState state = InnerAccountIAMManager::GetInstance().GetState(TEST_USER_ID);
    InnerAccountIAMManager::GetInstance().SetState(TEST_USER_ID, ROLL_BACK_UPDATE_CRED);
    int32_t errCode = 0;
    updateCredCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(ResultCode::FAIL, callback->result_);
    errCode = 10;
    updateCredCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(errCode, callback->result_);
    InnerAccountIAMManager::GetInstance().SetState(TEST_USER_ID, state);
}

/**
 * @tc.name: UpdateCredCallback_OnResult_0300
 * @tc.desc: OnResult with not PIN.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, UpdateCredCallback_OnResult_0300, TestSize.Level0)
{
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    CredentialParameters credInfo = {};
    credInfo.authType = AuthType::FACE;
    Attributes extraInfo;
    auto updateCredCallback = std::make_shared<UpdateCredCallback>(TEST_USER_ID, credInfo, callback);
    EXPECT_TRUE(updateCredCallback->innerCallback_ != nullptr);
    IAMState state = InnerAccountIAMManager::GetInstance().GetState(TEST_USER_ID);
    InnerAccountIAMManager::GetInstance().SetState(TEST_USER_ID, IDLE);
    int32_t errCode = 0;
    updateCredCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(errCode, callback->result_);
    errCode = 10;
    updateCredCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(errCode, callback->result_);
    InnerAccountIAMManager::GetInstance().SetState(TEST_USER_ID, state);
}

/**
 * @tc.name: UpdateCredCallback_OnAcquireInfo_0100
 * @tc.desc: OnAcquireInfo with nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, UpdateCredCallback_OnAcquireInfo_0100, TestSize.Level0)
{
    CredentialParameters credInfo = {};
    Attributes extraInfo;
    auto updateCredCallback = std::make_shared<UpdateCredCallback>(TEST_USER_ID, credInfo, nullptr);
    EXPECT_TRUE(updateCredCallback->innerCallback_ == nullptr);
    updateCredCallback->OnAcquireInfo(0, 0, extraInfo);
}

/**
 * @tc.name: UpdateCredCallback_OnAcquireInfo_0200
 * @tc.desc: OnAcquireInfo with not nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, UpdateCredCallback_OnAcquireInfo_0200, TestSize.Level0)
{
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    CredentialParameters credInfo = {};
    Attributes extraInfo;
    auto updateCredCallback = std::make_shared<UpdateCredCallback>(TEST_USER_ID, credInfo, callback);
    EXPECT_TRUE(updateCredCallback->innerCallback_ != nullptr);
    updateCredCallback->OnAcquireInfo(TEST_MODULE, TEST_ACQUIRE_INFO, extraInfo);
    EXPECT_EQ(TEST_MODULE, callback->module_);
    EXPECT_EQ(TEST_ACQUIRE_INFO, callback->acquireInfo_);
}

/**
 * @tc.name: DelCredCallback_OnResult_0100
 * @tc.desc: OnResult with nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, DelCredCallback_OnResult_0100, TestSize.Level0)
{
    Attributes extraInfo;
    std::vector<uint8_t> authToken;
    auto delCredCallback = std::make_shared<DelCredCallback>(TEST_USER_ID, 0, authToken, nullptr);
    EXPECT_TRUE(delCredCallback->innerCallback_ == nullptr);
    delCredCallback->OnResult(0, extraInfo);
}

/**
 * @tc.name: DelCredCallback_OnResult_0200
 * @tc.desc: OnResult with PIN.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, DelCredCallback_OnResult_0200, TestSize.Level0)
{
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    Attributes extraInfo;
    std::vector<uint8_t> authToken;
    auto delCredCallback = std::make_shared<DelCredCallback>(TEST_USER_ID, 0, authToken, callback);
    EXPECT_TRUE(delCredCallback->innerCallback_ != nullptr);
    IAMState state = InnerAccountIAMManager::GetInstance().GetState(TEST_USER_ID);
    InnerAccountIAMManager::GetInstance().SetState(TEST_USER_ID, ROLL_BACK_ADD_CRED);
    int32_t errCode = 0;
    delCredCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(ResultCode::FAIL, callback->result_);
    errCode = 10;
    delCredCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(errCode, callback->result_);
    InnerAccountIAMManager::GetInstance().SetState(TEST_USER_ID, state);
}

/**
 * @tc.name: DelCredCallback_OnResult_0300
 * @tc.desc: OnResult with not PIN.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, DelCredCallback_OnResult_0300, TestSize.Level0)
{
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    Attributes extraInfo;
    std::vector<uint8_t> authToken;
    auto delCredCallback = std::make_shared<DelCredCallback>(TEST_USER_ID, 0, authToken, callback);
    EXPECT_TRUE(delCredCallback->innerCallback_ != nullptr);
    IAMState state = InnerAccountIAMManager::GetInstance().GetState(TEST_USER_ID);
    InnerAccountIAMManager::GetInstance().SetState(TEST_USER_ID, IDLE);
    int32_t errCode = 0;
    delCredCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(errCode, callback->result_);
    errCode = 10;
    delCredCallback->OnResult(errCode, extraInfo);
    EXPECT_EQ(errCode, callback->result_);
    InnerAccountIAMManager::GetInstance().SetState(TEST_USER_ID, state);
}

/**
 * @tc.name: DelCredCallback_OnAcquireInfo_0100
 * @tc.desc: OnAcquireInfo with nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, DelCredCallback_OnAcquireInfo_0100, TestSize.Level0)
{
    Attributes extraInfo;
    std::vector<uint8_t> authToken;
    auto delCredCallback = std::make_shared<DelCredCallback>(TEST_USER_ID, 0, authToken, nullptr);
    EXPECT_TRUE(delCredCallback->innerCallback_ == nullptr);
    delCredCallback->OnAcquireInfo(0, 0, extraInfo);
}

/**
 * @tc.name: DelCredCallback_OnAcquireInfo_0200
 * @tc.desc: OnAcquireInfo with not nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, DelCredCallback_OnAcquireInfo_0200, TestSize.Level0)
{
    sptr<MockIIDMCallback> callback = new (std::nothrow) MockIIDMCallback();
    Attributes extraInfo;
    std::vector<uint8_t> authToken;
    auto delCredCallback = std::make_shared<DelCredCallback>(TEST_USER_ID, 0, authToken, callback);
    EXPECT_TRUE(delCredCallback->innerCallback_ != nullptr);
    delCredCallback->OnAcquireInfo(TEST_MODULE, TEST_ACQUIRE_INFO, extraInfo);
    EXPECT_EQ(TEST_MODULE, callback->module_);
    EXPECT_EQ(TEST_ACQUIRE_INFO, callback->acquireInfo_);
}

/**
 * @tc.name: GetCredInfoCallbackWrapper_OnCredentialInfo_0100
 * @tc.desc: OnCredentialInfo with nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, GetCredInfoCallbackWrapper_OnCredentialInfo_0100, TestSize.Level0)
{
    auto getCredInfoCallback = std::make_shared<GetCredInfoCallbackWrapper>(0, 0, nullptr);
    EXPECT_TRUE(getCredInfoCallback->innerCallback_ == nullptr);
    std::vector<CredentialInfo> infoList;
    getCredInfoCallback->OnCredentialInfo(infoList);
}

/**
 * @tc.name: GetPropCallbackWrapper_OnResult_0100
 * @tc.desc: OnResult with nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, GetPropCallbackWrapper_OnResult_0100, TestSize.Level0)
{
    Attributes extraInfo;
    auto getPropCallback = std::make_shared<GetPropCallbackWrapper>(nullptr);
    EXPECT_TRUE(getPropCallback->innerCallback_ == nullptr);
    getPropCallback->OnResult(0, extraInfo);
}

/**
 * @tc.name: GetCredInfoCallbackWrapper_OnCredentialInfo_0200
 * @tc.desc: OnCredentialInfo with domain auth plugin not available.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, GetCredInfoCallbackWrapper_OnCredentialInfo_0200, TestSize.Level0)
{
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "zhangsan";
    domainInfo.domain_ = "china.example.com";
    OsAccountInfo accountInfo;
    std::vector<CredentialInfo> infoList = {};
    ErrCode errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo, accountInfo);
    EXPECT_EQ(errCode, ERR_OK);
    sptr<MockGetCredInfoCallbackService> service = new (std::nothrow) MockGetCredInfoCallbackService();
    int32_t userId = accountInfo.GetLocalId();
    auto authType = static_cast<int32_t>(IAMAuthType::DOMAIN);
    auto callback = std::make_shared<GetCredInfoCallbackWrapper>(userId, authType, service);
    EXPECT_TRUE(callback->innerCallback_ != nullptr);
    UserIdmClient::GetInstance().GetCredentialInfo(userId, AuthType::ALL, callback);
    callback->OnCredentialInfo(infoList);
    EXPECT_EQ(infoList.size(), 0);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(accountInfo.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: GetCredInfoCallbackWrapper_OnCredentialInfo_0300
 * @tc.desc: OnCredentialInfo with domain auth plugin available.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, GetCredInfoCallbackWrapper_OnCredentialInfo_0300, TestSize.Level0)
{
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "lisi";
    domainInfo.domain_ = "china.example.com";
    OsAccountInfo accountInfo;
    std::vector<CredentialInfo> infoList = {static_cast<int32_t>(IAMAuthType::DOMAIN), 0, 0};
    ErrCode errCode = OsAccountManager::CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo, accountInfo);
    EXPECT_EQ(errCode, ERR_OK);
    sptr<MockGetCredInfoCallbackService> service = new (std::nothrow) MockGetCredInfoCallbackService();
    int32_t userId = accountInfo.GetLocalId();
    auto authType = static_cast<int32_t>(IAMAuthType::DOMAIN);
    auto callback = std::make_shared<GetCredInfoCallbackWrapper>(userId, authType, service);
    EXPECT_TRUE(callback->innerCallback_ != nullptr);
    std::shared_ptr<MockDomainPlugin> g_plugin = std::make_shared<MockDomainPlugin>();
    ASSERT_EQ(DomainAccountClient::GetInstance().RegisterPlugin(g_plugin), ERR_OK);
    UserIdmClient::GetInstance().GetCredentialInfo(userId, AuthType::ALL, callback);
    callback->OnCredentialInfo(infoList);
    EXPECT_EQ(infoList.size(), 1);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(accountInfo.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: GetCredInfoCallbackWrapper_OnCredentialInfo_0400
 * @tc.desc: OnCredentialInfo with not domain authtype.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, GetCredInfoCallbackWrapper_OnCredentialInfo_0400, TestSize.Level0)
{
    OsAccountInfo accountInfo;
    std::vector<CredentialInfo> infoList = {};
    sptr<MockGetCredInfoCallbackService> service = new (std::nothrow) MockGetCredInfoCallbackService();
    int32_t userId = accountInfo.GetLocalId();
    auto authType = static_cast<int32_t>(AuthType::PIN);
    auto callback = std::make_shared<GetCredInfoCallbackWrapper>(userId, authType, service);
    EXPECT_TRUE(callback->innerCallback_ != nullptr);
    UserIdmClient::GetInstance().GetCredentialInfo(userId, AuthType::PIN, callback);
    callback->OnCredentialInfo(infoList);
    EXPECT_EQ(infoList.size(), 0);
}

/**
 * @tc.name: SetPropCallbackWrapper_OnResult_0100
 * @tc.desc: OnResult with nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamCallbackTest, SetPropCallbackWrapper_OnResult_0100, TestSize.Level0)
{
    Attributes extraInfo;
    auto setPropCallback = std::make_shared<SetPropCallbackWrapper>(nullptr);
    EXPECT_TRUE(setPropCallback->innerCallback_ == nullptr);
    setPropCallback->OnResult(0, extraInfo);
}
} // namespace AccountTest
} // namespace OHOS