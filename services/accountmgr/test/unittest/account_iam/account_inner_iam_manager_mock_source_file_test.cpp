/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <gtest/gtest.h>
#include <pthread.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "accesstoken_kit.h"
#include "account_error_no.h"
#include "account_iam_callback_stub.h"
#include "account_log_wrapper.h"
#include "account_test_common.h"
#define private public
#include "account_iam_callback.h"
#include "domain_account_plugin_stub.h"
#include "iinner_os_account_manager.h"
#include "inner_account_iam_manager.h"
#include "os_account_info.h"
#include "os_account_manager.h"
#undef private
#include "iam_common_defines.h"
#include "istorage_manager.h"
#include "parameter.h"
#include "token_setproc.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;
using namespace Security::AccessToken;
using namespace OHOS::EventFwk;

namespace OHOS {
namespace AccountTest {
namespace {
const int32_t TEST_EXIST_ID = 100;
const int32_t TEST_USER_ID = 101;
const std::vector<uint8_t> TEST_CHALLENGE = {1, 2, 3, 4};
const uid_t ACCOUNT_UID = 3058;
const int32_t WAIT_TIME = 20;
const int32_t WAIT_TIME_OUT = 5;
#ifdef DOMAIN_ACCOUNT_TEST_CASE
const int32_t INFO_LIST_SIZE_ZERO = 0;
const int32_t INFO_LIST_SIZE_ONE = 1;
#endif // DOMAIN_ACCOUNT_TEST_CASE
}

class AccountIamManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AccountIamManagerTest::SetUpTestCase()
{
    ASSERT_TRUE(MockTokenId("accountmgr"));
    setuid(ACCOUNT_UID);
}

void AccountIamManagerTest::TearDownTestCase()
{
    std::cout << "AccountIamManagerTest::TearDownTestCase" << std::endl;
}

void AccountIamManagerTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void AccountIamManagerTest::TearDown()
{}

class MockIIDMCallback : public IDMCallbackStub {
public:
    MOCK_METHOD2(OnResult, void(int32_t result, const AccountSA::Attributes &extraInfo));
    MOCK_METHOD3(OnAcquireInfo, void(int32_t module, uint32_t acquireInfo, const AccountSA::Attributes &extraInfo));
};

class TestIIDMCallback : public IDMCallbackStub {
public:
    explicit TestIIDMCallback(const std::shared_ptr<MockIIDMCallback> &callback) : callback_(callback)
    {}
    void OnResult(int32_t result, const AccountSA::Attributes &extraInfo)
    {
        callback_->OnResult(result, extraInfo);
        std::unique_lock<std::mutex> lock(mutex_);
        result_ = result;
        isReady_ = true;
        cv_.notify_one();
        return;
    }
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const AccountSA::Attributes &extraInfo)
    {
        callback_->OnAcquireInfo(module, acquireInfo, extraInfo);
    }
    std::condition_variable cv_;
    bool isReady_ = false;
    std::mutex mutex_;
    int32_t result_ = -1;

private:
    std::shared_ptr<MockIIDMCallback> callback_;
};

/**
 * @tc.name: TestAddCred001
 * @tc.desc: test auth when the callback is not remote object.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, TestAddCred001, TestSize.Level3)
{
    CredentialParameters testPara = {};
    testPara.authType = AuthType::PIN;
    std::shared_ptr<MockIIDMCallback> callback = std::make_shared<MockIIDMCallback>();
    EXPECT_NE(callback, nullptr);
    sptr<TestIIDMCallback> testCallback = new(std::nothrow) TestIIDMCallback(callback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*callback, OnResult(_, _)).Times(Exactly(0));
    InnerAccountIAMManager::GetInstance().AddCredential(TEST_USER_ID, testPara, testCallback);
    std::unique_lock<std::mutex> lock(testCallback->mutex_);
    testCallback->cv_.wait_for(
        lock, std::chrono::seconds(WAIT_TIME_OUT), [lockCallback = testCallback]() { return lockCallback->isReady_; });
    EXPECT_NE(testCallback->result_, ERR_OK);
}

/**
 * @tc.name: DelUser001
 * @tc.desc: Delete user with token is empty.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, DelUser001, TestSize.Level3)
{
    std::vector<uint8_t> testAuthToken = {};
    std::shared_ptr<MockIIDMCallback> callback = std::make_shared<MockIIDMCallback>();
    EXPECT_NE(callback, nullptr);
    sptr<TestIIDMCallback> testCallback = new(std::nothrow) TestIIDMCallback(callback);
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*callback, OnResult(_, _)).Times(Exactly(1));
    InnerAccountIAMManager::GetInstance().DelUser(TEST_USER_ID, testAuthToken, testCallback);
    {
        std::unique_lock<std::mutex> lock(testCallback->mutex_);
        testCallback->cv_.wait_for(
            lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady_; });
    }
    EXPECT_EQ(testCallback->result_, ResultCode::FAIL);
}

#ifdef DOMAIN_ACCOUNT_TEST_CASE
class MockDomainPlugin : public DomainAccountPluginStub {
public:
    MockDomainPlugin();
    virtual ~MockDomainPlugin();
    ErrCode Auth(const DomainAccountInfo &info, const std::vector<uint8_t> &password,
        const sptr<IDomainAccountCallback> &callback) override;
    ErrCode AuthWithPopup(const DomainAccountInfo &info, const sptr<IDomainAccountCallback> &callback) override;
    ErrCode AuthWithToken(const DomainAccountInfo &info, const std::vector<uint8_t> &token,
        const sptr<IDomainAccountCallback> &callback) override;
    ErrCode GetAuthStatusInfo(const DomainAccountInfo &info, const sptr<IDomainAccountCallback> &callback) override;
    ErrCode GetDomainAccountInfo(const GetDomainAccountInfoOptions &options,
        const sptr<IDomainAccountCallback> &callback) override;
    ErrCode OnAccountBound(const DomainAccountInfo &info, const int32_t localId,
        const sptr<IDomainAccountCallback> &callback) override;
    ErrCode OnAccountUnBound(const DomainAccountInfo &info, const sptr<IDomainAccountCallback> &callback) override;
    ErrCode IsAccountTokenValid(const DomainAccountInfo &info, const std::vector<uint8_t> &token,
        const sptr<IDomainAccountCallback> &callback) override;
    ErrCode GetAccessToken(const DomainAccountInfo &domainInfo, const std::vector<uint8_t> &accountToken,
        const GetAccessTokenOptions &option, const sptr<IDomainAccountCallback> &callback) override;
};

MockDomainPlugin::MockDomainPlugin()
{}

MockDomainPlugin::~MockDomainPlugin()
{}

ErrCode MockDomainPlugin::Auth(const DomainAccountInfo &info, const std::vector<uint8_t> &password,
    const sptr<IDomainAccountCallback> &callback)
{
    ACCOUNT_LOGI("Mock enter.");
    return ERR_OK;
}

ErrCode MockDomainPlugin::AuthWithPopup(const DomainAccountInfo &info, const sptr<IDomainAccountCallback> &callback)
{
    ACCOUNT_LOGI("Mock enter.");
    return ERR_OK;
}

ErrCode MockDomainPlugin::AuthWithToken(const DomainAccountInfo &info, const std::vector<uint8_t> &token,
    const sptr<IDomainAccountCallback> &callback)
{
    ACCOUNT_LOGI("Mock enter.");
    return ERR_OK;
}

ErrCode MockDomainPlugin::GetAuthStatusInfo(const DomainAccountInfo &info, const sptr<IDomainAccountCallback> &callback)
{
    ACCOUNT_LOGI("Mock enter.");
    Parcel testParcel;
    AuthStatusInfo authInfo;
    authInfo.remainingTimes = 5; // test remainingTimes return 5.
    authInfo.freezingTime = 10; // test freezingTime return 10.
    authInfo.Marshalling(testParcel);
    callback->OnResult(ERR_OK, testParcel);
    return ERR_OK;
}

ErrCode MockDomainPlugin::GetDomainAccountInfo(const GetDomainAccountInfoOptions &options,
    const sptr<IDomainAccountCallback> &callback)
{
    ACCOUNT_LOGI("Mock enter.");
    return ERR_OK;
}

ErrCode MockDomainPlugin::OnAccountBound(const DomainAccountInfo &info, const int32_t localId,
    const sptr<IDomainAccountCallback> &callback)
{
    ACCOUNT_LOGI("Mock enter.");
    return ERR_OK;
}

ErrCode MockDomainPlugin::OnAccountUnBound(const DomainAccountInfo &info, const sptr<IDomainAccountCallback> &callback)
{
    ACCOUNT_LOGI("Mock enter.");
    return ERR_OK;
}

ErrCode MockDomainPlugin::IsAccountTokenValid(const DomainAccountInfo &info, const std::vector<uint8_t> &token,
    const sptr<IDomainAccountCallback> &callback)
{
    ACCOUNT_LOGI("Mock enter.");
    return ERR_OK;
}

ErrCode MockDomainPlugin::GetAccessToken(const DomainAccountInfo &domainInfo, const std::vector<uint8_t> &accountToken,
    const GetAccessTokenOptions &option, const sptr<IDomainAccountCallback> &callback)
{
    ACCOUNT_LOGI("Mock enter.");
    return ERR_OK;
}


class MockGetCredInfoCallback {
public:
    MOCK_METHOD1(OnResult, void(int32_t result));
};

class TestGetCredInfoCallback : public GetCredInfoCallbackStub {
public:
    explicit TestGetCredInfoCallback(const std::shared_ptr<MockGetCredInfoCallback> &callback) : callback_(callback)
    {}
    void OnCredentialInfo(int32_t result, const std::vector<CredentialInfo> &infoList)
    {
        int infoListSize = infoList.size();
        callback_->OnResult(infoListSize);
        std::unique_lock<std::mutex> lock(mutex_);
        isReady_ = true;
        result_ = result;
        infoList_ = infoList;
        cv_.notify_one();
        return;
    }
    std::condition_variable cv_;
    bool isReady_ = false;
    std::mutex mutex_;
    std::vector<CredentialInfo> infoList_;
    int32_t result_ = -1;

private:
    std::shared_ptr<MockGetCredInfoCallback> callback_;
};

/**
 * @tc.name: GetCredInfoCallbackWrapper_GetCredentialInfo_0100
 * @tc.desc: GetCredentialInfo with domain authType and account not exist.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, GetCredInfoCallbackWrapper_GetCredentialInfo_0100, TestSize.Level3)
{
    IInnerOsAccountManager::GetInstance().osAccountControl_->DelOsAccount(TEST_USER_ID);
    std::shared_ptr<MockGetCredInfoCallback> callback = std::make_shared<MockGetCredInfoCallback>();
    ASSERT_NE(callback, nullptr);
    sptr<TestGetCredInfoCallback> testCallback = new (std::nothrow) TestGetCredInfoCallback(callback);
    ASSERT_NE(testCallback, nullptr);
    EXPECT_CALL(*callback, OnResult(INFO_LIST_SIZE_ZERO)).Times(1);
    InnerDomainAccountManager::GetInstance().UnregisterPlugin();
    InnerAccountIAMManager::GetInstance().GetCredentialInfo(
        TEST_USER_ID, static_cast<AuthType>(IAMAuthType::DOMAIN), testCallback);
    std::unique_lock<std::mutex> lock(testCallback->mutex_);
    testCallback->cv_.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady_; });
EXPECT_EQ(testCallback->result_, ERR_OK);
}

/**
 * @tc.name: GetCredInfoCallbackWrapper_GetCredentialInfo_0200
 * @tc.desc: GetCredentialInfo with domain auth plugin not available.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, GetCredInfoCallbackWrapper_GetCredentialInfo_0200, TestSize.Level3)
{
    IInnerOsAccountManager::GetInstance().osAccountControl_->DelOsAccount(TEST_USER_ID);
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "GetCredentialInfo_0200_domain";
    domainInfo.domain_ = "test.example.com";
    OsAccountInfo osAccountInfo(TEST_USER_ID, "GetCredentialInfo_0200", OsAccountType::NORMAL, 0);
    osAccountInfo.SetIsCreateCompleted(true);
    osAccountInfo.SetDomainInfo(domainInfo);
    ASSERT_EQ(IInnerOsAccountManager::GetInstance().osAccountControl_->InsertOsAccount(osAccountInfo), ERR_OK);
    std::shared_ptr<MockGetCredInfoCallback> callback = std::make_shared<MockGetCredInfoCallback>();
    ASSERT_NE(callback, nullptr);
    sptr<TestGetCredInfoCallback> testCallback = new (std::nothrow) TestGetCredInfoCallback(callback);
    ASSERT_NE(testCallback, nullptr);
    EXPECT_CALL(*callback, OnResult(INFO_LIST_SIZE_ZERO)).Times(1);
    InnerDomainAccountManager::GetInstance().UnregisterPlugin();
    InnerAccountIAMManager::GetInstance().GetCredentialInfo(
        TEST_USER_ID, static_cast<AuthType>(IAMAuthType::DOMAIN), testCallback);
    std::unique_lock<std::mutex> lock(testCallback->mutex_);
    testCallback->cv_.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady_; });
    IInnerOsAccountManager::GetInstance().osAccountControl_->DelOsAccount(TEST_USER_ID);
    EXPECT_EQ(testCallback->result_, ERR_OK);
}

/**
 * @tc.name: GetCredInfoCallbackWrapper_GetCredentialInfo_0300
 * @tc.desc: GetCredentialInfo with domain auth plugin available.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, GetCredInfoCallbackWrapper_GetCredentialInfo_0300, TestSize.Level3)
{
    IInnerOsAccountManager::GetInstance().osAccountControl_->DelOsAccount(TEST_USER_ID);
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "GetCredentialInfo_0300_domain";
    domainInfo.domain_ = "test.example.com";
    OsAccountInfo osAccountInfo(TEST_USER_ID, "GetCredentialInfo_0300", OsAccountType::NORMAL, 0);
    osAccountInfo.SetIsCreateCompleted(true);
    osAccountInfo.SetDomainInfo(domainInfo);
    ASSERT_EQ(IInnerOsAccountManager::GetInstance().osAccountControl_->InsertOsAccount(osAccountInfo), ERR_OK);
    sptr<MockDomainPlugin> mockPlugin = new (std::nothrow) MockDomainPlugin();
    ASSERT_EQ(InnerDomainAccountManager::GetInstance().RegisterPlugin(mockPlugin), ERR_OK);
    std::shared_ptr<MockGetCredInfoCallback> callback = std::make_shared<MockGetCredInfoCallback>();
    sptr<TestGetCredInfoCallback> testCallback = new (std::nothrow) TestGetCredInfoCallback(callback);
    ASSERT_NE(testCallback, nullptr);
    EXPECT_CALL(*callback, OnResult(INFO_LIST_SIZE_ONE)).Times(Exactly(1));
    InnerAccountIAMManager::GetInstance().GetCredentialInfo(
        TEST_USER_ID, static_cast<AuthType>(IAMAuthType::DOMAIN), testCallback);
    std::unique_lock<std::mutex> lock(testCallback->mutex_);
    testCallback->cv_.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady_; });
    ASSERT_NE(testCallback->infoList_.size(), 0);
    EXPECT_EQ(testCallback->infoList_[0].authType, static_cast<AuthType>(IAMAuthType::DOMAIN));
    EXPECT_EQ(testCallback->infoList_[0].pinType, static_cast<PinSubType>(IAMAuthSubType::DOMAIN_MIXED));
    IInnerOsAccountManager::GetInstance().osAccountControl_->DelOsAccount(TEST_USER_ID);
    ASSERT_EQ(InnerDomainAccountManager::GetInstance().UnregisterPlugin(), ERR_OK);
}

/**
 * @tc.name: GetCredInfoCallbackWrapper_GetCredentialInfo_0400
 * @tc.desc: GetCredentialInfo with all authtype.
 * @tc.type: FUNC
 * @tc.require: issuesI64KAM
 */
HWTEST_F(AccountIamManagerTest, GetCredInfoCallbackWrapper_GetCredentialInfo_0400, TestSize.Level3)
{
    IInnerOsAccountManager::GetInstance().osAccountControl_->DelOsAccount(TEST_USER_ID);
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "GetCredentialInfo_0400_domain";
    domainInfo.domain_ = "test.example.com";
    OsAccountInfo osAccountInfo(TEST_USER_ID, "GetCredentialInfo_0400", OsAccountType::NORMAL, 0);
    osAccountInfo.SetIsCreateCompleted(true);
    osAccountInfo.SetDomainInfo(domainInfo);
    ASSERT_EQ(IInnerOsAccountManager::GetInstance().osAccountControl_->InsertOsAccount(osAccountInfo), ERR_OK);
    sptr<MockDomainPlugin> mockPlugin = new (std::nothrow) MockDomainPlugin();
    ASSERT_EQ(InnerDomainAccountManager::GetInstance().RegisterPlugin(mockPlugin), ERR_OK);
    std::shared_ptr<MockGetCredInfoCallback> callback = std::make_shared<MockGetCredInfoCallback>();
    ASSERT_NE(callback, nullptr);
    sptr<TestGetCredInfoCallback> testCallback = new (std::nothrow) TestGetCredInfoCallback(callback);
    ASSERT_NE(testCallback, nullptr);
    EXPECT_CALL(*callback, OnResult(INFO_LIST_SIZE_ONE)).Times(Exactly(1));
    InnerAccountIAMManager::GetInstance().GetCredentialInfo(TEST_USER_ID, AuthType::ALL, testCallback);
    std::unique_lock<std::mutex> lock(testCallback->mutex_);
    testCallback->cv_.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady_; });
    ASSERT_NE(testCallback->infoList_.size(), 0);
    EXPECT_EQ(testCallback->infoList_[0].authType, static_cast<AuthType>(IAMAuthType::DOMAIN));
    EXPECT_EQ(testCallback->infoList_[0].pinType, static_cast<PinSubType>(IAMAuthSubType::DOMAIN_MIXED));
    IInnerOsAccountManager::GetInstance().osAccountControl_->DelOsAccount(TEST_USER_ID);
    ASSERT_EQ(InnerDomainAccountManager::GetInstance().UnregisterPlugin(), ERR_OK);
}

/**
 * @tc.name: GetAvailableStatus_0100
 * @tc.desc: GetAvailableStatus with domain auth plugin not available.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, GetAvailableStatus_0100, TestSize.Level3)
{
    ASSERT_EQ(InnerDomainAccountManager::GetInstance().UnregisterPlugin(), ERR_OK);
    int32_t status = 0;
    int32_t ret = InnerAccountIAMManager::GetInstance().GetAvailableStatus(
        static_cast<AuthType>(IAMAuthType::DOMAIN), AuthTrustLevel::ATL1, status);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(status, ERR_JS_AUTH_TYPE_NOT_SUPPORTED);
}

 /**
  * @tc.name: GetAvailableStatus_0200
  * @tc.desc: GetAvailableStatus with domain auth plugin available.
  * @tc.type: FUNC
  * @tc.require:
  */
HWTEST_F(AccountIamManagerTest, GetAvailableStatus_0200, TestSize.Level3)
{
    sptr<MockDomainPlugin> mockPlugin = new (std::nothrow) MockDomainPlugin();
    ASSERT_EQ(InnerDomainAccountManager::GetInstance().RegisterPlugin(mockPlugin), ERR_OK);
    int32_t status = -1;
    int32_t ret = InnerAccountIAMManager::GetInstance().GetAvailableStatus(
        static_cast<AuthType>(IAMAuthType::DOMAIN), AuthTrustLevel::ATL1, status);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(status, ERR_JS_SUCCESS);
    ASSERT_EQ(InnerDomainAccountManager::GetInstance().UnregisterPlugin(), ERR_OK);
}
#endif // DOMAIN_ACCOUNT_TEST_CASE

/**
 * @tc.name: CopyAuthParam001
 * @tc.desc: Copy auth param with normal case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, CopyAuthParam001, TestSize.Level3)
{
    AccountSA::AuthParam srcAuthParam = {
        .userId = TEST_USER_ID,
        .challenge = TEST_CHALLENGE,
        .authType = AuthType::PIN,
        .authTrustLevel = AuthTrustLevel::ATL1
    };
    UserIam::UserAuth::AuthParam testAuthParam;
    InnerAccountIAMManager::GetInstance().CopyAuthParam(srcAuthParam, testAuthParam);
    EXPECT_EQ(srcAuthParam.userId, TEST_USER_ID);
    EXPECT_EQ(srcAuthParam.challenge, TEST_CHALLENGE);
    EXPECT_EQ(srcAuthParam.authType, AuthType::PIN);
    EXPECT_EQ(srcAuthParam.authTrustLevel, AuthTrustLevel::ATL1);
}

/**
 * @tc.name: CopyAuthParam002
 * @tc.desc: Copy auth param with remote authentication case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, CopyAuthParam002, TestSize.Level3)
{
    // test remote param value is not empty
    AccountSA::AuthParam srcAuthParam = {
        .userId = TEST_USER_ID,
        .challenge = TEST_CHALLENGE,
        .authType = AuthType::PIN,
        .authTrustLevel = AuthTrustLevel::ATL1
    };
    std::optional<RemoteAuthParam> testRemoteAuthParam = RemoteAuthParam();
    testRemoteAuthParam.value().verifierNetworkId = "testVerifierNetworkId";
    testRemoteAuthParam.value().collectorNetworkId = "testCollectorNetworkId";
    testRemoteAuthParam.value().collectorTokenId = 111;
    srcAuthParam.remoteAuthParam = testRemoteAuthParam;
    UserIam::UserAuth::AuthParam testAuthParam;
    InnerAccountIAMManager::GetInstance().CopyAuthParam(srcAuthParam, testAuthParam);
    ASSERT_NE(testAuthParam.remoteAuthParam, std::nullopt);
    EXPECT_EQ(testAuthParam.remoteAuthParam.value().verifierNetworkId.value(), "testVerifierNetworkId");
    EXPECT_EQ(testAuthParam.remoteAuthParam.value().collectorNetworkId.value(), "testCollectorNetworkId");
    EXPECT_EQ(testAuthParam.remoteAuthParam.value().collectorTokenId.value(), 111);

    // test remote param value is empty
    std::optional<RemoteAuthParam> emptyRemoteAuthParam = RemoteAuthParam();;
    srcAuthParam.remoteAuthParam = emptyRemoteAuthParam;
    UserIam::UserAuth::AuthParam testEmptyRemoteAuthParam;
    InnerAccountIAMManager::GetInstance().CopyAuthParam(srcAuthParam, testEmptyRemoteAuthParam);
    ASSERT_NE(testEmptyRemoteAuthParam.remoteAuthParam, std::nullopt);
    EXPECT_EQ(testEmptyRemoteAuthParam.remoteAuthParam.value().verifierNetworkId, std::nullopt);
    EXPECT_EQ(testEmptyRemoteAuthParam.remoteAuthParam.value().collectorNetworkId, std::nullopt);
    EXPECT_EQ(testEmptyRemoteAuthParam.remoteAuthParam.value().collectorTokenId, std::nullopt);
}

class MockGetPropertyCallback {
public:
    MOCK_METHOD1(OnResult, void(int32_t result));
};

class TestGetPropertyCallback : public GetSetPropCallbackStub {
public:
    explicit TestGetPropertyCallback(const std::shared_ptr<MockGetPropertyCallback> &callback) : callback_(callback)
    {}
    void OnResult(int32_t result, const Attributes &extraInfo)
    {
        callback_->OnResult(result);
        std::unique_lock<std::mutex> lock(mutex_);
        result_ = result;
        extraInfo.GetInt32Value(Attributes::AttributeKey::ATTR_REMAIN_TIMES, remainTimes_);
        extraInfo.GetInt32Value(Attributes::AttributeKey::ATTR_FREEZING_TIME, freezingTime_);
        isReady_ = true;
        cv_.notify_one();
        return;
    }
    std::condition_variable cv_;
    bool isReady_ = false;
    std::mutex mutex_;
    int32_t result_;
    int32_t remainTimes_ = -1;
    int32_t freezingTime_ = -1;
private:
    std::shared_ptr<MockGetPropertyCallback> callback_;
};


/**
 * @tc.name: GetProperty_0100
 * @tc.desc: test get property normal case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, GetProperty_0100, TestSize.Level3)
{
    std::shared_ptr<MockGetPropertyCallback> callback = std::make_shared<MockGetPropertyCallback>();
    ASSERT_NE(callback, nullptr);
    sptr<TestGetPropertyCallback> testCallback = new (std::nothrow) TestGetPropertyCallback(callback);
    ASSERT_NE(testCallback, nullptr);
    EXPECT_CALL(*callback, OnResult(_)).Times(Exactly(1));
    // callback is nullptr
    GetPropertyRequest request;
    request.authType = AuthType::PIN;
    InnerAccountIAMManager::GetInstance().GetProperty(TEST_EXIST_ID, request, nullptr);

    // test normal case
    InnerAccountIAMManager::GetInstance().GetProperty(TEST_EXIST_ID, request, testCallback);
    std::unique_lock<std::mutex> lock(testCallback->mutex_);
    testCallback->cv_.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady_; });
    // expect return param is invalid err, because request is empty, ret = 8
    EXPECT_NE(testCallback->result_, ERR_OK);
}

#ifdef DOMAIN_ACCOUNT_TEST_CASE
/**
 * @tc.name: GetProperty_0200
 * @tc.desc: test get domain type credential property with account not domain account.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, GetProperty_0200, TestSize.Level3)
{
    OsAccountInfo osAccountInfo;
    int32_t ret = IInnerOsAccountManager::GetInstance().CreateOsAccount(
        "GetProperty_0200", OsAccountType::NORMAL, osAccountInfo);
    ASSERT_EQ(ret, 0);
    std::shared_ptr<MockGetPropertyCallback> callback = std::make_shared<MockGetPropertyCallback>();
    ASSERT_NE(callback, nullptr);
    sptr<TestGetPropertyCallback> testCallback = new (std::nothrow) TestGetPropertyCallback(callback);
    ASSERT_NE(testCallback, nullptr);
    EXPECT_CALL(*callback, OnResult(_)).Times(Exactly(1));
    GetPropertyRequest request;
    request.authType = static_cast<AuthType>(IAMAuthType::DOMAIN);
    InnerAccountIAMManager::GetInstance().GetProperty(osAccountInfo.GetLocalId(), request, testCallback);
    std::unique_lock<std::mutex> lock(testCallback->mutex_);
    testCallback->cv_.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady_; });
    EXPECT_EQ(testCallback->result_, ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE);
    ret = IInnerOsAccountManager::GetInstance().RemoveOsAccount(osAccountInfo.GetLocalId());
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: GetProperty_0300
 * @tc.desc: test get domain type credential property with account not exit.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, GetProperty_0300, TestSize.Level3)
{
    OsAccountInfo osAccountInfo;
    int32_t ret = IInnerOsAccountManager::GetInstance().CreateOsAccount(
        "GetProperty_0300", OsAccountType::NORMAL, osAccountInfo);
    ASSERT_EQ(ret, 0);
    ret = IInnerOsAccountManager::GetInstance().RemoveOsAccount(osAccountInfo.GetLocalId());
    ASSERT_EQ(ret, 0);
    std::shared_ptr<MockGetPropertyCallback> callback = std::make_shared<MockGetPropertyCallback>();
    ASSERT_NE(callback, nullptr);
    sptr<TestGetPropertyCallback> testCallback = new (std::nothrow) TestGetPropertyCallback(callback);
    ASSERT_NE(testCallback, nullptr);
    EXPECT_CALL(*callback, OnResult(_)).Times(Exactly(1));
    GetPropertyRequest request;
    request.authType = static_cast<AuthType>(IAMAuthType::DOMAIN);
    InnerAccountIAMManager::GetInstance().GetProperty(osAccountInfo.GetLocalId(), request, testCallback);
    std::unique_lock<std::mutex> lock(testCallback->mutex_);
    testCallback->cv_.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady_; });
    EXPECT_EQ(testCallback->result_, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: GetProperty_0400
 * @tc.desc: test get domain type credential property with domain account but plugin not exist.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, GetProperty_0400, TestSize.Level3)
{
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "GetProperty_0400_domain";
    domainInfo.domain_ = "test.example.com";
    OsAccountInfo osAccountInfo(TEST_USER_ID, "GetProperty_0400", OsAccountType::NORMAL, 0);
    osAccountInfo.SetIsCreateCompleted(true);
    osAccountInfo.SetDomainInfo(domainInfo);
    ASSERT_EQ(IInnerOsAccountManager::GetInstance().osAccountControl_->InsertOsAccount(osAccountInfo), ERR_OK);
    std::shared_ptr<MockGetPropertyCallback> callback = std::make_shared<MockGetPropertyCallback>();
    ASSERT_NE(callback, nullptr);
    sptr<TestGetPropertyCallback> testCallback = new (std::nothrow) TestGetPropertyCallback(callback);
    ASSERT_NE(testCallback, nullptr);
    EXPECT_CALL(*callback, OnResult(_)).Times(Exactly(1));
    GetPropertyRequest request;
    request.authType = static_cast<AuthType>(IAMAuthType::DOMAIN);
    InnerAccountIAMManager::GetInstance().GetProperty(TEST_USER_ID, request, testCallback);
    std::unique_lock<std::mutex> lock(testCallback->mutex_);
    testCallback->cv_.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady_; });
    EXPECT_EQ(testCallback->result_, ERR_JS_CAPABILITY_NOT_SUPPORTED);
    IInnerOsAccountManager::GetInstance().osAccountControl_->DelOsAccount(TEST_USER_ID);
}

/**
 * @tc.name: GetProperty_0500
 * @tc.desc: test get domain type credential property with domain account and plugin exist.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, GetProperty_0500, TestSize.Level3)
{
    DomainAccountInfo domainInfo;
    domainInfo.accountName_ = "GetProperty_0500_domain";
    domainInfo.domain_ = "test.example.com";
    OsAccountInfo osAccountInfo(TEST_USER_ID, "GetProperty_0500", OsAccountType::NORMAL, 0);
    osAccountInfo.SetIsCreateCompleted(true);
    osAccountInfo.SetDomainInfo(domainInfo);
    ASSERT_EQ(IInnerOsAccountManager::GetInstance().osAccountControl_->InsertOsAccount(osAccountInfo), ERR_OK);
    std::shared_ptr<MockGetPropertyCallback> callback = std::make_shared<MockGetPropertyCallback>();
    ASSERT_NE(callback, nullptr);
    sptr<TestGetPropertyCallback> testCallback = new (std::nothrow) TestGetPropertyCallback(callback);
    ASSERT_NE(testCallback, nullptr);
    EXPECT_CALL(*callback, OnResult(_)).Times(Exactly(1));
    sptr<MockDomainPlugin> mockPlugin = new (std::nothrow) MockDomainPlugin();
    ASSERT_EQ(InnerDomainAccountManager::GetInstance().RegisterPlugin(mockPlugin), ERR_OK);
    GetPropertyRequest request;
    request.authType = static_cast<AuthType>(IAMAuthType::DOMAIN);
    InnerAccountIAMManager::GetInstance().GetProperty(TEST_USER_ID, request, testCallback);
    std::unique_lock<std::mutex> lock(testCallback->mutex_);
    testCallback->cv_.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady_; });
    EXPECT_EQ(testCallback->result_, ERR_OK);
    EXPECT_EQ(testCallback->freezingTime_, 10);
    EXPECT_EQ(testCallback->remainTimes_, 5);
    IInnerOsAccountManager::GetInstance().osAccountControl_->DelOsAccount(TEST_USER_ID);
    ASSERT_EQ(InnerDomainAccountManager::GetInstance().UnregisterPlugin(), ERR_OK);
}
#endif // DOMAIN_ACCOUNT_TEST_CASE


/**
 * @tc.name: SetProperty_0100
 * @tc.desc: test set property with domain type.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, SetProperty_0100, TestSize.Level3)
{
    std::shared_ptr<MockGetPropertyCallback> callback = std::make_shared<MockGetPropertyCallback>();
    ASSERT_NE(callback, nullptr);
    sptr<TestGetPropertyCallback> testCallback = new (std::nothrow) TestGetPropertyCallback(callback);
    ASSERT_NE(testCallback, nullptr);
    EXPECT_CALL(*callback, OnResult(ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE)).Times(Exactly(1));
    // callback is nullptr
    SetPropertyRequest testRequestSet = {};
    testRequestSet.authType = static_cast<AuthType>(IAMAuthType::DOMAIN);
    InnerAccountIAMManager::GetInstance().SetProperty(TEST_EXIST_ID, testRequestSet, testCallback);
    std::unique_lock<std::mutex> lock(testCallback->mutex_);
    testCallback->cv_.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady_; });
    EXPECT_EQ(testCallback->result_, ERR_ACCOUNT_IAM_UNSUPPORTED_AUTH_TYPE);
}

/**
 * @tc.name: SetProperty_0200
 * @tc.desc: test set property with normal case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, SetProperty_0200, TestSize.Level3)
{
    std::shared_ptr<MockGetPropertyCallback> callback = std::make_shared<MockGetPropertyCallback>();
    ASSERT_NE(callback, nullptr);
    sptr<TestGetPropertyCallback> testCallback = new (std::nothrow) TestGetPropertyCallback(callback);
    ASSERT_NE(testCallback, nullptr);
    EXPECT_CALL(*callback, OnResult(_)).Times(Exactly(1));
    SetPropertyRequest testRequestSet = {};
    InnerAccountIAMManager::GetInstance().SetProperty(TEST_EXIST_ID, testRequestSet, testCallback);
    std::unique_lock<std::mutex> lock(testCallback->mutex_);
    testCallback->cv_.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady_; });
    // expect return param is invalid err, because request is empty
    EXPECT_NE(testCallback->result_, ERR_OK);
}

class MockGetEnrolledIdCallback {
public:
    MOCK_METHOD1(OnResult, void(uint64_t enrolledId));
};

class TestGetEnrolledIdCallback : public GetEnrolledIdCallbackStub {
public:
    explicit TestGetEnrolledIdCallback(const std::shared_ptr<MockGetEnrolledIdCallback> &callback) : callback_(callback)
    {}
    void OnEnrolledId(int32_t result, uint64_t enrolledId)
    {
        callback_->OnResult(enrolledId);
        std::unique_lock<std::mutex> lock(mutex_);
        isReady_ = true;
        result_ = result;
        cv_.notify_one();
        return;
    }
    std::condition_variable cv_;
    bool isReady_ = false;
    std::mutex mutex_;
    int32_t result_;
private:
    std::shared_ptr<MockGetEnrolledIdCallback> callback_;
};

/**
 * @tc.name: GetEnrolledId_0100
 * @tc.desc: test set property with normal case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIamManagerTest, GetEnrolledId_0100, TestSize.Level3)
{
    std::shared_ptr<MockGetEnrolledIdCallback> callback = std::make_shared<MockGetEnrolledIdCallback>();
    ASSERT_NE(callback, nullptr);
    sptr<TestGetEnrolledIdCallback> testCallback = new (std::nothrow) TestGetEnrolledIdCallback(callback);
    ASSERT_NE(testCallback, nullptr);
    EXPECT_CALL(*callback, OnResult(_)).Times(Exactly(1));
    InnerAccountIAMManager::GetInstance().GetEnrolledId(TEST_EXIST_ID, AuthType::PIN, testCallback);
    std::unique_lock<std::mutex> lock(testCallback->mutex_);
    testCallback->cv_.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady_; });
    EXPECT_EQ(testCallback->result_, ERR_IAM_NOT_ENROLLED);
}
}  // namespace AccountTest
}  // namespace OHOS
