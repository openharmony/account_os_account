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
#include <gmock/gmock.h>
#include <thread>
#include "account_log_wrapper.h"
#include "datetime_ex.h"
#define private public
#include "iinner_os_account_manager.h"
#include "os_account.h"
#include "os_account_manager_service.h"
#undef private
#include "accesstoken_kit.h"
#include "account_iam_client.h"
#include "account_log_wrapper.h"
#include "account_iam_callback.h"
#include "account_iam_mgr_proxy.h"
#include "account_iam_callback_stub.h"
#include "account_iam_callback_service.h"
#include "account_iam_client_test_callback.h"
#include "ipc_skeleton.h"
#include "iam_common_defines.h"
#include "os_account_subscriber.h"
#include "os_account_subscribe_manager.h"
#include "singleton.h"
#include "test_common.h"
#include "token_setproc.h"


using namespace testing;
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::UserIam::UserAuth;
#ifdef HAS_PIN_AUTH_PART
using namespace OHOS::UserIam::PinAuth;
#endif

namespace OHOS {
namespace AccountTest {
namespace {
std::mutex g_mtx;
std::mutex h_mtx;
}  // namespace

std::mutex addmtx;
std::mutex authmtx;
std::condition_variable cv1;
std::condition_variable cv2;

class OsAccountManagerServiceSubscribeModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
    std::shared_ptr<OsAccountManagerService> osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
};

void OsAccountManagerServiceSubscribeModuleTest::SetUpTestCase(void)
{
    IInnerOsAccountManager::GetInstance().Init();
}

void OsAccountManagerServiceSubscribeModuleTest::TearDownTestCase(void)
{
    GTEST_LOG_(INFO) << "TearDownTestCase exit!";
}

void OsAccountManagerServiceSubscribeModuleTest::SetUp(void)
{}

void OsAccountManagerServiceSubscribeModuleTest::TearDown(void)
{}

class OsAccountSubscriberTest : public OsAccountSubscriber {
public:
    explicit OsAccountSubscriberTest(const OsAccountSubscribeInfo &subscribeInfo)
        : OsAccountSubscriber(subscribeInfo), id_(0)
    {
        ACCOUNT_LOGI("enter");
    }

    ~OsAccountSubscriberTest()
    {}

    virtual void OnAccountsChanged(const int &id)
    {
        ACCOUNT_LOGI("enter");

        g_mtx.unlock();
        EXPECT_EQ(id, id_);
        GTEST_LOG_(INFO) << id;
        GTEST_LOG_(INFO) << id_;
    }
    int id_;
};
class MockOsAccountSubscriberTest final : public OsAccountSubscriber {
public:
    explicit MockOsAccountSubscriberTest(const OsAccountSubscribeInfo &subscribeInfo)
        : OsAccountSubscriber(subscribeInfo)
    {}
    MOCK_METHOD1(OnAccountsChanged, void(const int &id));
    virtual ~MockOsAccountSubscriberTest()
    {}
};

#ifdef HAS_PIN_AUTH_PART
class TestIInputer : public OHOS::AccountSA::IInputer {
public:
    explicit TestIInputer() {}
    void OnGetData(int32_t authSubType, const std::shared_ptr<IInputerData> inputerData) override
    {
        // inputer class is IAMInputerData
        std::vector<uint8_t> data = { 1, 2, 3, 4, 5, 6 };
        inputerData->OnSetData(authSubType, data);
    }
    virtual ~TestIInputer() = default;
};
#endif

class TestAuthCallBack : public OHOS::AccountSA::IDMCallback {
public:
    explicit TestAuthCallBack()
    {}
    virtual ~TestAuthCallBack()=default;
    void OnResult(int32_t result, const Attributes &extraInfo) override
    {
        cv2.notify_one();
        EXPECT_EQ(result, ERR_OK);
    }
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) override
    {}
};

class TestAddCredCallBack : public OHOS::AccountSA::IDMCallback {
public:
    explicit TestAddCredCallBack()
    {}
    virtual ~TestAddCredCallBack() = default;
    void OnResult(int32_t result, const Attributes &extraInfo) override
    {
        cv1.notify_one();
    }
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) override
    {}
};

/**
 * @tc.name: OsAccountManagerServiceSubscribeModuleTest_0001
 * @tc.desc: Subscribe os accounts activate
 * @tc.type: FUNC
 * @tc.require: SR000GGVFH
 */
HWTEST_F(OsAccountManagerServiceSubscribeModuleTest, OsAccountManagerServiceSubscribeModuleTest_0001, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceSubscribeModuleTest_0001");
    OsAccountSubscribeInfo osAccountSubscribeInfo;
    osAccountSubscribeInfo.SetOsAccountSubscribeType(OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVED);
    osAccountSubscribeInfo.SetName("subscribeActive");

    // make a subscriber
    auto subscriberTestPtr = std::make_shared<OsAccountSubscriberTest>(osAccountSubscribeInfo);

    // make an event listener
    sptr<IRemoteObject> osAccountEventListener = nullptr;

    OsAccountInfo osAccountInfo;
    ErrCode result = osAccountManagerService_->CreateOsAccount("Test_0001", OsAccountType::GUEST, osAccountInfo);
    EXPECT_EQ(result, ERR_OK);
    subscriberTestPtr->id_ = osAccountInfo.GetLocalId();
    ErrCode subscribeState = OsAccount::GetInstance().CreateOsAccountEventListener(
        subscriberTestPtr, osAccountEventListener);
    EXPECT_EQ(subscribeState, OsAccount::INITIAL_SUBSCRIPTION);

    // subscribe app account
    result = osAccountManagerService_->SubscribeOsAccount(osAccountSubscribeInfo, osAccountEventListener);
    EXPECT_EQ(result, ERR_OK);
    // lock the mutex
    g_mtx.lock();
    EXPECT_EQ(result, ERR_OK);
    result = osAccountManagerService_->ActivateOsAccount(osAccountInfo.GetLocalId());
    EXPECT_EQ(result, ERR_OK);
    struct tm startTime = {0};
    EXPECT_EQ(GetSystemCurrentTime(&startTime), true);
    struct tm doingTime = {0};
    while (!g_mtx.try_lock()) {
        EXPECT_EQ(GetSystemCurrentTime(&doingTime), true);
        int64_t seconds = GetSecondsBetween(startTime, doingTime);
        if (seconds >= 5) {
            break;
        }
    }
    g_mtx.unlock();
    result = osAccountManagerService_->UnsubscribeOsAccount(osAccountEventListener);
    EXPECT_EQ(result, ERR_OK);
    osAccountManagerService_->ActivateOsAccount(Constants::START_USER_ID);
    // unlock the mutex
    result = osAccountManagerService_->RemoveOsAccount(osAccountInfo.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerServiceSubscribeModuleTest_0002
 * @tc.desc: Subscribe os accounts unlock with no password
 * @tc.type: FUNC
 * @tc.require: issueI7WX2P
 */
HWTEST_F(OsAccountManagerServiceSubscribeModuleTest, OsAccountManagerServiceSubscribeModuleTest_0002, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceSubscribeModuleTest_0002");
    OsAccountSubscribeInfo osAccountSubscribeInfo;
    osAccountSubscribeInfo.SetOsAccountSubscribeType(OS_ACCOUNT_SUBSCRIBE_TYPE::UNLOCKED);
    osAccountSubscribeInfo.SetName("subscribeUnlock");
    // make a subscriber
    auto subscriberTestPtr = std::make_shared<MockOsAccountSubscriberTest>(osAccountSubscribeInfo);
    // create a osAccount
    OsAccountInfo osAccountInfo;
    ErrCode result = OsAccount::GetInstance().CreateOsAccount("Test_0002", OsAccountType::GUEST, osAccountInfo);
    const int id = osAccountInfo.GetLocalId();
    EXPECT_CALL(*subscriberTestPtr, OnAccountsChanged(id)).Times(Exactly(1));
    //subscribe
    result = OsAccount::GetInstance().SubscribeOsAccount(subscriberTestPtr);
    EXPECT_EQ(result, ERR_OK);
    //unlock
    result = OsAccount::GetInstance().ActivateOsAccount(id);
    EXPECT_EQ(result, ERR_OK);
    OsAccount::GetInstance().UnsubscribeOsAccount(subscriberTestPtr);
    EXPECT_EQ(result, ERR_OK);
    result = OsAccount::GetInstance().RemoveOsAccount(id);
}

#ifdef HAS_PIN_AUTH_PART
/**
 * @tc.name: OsAccountManagerServiceSubscribeModuleTest_0003
 * @tc.desc: Subscribe os accounts unlock with password
 * @tc.type: FUNC
 * @tc.require: issueI7WX2P
 */
HWTEST_F(OsAccountManagerServiceSubscribeModuleTest, OsAccountManagerServiceSubscribeModuleTest_0003, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceSubscribeModuleTest_0003");
    //set tokenId
    AccessTokenID tokenId = AccessTokenKit::GetNativeTokenId("accountmgr");
    SetSelfTokenID(tokenId);
    //set selinux
    std::string cmd = "setenforce 0";
    FILE *file = popen(cmd.c_str(), "r");
    if (file != nullptr) {
        pclose(file);
    }
    //make a subscriber
    OsAccountSubscribeInfo osAccountSubscribeInfo;
    osAccountSubscribeInfo.SetOsAccountSubscribeType(OS_ACCOUNT_SUBSCRIBE_TYPE::UNLOCKED);
    osAccountSubscribeInfo.SetName("subscribeUnlock");
    auto subscriberTestPtr = std::make_shared<MockOsAccountSubscriberTest>(osAccountSubscribeInfo);
    OsAccountInfo osAccountInfo;
    //create osAccount
    ErrCode result = OsAccount::GetInstance().CreateOsAccount("Test_0003", OsAccountType::GUEST, osAccountInfo);
    EXPECT_EQ(result, ERR_OK);
    const int id = osAccountInfo.GetLocalId();
    EXPECT_CALL(*subscriberTestPtr, OnAccountsChanged(id)).Times(Exactly(1));
    result = OsAccount::GetInstance().SubscribeOsAccount(subscriberTestPtr);
    EXPECT_EQ(result, ERR_OK);
    auto inputer = std::make_shared<TestIInputer>();
    EXPECT_NE(nullptr, inputer);
    result = AccountIAMClient::GetInstance().RegisterPINInputer(inputer);
    ASSERT_EQ(ERR_OK, result);
    //add a credential
    CredentialParameters testPara = {};
    std::vector<uint8_t> testchange = {};
    testPara.authType = AuthType::PIN;
    testPara.pinType = PinSubType::PIN_SIX;
    EXPECT_EQ(AccountIAMClient::GetInstance().OpenSession(id, testchange), ERR_OK);
    auto mockAddCredentialCallback = std::make_shared<TestAddCredCallBack>();
    EXPECT_NE(mockAddCredentialCallback, nullptr);
    std::unique_lock<std::mutex> mtx1(addmtx);
    AccountIAMClient::GetInstance().AddCredential(id, testPara, mockAddCredentialCallback);
    cv1.wait(mtx1);
    //authUser
    std::unique_lock<std::mutex> mtx2(authmtx);
    auto mockAuthCallback = std::make_shared<TestAuthCallBack>();
    AccountIAMClient::GetInstance().AuthUser(id, testchange, AuthType::PIN, AuthTrustLevel::ATL1, mockAuthCallback);
    cv2.wait(mtx2);
    //after opration
    EXPECT_EQ(AccountIAMClient::GetInstance().UnregisterPINInputer(), ERR_OK);
    EXPECT_EQ(AccountIAMClient::GetInstance().CloseSession(id), ERR_OK);
    result = OsAccount::GetInstance().UnsubscribeOsAccount(subscriberTestPtr);
    EXPECT_EQ(result, ERR_OK);
    result = OsAccount::GetInstance().RemoveOsAccount(id);
    EXPECT_EQ(result, ERR_OK);
}
#endif

/**
 * @tc.name: OsAccountManagerServiceSubscribeModuleTest_0004
 * @tc.desc: Subscribe os accounts created
 * @tc.type: FUNC
 * @tc.require: issueI7WX2P
 */
HWTEST_F(OsAccountManagerServiceSubscribeModuleTest, OsAccountManagerServiceSubscribeModuleTest_0004, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceSubscribeModuleTest_0004");
    //make a subscriber
    AccessTokenID tokenId = AccessTokenKit::GetNativeTokenId("accountmgr");
    SetSelfTokenID(tokenId);
    OsAccountSubscribeInfo osAccountSubscribeInfo;
    osAccountSubscribeInfo.SetOsAccountSubscribeType(OS_ACCOUNT_SUBSCRIBE_TYPE::CREATED);
    osAccountSubscribeInfo.SetName("subscribeCreated");
    auto subscriberTestPtr = std::make_shared<MockOsAccountSubscriberTest>(osAccountSubscribeInfo);
    //subscribe
    ErrCode result = OsAccount::GetInstance().SubscribeOsAccount(subscriberTestPtr);
    EXPECT_EQ(result, ERR_OK);
    //create osAccount
    EXPECT_CALL(*subscriberTestPtr, OnAccountsChanged(_)).Times(Exactly(1));
    OsAccountInfo osAccountInfo;
    result = OsAccount::GetInstance().CreateOsAccount("Test_0004", OsAccountType::GUEST, osAccountInfo);
    const int id = osAccountInfo.GetLocalId();
    //unsubscribe
    result = OsAccount::GetInstance().RemoveOsAccount(id);
    OsAccount::GetInstance().UnsubscribeOsAccount(subscriberTestPtr);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceSubscribeModuleTest_0005
 * @tc.desc: Subscribe os accounts removed
 * @tc.type: FUNC
 * @tc.require: issueI7WX2P
 */
HWTEST_F(OsAccountManagerServiceSubscribeModuleTest, OsAccountManagerServiceSubscribeModuleTest_0005, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceSubscribeModuleTest_0005");
    //make a subscriber
    AccessTokenID tokenId = AccessTokenKit::GetNativeTokenId("accountmgr");
    SetSelfTokenID(tokenId);
    OsAccountSubscribeInfo osAccountSubscribeInfo;
    osAccountSubscribeInfo.SetOsAccountSubscribeType(OS_ACCOUNT_SUBSCRIBE_TYPE::REMOVED);
    osAccountSubscribeInfo.SetName("subscribeCreated");
    auto subscriberTestPtr = std::make_shared<MockOsAccountSubscriberTest>(osAccountSubscribeInfo);
    //subscribe
    ErrCode result = OsAccount::GetInstance().SubscribeOsAccount(subscriberTestPtr);
    EXPECT_EQ(result, ERR_OK);
    //create osAccount
    OsAccountInfo osAccountInfo;
    result = OsAccount::GetInstance().CreateOsAccount("Test_0005", OsAccountType::GUEST, osAccountInfo);
    const int id = osAccountInfo.GetLocalId();
    EXPECT_CALL(*subscriberTestPtr, OnAccountsChanged(id)).Times(Exactly(1));
    //unsubscribe
    result = OsAccount::GetInstance().RemoveOsAccount(id);
    OsAccount::GetInstance().UnsubscribeOsAccount(subscriberTestPtr);
    EXPECT_EQ(result, ERR_OK);
}
}
}
