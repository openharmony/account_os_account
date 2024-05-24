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

#include "accesstoken_kit.h"
#define private public
#include "account_iam_callback_service.h"
#undef private
#include "account_iam_client.h"
#include "account_iam_client_test_callback.h"
#include "account_log_wrapper.h"
#include "test_common.h"
#include "token_setproc.h"

namespace OHOS {
namespace AccountTest {
namespace {
    const int32_t TEST_USER_ID = 200;
    const int32_t WAIT_TIME = 20;
}

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS::Security::AccessToken;

#ifdef HAS_PIN_AUTH_PART
class MockIInputer : public OHOS::AccountSA::IInputer {
public:
    virtual ~MockIInputer() {}
    void OnGetData(int32_t authSubType, std::vector<uint8_t> challenge,
        std::shared_ptr<IInputerData> inputerData) override
    {
        return;
    }
};
#endif

class AccountIAMCallbackServiceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void AccountIAMCallbackServiceTest::SetUpTestCase(void)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(100, "com.ohos.settings", 0);
    SetSelfTokenID(tokenId);
}

void AccountIAMCallbackServiceTest::TearDownTestCase(void)
{}

void AccountIAMCallbackServiceTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void AccountIAMCallbackServiceTest::TearDown(void)
{}

/**
 * @tc.name: IDMCallbackService_OnAcquireInfo_0100
 * @tc.desc: OnAcquireInfo with nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMCallbackServiceTest, IDMCallbackService_OnAcquireInfo_0100, TestSize.Level0)
{
    sptr<IDMCallbackService> wrapper = new (std::nothrow) IDMCallbackService(TEST_USER_ID, nullptr);
    EXPECT_TRUE(wrapper->callback_ == nullptr);
    Attributes extraInfo;
    wrapper->OnAcquireInfo(0, 0, extraInfo);
}

/**
 * @tc.name: IDMCallbackService_OnAcquireInfo_0200
 * @tc.desc: OnAcquireInfo with not nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMCallbackServiceTest, IDMCallbackService_OnAcquireInfo_0200, TestSize.Level0)
{
    auto callback = std::make_shared<MockIDMCallback>();
    EXPECT_NE(callback, nullptr);
    EXPECT_CALL(*callback, OnAcquireInfo(_, _, _)).Times(Exactly(1));
    auto testCallback = std::make_shared<TestIDMCallback>(callback);
    sptr<IDMCallbackService> wrapper = new (std::nothrow) IDMCallbackService(TEST_USER_ID, testCallback);
    EXPECT_TRUE(wrapper->callback_ != nullptr);
    Attributes extraInfo;
    wrapper->OnAcquireInfo(0, 0, extraInfo);
    std::unique_lock<std::mutex> lock(testCallback->mutex);
    testCallback->cv.wait_for(
        lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
}

/**
 * @tc.name: IDMCallbackService_OnResult_0100
 * @tc.desc: OnResult test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMCallbackServiceTest, IDMCallbackService_OnResult_0100, TestSize.Level0)
{
    auto callback = std::make_shared<MockIDMCallback>();
    EXPECT_NE(callback, nullptr);
    EXPECT_CALL(*callback, OnResult(0, _)).Times(Exactly(1));
    auto testCallback = std::make_shared<TestIDMCallback>(callback);
    sptr<IDMCallbackService> wrapper = new (std::nothrow) IDMCallbackService(TEST_USER_ID, testCallback);
    ASSERT_NE(wrapper, nullptr);
    Attributes extraInfo;
    wrapper->OnResult(0, extraInfo);
    {
        std::unique_lock<std::mutex> lock(testCallback->mutex);
        testCallback->cv.wait_for(
            lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
    }
    EXPECT_CALL(*callback, OnResult(1, _)).Times(Exactly(1));
    testCallback->isReady = false;
    wrapper->OnResult(1, extraInfo);
    {
        std::unique_lock<std::mutex> lock(testCallback->mutex);
        testCallback->cv.wait_for(
            lock, std::chrono::seconds(WAIT_TIME), [lockCallback = testCallback]() { return lockCallback->isReady; });
    }
    wrapper->callback_ = nullptr;
    wrapper->OnResult(0, extraInfo);
}

/**
 * @tc.name: GetCredInfoCallbackService_OnCredentialInfo_0100
 * @tc.desc: OnCredentialInfo with nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMCallbackServiceTest, GetCredInfoCallbackService_OnCredentialInfo_0100, TestSize.Level0)
{
    sptr<GetCredInfoCallbackService> wrapper = new (std::nothrow) GetCredInfoCallbackService(nullptr);
    EXPECT_TRUE(wrapper->callback_ == nullptr);
    std::vector<CredentialInfo> infoList;
    wrapper->OnCredentialInfo(infoList);
}

/**
 * @tc.name: GetSetPropCallbackService_OnResult_0100
 * @tc.desc: OnResult with nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMCallbackServiceTest, GetSetPropCallbackService_OnResult_0100, TestSize.Level0)
{
    sptr<GetSetPropCallbackService> wrapper = new (std::nothrow) GetSetPropCallbackService(nullptr);
    EXPECT_TRUE(wrapper->callback_ == nullptr);
    Attributes extraInfo;
    wrapper->OnResult(0, extraInfo);
}

#ifdef HAS_PIN_AUTH_PART
/**
 * @tc.name: IAMInputer_OnGetData_0100
 * @tc.desc: OnGetData with inputerData_ nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMCallbackServiceTest, IAMInputer_OnGetData_0100, TestSize.Level0)
{
    std::shared_ptr<MockIInputer> inputer = std::make_shared<MockIInputer>();
    auto iamInputer = std::make_shared<IAMInputer>(TEST_USER_ID, inputer);
    ASSERT_TRUE(iamInputer != nullptr);
    int32_t authSubType = 0;
    auto iamInputerData = std::make_shared<IAMInputerData>(TEST_USER_ID, nullptr);
    EXPECT_TRUE(iamInputerData != nullptr);
    iamInputer->inputerData_ = nullptr;
    iamInputer->OnGetData(authSubType, std::vector<uint8_t>(), iamInputerData);
}

/**
 * @tc.name: IAMInputer_OnGetData_0200
 * @tc.desc: OnGetData.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMCallbackServiceTest, IAMInputer_OnGetData_0200, TestSize.Level0)
{
    std::shared_ptr<MockIInputer> inputer = std::make_shared<MockIInputer>();
    auto iamInputer = std::make_shared<IAMInputer>(TEST_USER_ID, inputer);
    ASSERT_TRUE(iamInputer != nullptr);
    int32_t authSubType = 0;
    auto iamInputerData = std::make_shared<IAMInputerData>(TEST_USER_ID, nullptr);
    EXPECT_TRUE(iamInputerData != nullptr);
    iamInputer->OnGetData(authSubType, std::vector<uint8_t>(), iamInputerData);
}

/**
 * @tc.name: IAMInputer_OnGetData_0300
 * @tc.desc: test OnGetData.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMCallbackServiceTest, IAMInputer_OnGetData_0300, TestSize.Level0)
{
    std::shared_ptr<MockIInputer> inputer = std::make_shared<MockIInputer>();
    auto iamInputer = std::make_shared<IAMInputer>(TEST_USER_ID, inputer);
    ASSERT_TRUE(iamInputer != nullptr);
    int32_t authSubType = 0;
    iamInputer->OnGetData(authSubType, std::vector<uint8_t>(), nullptr);
    std::string cmd = "hilog -x | grep 'AccountIAMFwk'";
    std::string cmdRes = RunCommand(cmd);
    ASSERT_TRUE(cmdRes.find("inputerData is nullptr") != std::string::npos);
}
#endif

/**
 * @tc.name: DomainAuthCallbackAdapter_OnResult_0100
 * @tc.desc: test OnResult.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMCallbackServiceTest, DomainAuthCallbackAdapter_OnResult_0100, TestSize.Level0)
{
    std::shared_ptr<DomainAuthCallbackAdapter> domainAuthCallbackAdapter =
        std::make_shared<DomainAuthCallbackAdapter>(nullptr);
    Parcel emptyParcel;
    domainAuthCallbackAdapter->OnResult(0, emptyParcel);
    std::string cmd = "hilog -x | grep 'AccountIAMFwk'";
    std::string cmdRes = RunCommand(cmd);
    ASSERT_TRUE(cmdRes.find("callback is nullptr") != std::string::npos);
}

#ifdef HAS_PIN_AUTH_PART
/**
 * @tc.name: DomainCredentialRecipient_OnSetData_0100
 * @tc.desc: test OnSetData.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMCallbackServiceTest, DomainCredentialRecipient_OnSetData_0100, TestSize.Level0)
{
    auto domainCredentialRecipient = new (std::nothrow) DomainCredentialRecipient(100, nullptr);
    std::vector<uint8_t> data = {1, 2, 3, 4};
    domainCredentialRecipient->OnSetData(0, data);
    EXPECT_EQ(domainCredentialRecipient->idmCallback_, nullptr);
}

/**
 * @tc.name: IAMInputerData_OnSetData_0100
 * @tc.desc: test OnSetData.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMCallbackServiceTest, IAMInputerData_OnSetData_0100, TestSize.Level0)
{
    auto iamInputerData = new (std::nothrow) IAMInputerData(100, nullptr);
    std::vector<uint8_t> data = {1, 2, 3, 4};
    iamInputerData->OnSetData(0, data);
    EXPECT_EQ(iamInputerData->innerInputerData_, nullptr);
}
#endif
}  // namespace AccountTest
}  // namespace OHOS