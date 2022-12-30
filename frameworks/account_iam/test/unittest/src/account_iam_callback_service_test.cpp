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
#include "token_setproc.h"

namespace OHOS {
namespace AccountTest {
namespace {
    const int32_t TEST_USER_ID = 200;
}

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS::Security::AccessToken;

class MockIInputer : public OHOS::AccountSA::IInputer {
public:
    virtual ~MockIInputer() {}
    void OnGetData(int32_t authSubType, std::shared_ptr<IInputerData> inputerData) override
    {
        return;
    }
};

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

void AccountIAMCallbackServiceTest::SetUp(void)
{}

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
    auto testCallback = std::make_shared<MockIDMCallback>();
    EXPECT_NE(testCallback, nullptr);
    EXPECT_CALL(*testCallback, OnAcquireInfo(_, _, _)).Times(Exactly(1));
    sptr<IDMCallbackService> wrapper = new (std::nothrow) IDMCallbackService(TEST_USER_ID, testCallback);
    EXPECT_TRUE(wrapper->callback_ != nullptr);
    Attributes extraInfo;
    wrapper->OnAcquireInfo(0, 0, extraInfo);
}

/**
 * @tc.name: IDMCallbackService_OnResult_0100
 * @tc.desc: OnResult with nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMCallbackServiceTest, IDMCallbackService_OnResult_0100, TestSize.Level0)
{
    sptr<IDMCallbackService> wrapper = new (std::nothrow) IDMCallbackService(TEST_USER_ID, nullptr);
    EXPECT_TRUE(wrapper->callback_ == nullptr);
    Attributes extraInfo;
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
    iamInputer->OnGetData(authSubType, iamInputerData);
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
    iamInputer->OnGetData(authSubType, iamInputerData);
}
}  // namespace AccountTest
}  // namespace OHOS