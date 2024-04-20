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
#include <thread>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#define private public
#include "iinner_os_account_manager.h"
#undef private

namespace OHOS {
namespace AccountSA {
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS;
using namespace AccountSA;

class IInnerOsAccountManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);

    IInnerOsAccountManager *innerMgrService_ = &IInnerOsAccountManager::GetInstance();
};

void IInnerOsAccountManagerTest::SetUpTestCase(void)
{}

void IInnerOsAccountManagerTest::TearDownTestCase(void)
{}

void IInnerOsAccountManagerTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void IInnerOsAccountManagerTest::TearDown(void)
{}

/**
 * @tc.name: SendMsgForAccountStop001
 * @tc.desc: coverage SendMsgForAccountStop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, SendMsgForAccountStop001, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    ErrCode ret = innerMgrService_->SendMsgForAccountStop(osAccountInfo);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.name: SendMsgForAccountRemove001
 * @tc.desc: coverage SendMsgForAccountRemove
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, SendMsgForAccountRemove001, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    ErrCode ret = innerMgrService_->SendMsgForAccountRemove(osAccountInfo);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.name: SendMsgForAccountActivate001
 * @tc.desc: coverage SendMsgForAccountActivate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, SendMsgForAccountActivate001, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    ErrCode ret = innerMgrService_->SendMsgForAccountActivate(osAccountInfo);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.name: SubscribeOsAccount001
 * @tc.desc: coverage SubscribeOsAccount
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, SubscribeOsAccount001, TestSize.Level1)
{
    OsAccountSubscribeInfo subscribeInfo;
    const sptr<IRemoteObject> eventListener = nullptr;

    OsAccountInfo osAccountInfo;
    ErrCode ret = innerMgrService_->SubscribeOsAccount(subscribeInfo, eventListener);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.name: GetOsAccountShortName001
 * @tc.desc: coverage GetOsAccountShortName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, GetOsAccountShortName001, TestSize.Level1)
{
    std::string shortName;
    ErrCode ret = innerMgrService_->GetOsAccountShortName(199, shortName);
    EXPECT_NE(ret, ERR_OK);
    ret = innerMgrService_->GetOsAccountShortName(100, shortName);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: InnerOsAccountManagerTest001
 * @tc.desc: coverage ValidateShortName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, InnerOsAccountManagerTest001, TestSize.Level1)
{
    ErrCode ret = innerMgrService_->ValidateShortName("sdfgse*");
    EXPECT_NE(ret, ERR_OK);
    ret = innerMgrService_->ValidateShortName("..");
    EXPECT_NE(ret, ERR_OK);
    ret = innerMgrService_->ValidateShortName("");
    EXPECT_NE(ret, ERR_OK);
    ret = innerMgrService_->ValidateShortName("asdfgtr");
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: InnerOsAccountManagerTest002
 * @tc.desc: coverage CheckAndRefreshLocalIdRecord
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, InnerOsAccountManagerTest002, TestSize.Level1)
{
    innerMgrService_->CheckAndRefreshLocalIdRecord(100);
    innerMgrService_->CheckAndRefreshLocalIdRecord(199);
}

/**
 * @tc.name: InnerOsAccountManagerTest003
 * @tc.desc: coverage SendMsgForAccountDeactivate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IInnerOsAccountManagerTest, InnerOsAccountManagerTest003, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    ErrCode ret = innerMgrService_->CreateOsAccount("InnerOsAccountManager003", OsAccountType::NORMAL, osAccountInfo);
    EXPECT_NE(ret, ERR_OK);
    innerMgrService_->RemoveOsAccount(osAccountInfo.GetLocalId());
}
}  // namespace AccountSA
}  // namespace OHOS
