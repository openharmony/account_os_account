/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "file_ex.h"
#include <fstream>
#include <iostream>
#include <unistd.h>
#include <vector>

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_proxy.h"
#include "account_info.h"
#include "distributed_account_subscribe_callback.h"
#include "iaccount.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "ohos_account_constants.h"
#include "ohos_account_kits.h"
#include "os_account_manager.h"
#include "system_ability_definition.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;
using namespace OHOS::AccountSA::Constants;
using json = nlohmann::json;

class SubscribeDistributedAccountModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void SubscribeDistributedAccountModuleTest::SetUpTestCase(void)
{}

void SubscribeDistributedAccountModuleTest::TearDownTestCase(void)
{}

void SubscribeDistributedAccountModuleTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void SubscribeDistributedAccountModuleTest::TearDown(void)
{}

class MockDistributedAccountSubscribeCallback final : public DistributedAccountSubscribeCallback {
public:
    explicit MockDistributedAccountSubscribeCallback()
    {}

    MOCK_METHOD1(OnAccountsChanged, void(const DistributedAccountEventData &eventData));
};

/**
 * @tc.name: SubscribeDistributedAccountTest001
 * @tc.desc: subscribe distributed account login
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(SubscribeDistributedAccountModuleTest, SubscribeDistributedAccountTest001, TestSize.Level0)
{
    OsAccountInfo SubDistributedAccount;
    EXPECT_EQ(OsAccountManager::CreateOsAccount("SubDistributed001", OsAccountType::NORMAL, SubDistributedAccount),
        ERR_OK);
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(SubDistributedAccount.GetLocalId()), ERR_OK);

    // login
    auto loginSubscribeCallback = std::make_shared<MockDistributedAccountSubscribeCallback>();
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().SubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, loginSubscribeCallback));
    DistributedAccountEventData loginEventData;
    loginEventData.id_ = SubDistributedAccount.GetLocalId();
    loginEventData.type_ = DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN;
    EXPECT_CALL(*loginSubscribeCallback, OnAccountsChanged(loginEventData)).Times(Exactly(1));

    // logout
    auto logoutSubscribeCallback = std::make_shared<MockDistributedAccountSubscribeCallback>();
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().SubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGOUT, logoutSubscribeCallback));
    DistributedAccountEventData logoutEventData;
    logoutEventData.id_ = SubDistributedAccount.GetLocalId();
    logoutEventData.type_ = DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGOUT;
    EXPECT_CALL(*logoutSubscribeCallback, OnAccountsChanged(logoutEventData)).Times(Exactly(1));

    EXPECT_EQ(OhosAccountKits::GetInstance().UpdateOhosAccountInfo(
        "TestName001", "TestUID001", "Ohos.account.event.LOGIN"), true);
    EXPECT_EQ(OhosAccountKits::GetInstance().UpdateOhosAccountInfo(
        "TestName001", "TestUID001", "Ohos.account.event.LOGOUT"), true);

    sleep(1);
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().UnsubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, loginSubscribeCallback));
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().UnsubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGOUT, logoutSubscribeCallback));

    EXPECT_EQ(ERR_OK, OsAccountManager::RemoveOsAccount(SubDistributedAccount.GetLocalId()));
}

/**
 * @tc.name: SubscribeDistributedAccountTest002
 * @tc.desc: subscribe distributed account logoff and multi-EXPECT_CALL
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(SubscribeDistributedAccountModuleTest, SubscribeDistributedAccountTest002, TestSize.Level0)
{
    OsAccountInfo SubDistributedAccount;
    EXPECT_EQ(OsAccountManager::CreateOsAccount("SubDistributed002", OsAccountType::NORMAL, SubDistributedAccount),
        ERR_OK);
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(SubDistributedAccount.GetLocalId()), ERR_OK);

    // login
    auto loginSubscribeCallback = std::make_shared<MockDistributedAccountSubscribeCallback>();
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().SubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, loginSubscribeCallback));
    DistributedAccountEventData loginEventData;
    loginEventData.id_ = SubDistributedAccount.GetLocalId();
    loginEventData.type_ = DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN;
    // 2 times
    EXPECT_CALL(*loginSubscribeCallback, OnAccountsChanged(loginEventData)).Times(Exactly(2));

    // logoff
    auto logoffSubscribeCallback = std::make_shared<MockDistributedAccountSubscribeCallback>();
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().SubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGOFF, logoffSubscribeCallback));
    DistributedAccountEventData logoffEventData;
    logoffEventData.id_ = SubDistributedAccount.GetLocalId();
    logoffEventData.type_ = DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGOFF;
    // 2 times
    EXPECT_CALL(*logoffSubscribeCallback, OnAccountsChanged(logoffEventData)).Times(Exactly(2));

    // 2 times
    EXPECT_EQ(OhosAccountKits::GetInstance().UpdateOhosAccountInfo(
        "TestName002", "TestUID002", "Ohos.account.event.LOGIN"), true);
    EXPECT_EQ(OhosAccountKits::GetInstance().UpdateOhosAccountInfo(
        "TestName002", "TestUID002", "Ohos.account.event.LOGOFF"), true);
    EXPECT_EQ(OhosAccountKits::GetInstance().UpdateOhosAccountInfo(
        "TestName002", "TestUID002", "Ohos.account.event.LOGIN"), true);
    EXPECT_EQ(OhosAccountKits::GetInstance().UpdateOhosAccountInfo(
        "TestName002", "TestUID002", "Ohos.account.event.LOGOFF"), true);

    sleep(1);
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().UnsubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, loginSubscribeCallback));
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().UnsubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGOFF, logoffSubscribeCallback));

    EXPECT_EQ(ERR_OK, OsAccountManager::RemoveOsAccount(SubDistributedAccount.GetLocalId()));
}

/**
 * @tc.name: SubscribeDistributedAccountTest003
 * @tc.desc: subscribe distributed account token invalid
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(SubscribeDistributedAccountModuleTest, SubscribeDistributedAccountTest003, TestSize.Level0)
{
    OsAccountInfo SubDistributedAccount;
    EXPECT_EQ(OsAccountManager::CreateOsAccount("SubDistributed003", OsAccountType::NORMAL, SubDistributedAccount),
        ERR_OK);
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(SubDistributedAccount.GetLocalId()), ERR_OK);

    // login
    auto loginSubscribeCallback = std::make_shared<MockDistributedAccountSubscribeCallback>();
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().SubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, loginSubscribeCallback));
    DistributedAccountEventData loginEventData;
    loginEventData.id_ = SubDistributedAccount.GetLocalId();
    loginEventData.type_ = DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN;
    EXPECT_CALL(*loginSubscribeCallback, OnAccountsChanged(loginEventData)).Times(Exactly(1));

    // TokenInvalid use login callback
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().SubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::TOKEN_INVALID, loginSubscribeCallback));
    DistributedAccountEventData tokenInvalidEventData;
    tokenInvalidEventData.id_ = SubDistributedAccount.GetLocalId();
    tokenInvalidEventData.type_ = DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::TOKEN_INVALID;
    EXPECT_CALL(*loginSubscribeCallback, OnAccountsChanged(tokenInvalidEventData)).Times(Exactly(1));

    EXPECT_EQ(OhosAccountKits::GetInstance().UpdateOhosAccountInfo(
        "TestName003", "TestUID003", "Ohos.account.event.LOGIN"), true);
    EXPECT_EQ(OhosAccountKits::GetInstance().UpdateOhosAccountInfo(
        "TestName003", "TestUID003", "Ohos.account.event.TOKEN_INVALID"), true);

    sleep(1);
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().UnsubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, loginSubscribeCallback));
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().UnsubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::TOKEN_INVALID, loginSubscribeCallback));

    EXPECT_EQ(ERR_OK, OsAccountManager::RemoveOsAccount(SubDistributedAccount.GetLocalId()));
}

/**
 * @tc.name: SubscribeDistributedAccountTest004
 * @tc.desc: subscribe distributed account nullptr
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(SubscribeDistributedAccountModuleTest, SubscribeDistributedAccountTest004, TestSize.Level0)
{
    std::shared_ptr<DistributedAccountSubscribeCallback> loginSubscribeCallback = nullptr;

    EXPECT_EQ(ERR_ACCOUNT_COMMON_NULL_PTR_ERROR,
        OhosAccountKits::GetInstance().SubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, loginSubscribeCallback));
    EXPECT_EQ(ERR_ACCOUNT_COMMON_NULL_PTR_ERROR,
        OhosAccountKits::GetInstance().UnsubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, loginSubscribeCallback));
}

/**
 * @tc.name: SubscribeDistributedAccountTest005
 * @tc.desc: re-subscribe distributed account
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(SubscribeDistributedAccountModuleTest, SubscribeDistributedAccountTest005, TestSize.Level0)
{
    OsAccountInfo SubDistributedAccount;
    EXPECT_EQ(OsAccountManager::CreateOsAccount("SubDistributed005", OsAccountType::NORMAL, SubDistributedAccount),
        ERR_OK);
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(SubDistributedAccount.GetLocalId()), ERR_OK);

    // login
    auto loginSubscribeCallback = std::make_shared<MockDistributedAccountSubscribeCallback>();
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().SubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, loginSubscribeCallback));
    // re-sub
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().SubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, loginSubscribeCallback));
    DistributedAccountEventData loginEventData;
    loginEventData.id_ = SubDistributedAccount.GetLocalId();
    loginEventData.type_ = DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN;
    EXPECT_CALL(*loginSubscribeCallback, OnAccountsChanged(loginEventData)).Times(Exactly(1));

    EXPECT_EQ(OhosAccountKits::GetInstance().UpdateOhosAccountInfo(
        "TestName005", "TestUID005", "Ohos.account.event.LOGIN"), true);

    sleep(1);
    // unsub not exist type
    EXPECT_EQ(ERR_OHOSACCOUNT_KIT_NO_SPECIFIED_CALLBACK_HAS_BEEN_REGISTERED,
        OhosAccountKits::GetInstance().UnsubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGOUT, loginSubscribeCallback));
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().UnsubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, loginSubscribeCallback));
    // unsub not exist callback
    EXPECT_EQ(ERR_OHOSACCOUNT_KIT_NO_SPECIFIED_CALLBACK_HAS_BEEN_REGISTERED,
        OhosAccountKits::GetInstance().UnsubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, loginSubscribeCallback));

    EXPECT_EQ(ERR_OK, OsAccountManager::RemoveOsAccount(SubDistributedAccount.GetLocalId()));
}

/**
 * @tc.name: SubscribeDistributedAccountTest006
 * @tc.desc: subscribe distributed account login 2 callback
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(SubscribeDistributedAccountModuleTest, SubscribeDistributedAccountTest006, TestSize.Level0)
{
    OsAccountInfo SubDistributedAccount;
    EXPECT_EQ(OsAccountManager::CreateOsAccount("SubDistributed006", OsAccountType::NORMAL, SubDistributedAccount),
        ERR_OK);
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(SubDistributedAccount.GetLocalId()), ERR_OK);

    // login callback 1
    auto loginSubscribeCallbackOne = std::make_shared<MockDistributedAccountSubscribeCallback>();
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().SubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, loginSubscribeCallbackOne));
    DistributedAccountEventData loginEventData;
    loginEventData.id_ = SubDistributedAccount.GetLocalId();
    loginEventData.type_ = DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN;
    EXPECT_CALL(*loginSubscribeCallbackOne, OnAccountsChanged(loginEventData)).Times(Exactly(1));

    // login callback 2
    auto loginSubscribeCallbackTwo = std::make_shared<MockDistributedAccountSubscribeCallback>();
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().SubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, loginSubscribeCallbackTwo));
    EXPECT_CALL(*loginSubscribeCallbackTwo, OnAccountsChanged(loginEventData)).Times(Exactly(1));

    EXPECT_EQ(OhosAccountKits::GetInstance().UpdateOhosAccountInfo(
        "TestName006", "TestUID006", "Ohos.account.event.LOGIN"), true);

    sleep(1);
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().UnsubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, loginSubscribeCallbackOne));
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().UnsubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, loginSubscribeCallbackTwo));

    EXPECT_EQ(ERR_OK, OsAccountManager::RemoveOsAccount(SubDistributedAccount.GetLocalId()));
}
