/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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
#include "account_test_common.h"
#include "account_proxy.h"
#include "account_info.h"
#include "account_test_common.h"
#define  private public
#include "distributed_account_event_service.h"
#undef private
#include "iaccount.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "ohos_account_constants.h"
#include "ohos_account_kits_impl.h"
#include "os_account_manager.h"
#include "system_ability_definition.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;
using namespace OHOS::AccountSA::Constants;

static OsAccountInfo g_subDistributedAccount;

class SubscribeDistributedAccountModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void SubscribeDistributedAccountModuleTest::SetUpTestCase(void)
{
    ASSERT_NE(GetAllAccountPermission(), 0);
    ASSERT_EQ(CreateOsAccountForTest("SubDistributed003", OsAccountType::NORMAL, g_subDistributedAccount),
        ERR_OK);
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(g_subDistributedAccount.GetLocalId()), ERR_OK);
}

void SubscribeDistributedAccountModuleTest::TearDownTestCase(void)
{
    EXPECT_EQ(ERR_OK, RemoveOsAccountForTest(g_subDistributedAccount.GetLocalId()));
}

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
    MOCK_METHOD1(OnSpaceAccountsChanged, void(const DistributedAccountSubProfileEventData &eventData));
};

/**
 * @tc.name: SubscribeDistributedAccountTest001
 * @tc.desc: subscribe distributed account login
 * @tc.type: FUNC
 * @tc.require:
*/
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(SubscribeDistributedAccountModuleTest, SubscribeDistributedAccountTest001, TestSize.Level1)
{
    // login
    auto loginSubscribeCallback = std::make_shared<MockDistributedAccountSubscribeCallback>();
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().SubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, loginSubscribeCallback));
    DistributedAccountEventData loginEventData;
    loginEventData.id_ = g_subDistributedAccount.GetLocalId();
    loginEventData.type_ = DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN;
    EXPECT_CALL(*loginSubscribeCallback, OnAccountsChanged(loginEventData)).Times(Exactly(1));

    // logout
    auto logoutSubscribeCallback = std::make_shared<MockDistributedAccountSubscribeCallback>();
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().SubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGOUT, logoutSubscribeCallback));
    DistributedAccountEventData logoutEventData;
    logoutEventData.id_ = g_subDistributedAccount.GetLocalId();
    logoutEventData.type_ = DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGOUT;
    EXPECT_CALL(*logoutSubscribeCallback, OnAccountsChanged(logoutEventData)).Times(Exactly(1));

    EXPECT_EQ(OhosAccountKits::GetInstance().UpdateOhosAccountInfo(
        "TestName001", "TestUID001", "Ohos.account.event.LOGIN"), ERR_OK);
    EXPECT_EQ(OhosAccountKits::GetInstance().UpdateOhosAccountInfo(
        "TestName001", "TestUID001", "Ohos.account.event.LOGOUT"), ERR_OK);

    sleep(1);
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().UnsubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, loginSubscribeCallback));
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().UnsubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGOUT, logoutSubscribeCallback));
}

/**
 * @tc.name: SubscribeDistributedAccountTest002
 * @tc.desc: subscribe distributed account logoff and multi-EXPECT_CALL
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(SubscribeDistributedAccountModuleTest, SubscribeDistributedAccountTest002, TestSize.Level1)
{
    // login
    auto loginSubscribeCallback = std::make_shared<MockDistributedAccountSubscribeCallback>();
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().SubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, loginSubscribeCallback));
    DistributedAccountEventData loginEventData;
    loginEventData.id_ = g_subDistributedAccount.GetLocalId();
    loginEventData.type_ = DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN;
    // 2 times
    EXPECT_CALL(*loginSubscribeCallback, OnAccountsChanged(loginEventData)).Times(Exactly(2));

    // logoff
    auto logoffSubscribeCallback = std::make_shared<MockDistributedAccountSubscribeCallback>();
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().SubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGOFF, logoffSubscribeCallback));
    DistributedAccountEventData logoffEventData;
    logoffEventData.id_ = g_subDistributedAccount.GetLocalId();
    logoffEventData.type_ = DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGOFF;
    // 2 times
    EXPECT_CALL(*logoffSubscribeCallback, OnAccountsChanged(logoffEventData)).Times(Exactly(2));

    // 2 times
    EXPECT_EQ(OhosAccountKits::GetInstance().UpdateOhosAccountInfo(
        "TestName002", "TestUID002", "Ohos.account.event.LOGIN"), ERR_OK);
    EXPECT_EQ(OhosAccountKits::GetInstance().UpdateOhosAccountInfo(
        "TestName002", "TestUID002", "Ohos.account.event.LOGOFF"), ERR_OK);
    EXPECT_EQ(OhosAccountKits::GetInstance().UpdateOhosAccountInfo(
        "TestName002", "TestUID002", "Ohos.account.event.LOGIN"), ERR_OK);
    EXPECT_EQ(OhosAccountKits::GetInstance().UpdateOhosAccountInfo(
        "TestName002", "TestUID002", "Ohos.account.event.LOGOFF"), ERR_OK);

    sleep(1);
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().UnsubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, loginSubscribeCallback));
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().UnsubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGOFF, logoffSubscribeCallback));
}

/**
 * @tc.name: SubscribeDistributedAccountTest003
 * @tc.desc: subscribe distributed account token invalid
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(SubscribeDistributedAccountModuleTest, SubscribeDistributedAccountTest003, TestSize.Level1)
{
    // login
    auto loginSubscribeCallback = std::make_shared<MockDistributedAccountSubscribeCallback>();
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().SubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, loginSubscribeCallback));
    DistributedAccountEventData loginEventData;
    loginEventData.id_ = g_subDistributedAccount.GetLocalId();
    loginEventData.type_ = DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN;
    EXPECT_CALL(*loginSubscribeCallback, OnAccountsChanged(loginEventData)).Times(Exactly(1));

    // TokenInvalid use login callback
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().SubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::TOKEN_INVALID, loginSubscribeCallback));
    DistributedAccountEventData tokenInvalidEventData;
    tokenInvalidEventData.id_ = g_subDistributedAccount.GetLocalId();
    tokenInvalidEventData.type_ = DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::TOKEN_INVALID;
    EXPECT_CALL(*loginSubscribeCallback, OnAccountsChanged(tokenInvalidEventData)).Times(Exactly(1));

    EXPECT_EQ(OhosAccountKits::GetInstance().UpdateOhosAccountInfo(
        "TestName003", "TestUID003", "Ohos.account.event.LOGIN"), ERR_OK);
    EXPECT_EQ(OhosAccountKits::GetInstance().UpdateOhosAccountInfo(
        "TestName003", "TestUID003", "Ohos.account.event.TOKEN_INVALID"), ERR_OK);

    sleep(1);
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().UnsubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, loginSubscribeCallback));
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().UnsubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::TOKEN_INVALID, loginSubscribeCallback));
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: SubscribeDistributedAccountTest004
 * @tc.desc: subscribe distributed account nullptr
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(SubscribeDistributedAccountModuleTest, SubscribeDistributedAccountTest004, TestSize.Level3)
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
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(SubscribeDistributedAccountModuleTest, SubscribeDistributedAccountTest005, TestSize.Level1)
{
    // login
    auto loginSubscribeCallback = std::make_shared<MockDistributedAccountSubscribeCallback>();
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().SubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, loginSubscribeCallback));
    // re-sub
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().SubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, loginSubscribeCallback));
    DistributedAccountEventData loginEventData;
    loginEventData.id_ = g_subDistributedAccount.GetLocalId();
    loginEventData.type_ = DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN;
    EXPECT_CALL(*loginSubscribeCallback, OnAccountsChanged(loginEventData)).Times(Exactly(1));

    EXPECT_EQ(OhosAccountKits::GetInstance().UpdateOhosAccountInfo(
        "TestName005", "TestUID005", "Ohos.account.event.LOGIN"), ERR_OK);
    EXPECT_EQ(OhosAccountKits::GetInstance().UpdateOhosAccountInfo(
        "TestName005", "TestUID005", "Ohos.account.event.LOGOUT"), ERR_OK);

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
}

/**
 * @tc.name: SubscribeDistributedAccountTest006
 * @tc.desc: subscribe distributed account login 2 callback
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(SubscribeDistributedAccountModuleTest, SubscribeDistributedAccountTest006, TestSize.Level1)
{
    // login callback 1
    auto loginSubscribeCallbackOne = std::make_shared<MockDistributedAccountSubscribeCallback>();
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().SubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, loginSubscribeCallbackOne));
    DistributedAccountEventData loginEventData;
    Parcel parcel;
    loginEventData.id_ = g_subDistributedAccount.GetLocalId();
    loginEventData.type_ = DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN;
    loginEventData.Marshalling(parcel);
    EXPECT_CALL(*loginSubscribeCallbackOne, OnAccountsChanged(loginEventData)).Times(Exactly(1));

    // login callback 2
    auto loginSubscribeCallbackTwo = std::make_shared<MockDistributedAccountSubscribeCallback>();
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().SubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, loginSubscribeCallbackTwo));
    EXPECT_CALL(*loginSubscribeCallbackTwo, OnAccountsChanged(loginEventData)).Times(Exactly(1));

    EXPECT_EQ(OhosAccountKits::GetInstance().UpdateOhosAccountInfo(
        "TestName006", "TestUID006", "Ohos.account.event.LOGIN"), ERR_OK);

    sleep(1);
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().UnsubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, loginSubscribeCallbackOne));
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().UnsubscribeDistributedAccountEvent(
        DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN, loginSubscribeCallbackTwo));
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS


/**
 * @tc.name: SubscribeDistributedAccountSpaceEvents001
 * @tc.desc: Test AddSpaceTypes with multiple callbacks for same type - cover line 152 else branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SubscribeDistributedAccountModuleTest, SubscribeDistributedAccountSpaceEvents001, TestSize.Level3)
{
    auto callback1 = std::make_shared<MockDistributedAccountSubscribeCallback>();
    ASSERT_NE(callback1, nullptr);
    std::set<DistributedAccountSubProfileEventType> types = {DistributedAccountSubProfileEventType::CREATED};

    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().SubscribeDistributedAccountSpaceEvents(types, callback1));
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().UnsubscribeDistributedAccountSpaceEvents(callback1));
}

/**
 * @tc.name: DistributedAccountEventService_AddSpaceTypes001
 * @tc.desc: Test AddSpaceTypes with single type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SubscribeDistributedAccountModuleTest, AddSpaceTypes001, TestSize.Level3)
{
    auto callback = std::make_shared<MockDistributedAccountSubscribeCallback>();
    ASSERT_NE(callback, nullptr);

    std::set<DistributedAccountSubProfileEventType> types = {DistributedAccountSubProfileEventType::CREATED};
    DistributedAccountEventService::GetInstance()->AddSpaceTypes(types, callback);

    EXPECT_TRUE(DistributedAccountEventService::GetInstance()->IsAllSpaceTypeExist(types, callback));
    EXPECT_EQ(DistributedAccountEventService::GetInstance()->GetSpaceCallbackSize(), 1);

    DistributedAccountEventService::GetInstance()->DeleteSpaceCallback(callback);
}

/**
 * @tc.name: DistributedAccountEventService_AddSpaceTypes002
 * @tc.desc: Test AddSpaceTypes with nullptr callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SubscribeDistributedAccountModuleTest, AddSpaceTypes002, TestSize.Level3)
{
    std::shared_ptr<DistributedAccountSubscribeCallback> callback = nullptr;
    std::set<DistributedAccountSubProfileEventType> types = {DistributedAccountSubProfileEventType::CREATED};

    DistributedAccountEventService::GetInstance()->AddSpaceTypes(types, callback);
    EXPECT_EQ(DistributedAccountEventService::GetInstance()->GetSpaceCallbackSize(), 0);
}

/**
 * @tc.name: DistributedAccountEventService_DeleteSpaceTypes001
 * @tc.desc: Test DeleteSpaceTypes after AddSpaceTypes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SubscribeDistributedAccountModuleTest, DeleteSpaceTypes001, TestSize.Level3)
{
    auto callback = std::make_shared<MockDistributedAccountSubscribeCallback>();
    ASSERT_NE(callback, nullptr);

    std::set<DistributedAccountSubProfileEventType> types = {DistributedAccountSubProfileEventType::CREATED};
    DistributedAccountEventService::GetInstance()->AddSpaceTypes(types, callback);

    DistributedAccountEventService::GetInstance()->DeleteSpaceCallback(callback);
    EXPECT_FALSE(DistributedAccountEventService::GetInstance()->IsAllSpaceTypeExist(types, callback));
    EXPECT_EQ(DistributedAccountEventService::GetInstance()->GetSpaceCallbackSize(), 0);
}

/**
 * @tc.name: DistributedAccountEventService_AddSpaceTypes003
 * @tc.desc: Test AddSpaceTypes with empty types set - cover line 136 types.empty()
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SubscribeDistributedAccountModuleTest, AddSpaceTypes003, TestSize.Level3)
{
    auto callback = std::make_shared<MockDistributedAccountSubscribeCallback>();
    ASSERT_NE(callback, nullptr);

    std::set<DistributedAccountSubProfileEventType> types;
    DistributedAccountEventService::GetInstance()->AddSpaceTypes(types, callback);
    EXPECT_EQ(DistributedAccountEventService::GetInstance()->GetSpaceCallbackSize(), 0);
}

/**
 * @tc.name: DistributedAccountEventService_AddSpaceTypes004
 * @tc.desc: Test AddSpaceTypes merge types to existing callback - cover line 143 else branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SubscribeDistributedAccountModuleTest, AddSpaceTypes004, TestSize.Level3)
{
    auto callback = std::make_shared<MockDistributedAccountSubscribeCallback>();
    ASSERT_NE(callback, nullptr);

    std::set<DistributedAccountSubProfileEventType> types1 = {DistributedAccountSubProfileEventType::CREATED};
    DistributedAccountEventService::GetInstance()->AddSpaceTypes(types1, callback);
    EXPECT_EQ(DistributedAccountEventService::GetInstance()->GetSpaceCallbackSize(), 1);

    std::set<DistributedAccountSubProfileEventType> types2 = {DistributedAccountSubProfileEventType::SWITCHED};
    DistributedAccountEventService::GetInstance()->AddSpaceTypes(types2, callback);
    EXPECT_EQ(DistributedAccountEventService::GetInstance()->GetSpaceCallbackSize(), 1);

    std::set<DistributedAccountSubProfileEventType> allTypes = {DistributedAccountSubProfileEventType::CREATED,
        DistributedAccountSubProfileEventType::SWITCHED};
    EXPECT_TRUE(DistributedAccountEventService::GetInstance()->IsAllSpaceTypeExist(allTypes, callback));

    DistributedAccountEventService::GetInstance()->DeleteSpaceCallback(callback);
}

/**
 * @tc.name: DistributedAccountEventService_AddSpaceTypes005
 * @tc.desc: Test AddSpaceTypes with multiple callbacks for same type - cover line 152 else branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SubscribeDistributedAccountModuleTest, AddSpaceTypes005, TestSize.Level3)
{
    auto callback1 = std::make_shared<MockDistributedAccountSubscribeCallback>();
    ASSERT_NE(callback1, nullptr);
    auto callback2 = std::make_shared<MockDistributedAccountSubscribeCallback>();
    ASSERT_NE(callback2, nullptr);

    std::set<DistributedAccountSubProfileEventType> types = {DistributedAccountSubProfileEventType::CREATED};
    DistributedAccountEventService::GetInstance()->AddSpaceTypes(types, callback1);
    EXPECT_EQ(DistributedAccountEventService::GetInstance()->GetSpaceCallbackSize(), 1);

    DistributedAccountEventService::GetInstance()->AddSpaceTypes(types, callback2);
    EXPECT_EQ(DistributedAccountEventService::GetInstance()->GetSpaceCallbackSize(), 2);

    DistributedAccountEventService::GetInstance()->DeleteSpaceCallback(callback1);
    DistributedAccountEventService::GetInstance()->DeleteSpaceCallback(callback2);
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().SubscribeDistributedAccountSpaceEvents(types, callback1));
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().UnsubscribeDistributedAccountSpaceEvents(callback1));
}

/**
 * @tc.name: DistributedAccountEventService_DeleteSpaceCallback001
 * @tc.desc: Test DeleteSpaceCallback with nullptr - cover line 163
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SubscribeDistributedAccountModuleTest, DeleteSpaceCallback001, TestSize.Level3)
{
    std::shared_ptr<DistributedAccountSubscribeCallback> callback = nullptr;
    DistributedAccountEventService::GetInstance()->DeleteSpaceCallback(callback);
    EXPECT_EQ(DistributedAccountEventService::GetInstance()->GetSpaceCallbackSize(), 0);
}

/**
 * @tc.name: DistributedAccountEventService_DeleteSpaceCallback002
 * @tc.desc: Test DeleteSpaceCallback with non-existent callback - cover line 168
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SubscribeDistributedAccountModuleTest, DeleteSpaceCallback002, TestSize.Level3)
{
    auto callback = std::make_shared<MockDistributedAccountSubscribeCallback>();
    ASSERT_NE(callback, nullptr);

    DistributedAccountEventService::GetInstance()->DeleteSpaceCallback(callback);
    EXPECT_EQ(DistributedAccountEventService::GetInstance()->GetSpaceCallbackSize(), 0);
}

/**
 * @tc.name: DistributedAccountEventService_GetSpaceTypesToRemove001
 * @tc.desc: Test GetSpaceTypesToRemove with nullptr callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SubscribeDistributedAccountModuleTest, GetSpaceTypesToRemove001, TestSize.Level3)
{
    std::shared_ptr<DistributedAccountSubscribeCallback> callback = nullptr;
    std::set<DistributedAccountSubProfileEventType> removedTypes;
    DistributedAccountEventService::GetInstance()->GetSpaceTypesToRemove(callback, removedTypes);
    EXPECT_TRUE(removedTypes.empty());
}

/**
 * @tc.name: DistributedAccountEventService_GetSpaceTypesToRemove002
 * @tc.desc: Test GetSpaceTypesToRemove with non-existent callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SubscribeDistributedAccountModuleTest, GetSpaceTypesToRemove002, TestSize.Level3)
{
    auto callback = std::make_shared<MockDistributedAccountSubscribeCallback>();
    ASSERT_NE(callback, nullptr);

    std::set<DistributedAccountSubProfileEventType> removedTypes;
    DistributedAccountEventService::GetInstance()->GetSpaceTypesToRemove(callback, removedTypes);
    EXPECT_TRUE(removedTypes.empty());
}

/**
 * @tc.name: DistributedAccountEventService_GetSpaceTypesToRemove003
 * @tc.desc: Test GetSpaceTypesToRemove with single callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SubscribeDistributedAccountModuleTest, GetSpaceTypesToRemove003, TestSize.Level3)
{
    auto callback = std::make_shared<MockDistributedAccountSubscribeCallback>();
    ASSERT_NE(callback, nullptr);

    std::set<DistributedAccountSubProfileEventType> types = {DistributedAccountSubProfileEventType::CREATED};
    DistributedAccountEventService::GetInstance()->AddSpaceTypes(types, callback);

    std::set<DistributedAccountSubProfileEventType> removedTypes;
    DistributedAccountEventService::GetInstance()->GetSpaceTypesToRemove(callback, removedTypes);
    EXPECT_EQ(removedTypes.size(), 1);
    EXPECT_NE(removedTypes.find(DistributedAccountSubProfileEventType::CREATED), removedTypes.end());

    DistributedAccountEventService::GetInstance()->DeleteSpaceCallback(callback);
}

/**
 * @tc.name: DistributedAccountEventService_GetSpaceTypesToRemove004
 * @tc.desc: Test GetSpaceTypesToRemove with multiple callbacks same type - no removal needed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SubscribeDistributedAccountModuleTest, GetSpaceTypesToRemove004, TestSize.Level3)
{
    auto callback1 = std::make_shared<MockDistributedAccountSubscribeCallback>();
    ASSERT_NE(callback1, nullptr);
    auto callback2 = std::make_shared<MockDistributedAccountSubscribeCallback>();
    ASSERT_NE(callback2, nullptr);

    std::set<DistributedAccountSubProfileEventType> types = {DistributedAccountSubProfileEventType::CREATED};
    DistributedAccountEventService::GetInstance()->AddSpaceTypes(types, callback1);
    DistributedAccountEventService::GetInstance()->AddSpaceTypes(types, callback2);

    std::set<DistributedAccountSubProfileEventType> removedTypes;
    DistributedAccountEventService::GetInstance()->GetSpaceTypesToRemove(callback1, removedTypes);
    EXPECT_TRUE(removedTypes.empty());

    DistributedAccountEventService::GetInstance()->DeleteSpaceCallback(callback1);
    DistributedAccountEventService::GetInstance()->DeleteSpaceCallback(callback2);
}

/**
 * @tc.name: DistributedAccountEventService_GetAllSpaceType001
 * @tc.desc: Test GetAllSpaceType - cover line 216
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SubscribeDistributedAccountModuleTest, GetAllSpaceType001, TestSize.Level3)
{
    std::set<DistributedAccountSubProfileEventType> typeList;
    DistributedAccountEventService::GetInstance()->GetAllSpaceType(typeList);
    EXPECT_TRUE(typeList.empty());

    auto callback = std::make_shared<MockDistributedAccountSubscribeCallback>();
    ASSERT_NE(callback, nullptr);

    std::set<DistributedAccountSubProfileEventType> types = {DistributedAccountSubProfileEventType::CREATED};
    DistributedAccountEventService::GetInstance()->AddSpaceTypes(types, callback);

    typeList.clear();
    DistributedAccountEventService::GetInstance()->GetAllSpaceType(typeList);
    EXPECT_EQ(typeList.size(), 1);
    EXPECT_NE(typeList.find(DistributedAccountSubProfileEventType::CREATED), typeList.end());

    DistributedAccountEventService::GetInstance()->DeleteSpaceCallback(callback);
}

/**
 * @tc.name: DistributedAccountEventService_IsAllSpaceTypeExist001
 * @tc.desc: Test IsAllSpaceTypeExist with nullptr callback - cover line 223
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SubscribeDistributedAccountModuleTest, IsAllSpaceTypeExist001, TestSize.Level3)
{
    std::shared_ptr<DistributedAccountSubscribeCallback> callback = nullptr;
    std::set<DistributedAccountSubProfileEventType> types = {DistributedAccountSubProfileEventType::CREATED};
    EXPECT_FALSE(DistributedAccountEventService::GetInstance()->IsAllSpaceTypeExist(types, callback));
}

/**
 * @tc.name: DistributedAccountEventService_IsAllSpaceTypeExist002
 * @tc.desc: Test IsAllSpaceTypeExist with empty types - cover line 223
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SubscribeDistributedAccountModuleTest, IsAllSpaceTypeExist002, TestSize.Level3)
{
    auto callback = std::make_shared<MockDistributedAccountSubscribeCallback>();
    ASSERT_NE(callback, nullptr);

    std::set<DistributedAccountSubProfileEventType> types;
    EXPECT_FALSE(DistributedAccountEventService::GetInstance()->IsAllSpaceTypeExist(types, callback));
}

/**
 * @tc.name: DistributedAccountEventService_IsAllSpaceTypeExist003
 * @tc.desc: Test IsAllSpaceTypeExist with non-existent type - cover line 233
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SubscribeDistributedAccountModuleTest, IsAllSpaceTypeExist003, TestSize.Level3)
{
    auto callback = std::make_shared<MockDistributedAccountSubscribeCallback>();
    ASSERT_NE(callback, nullptr);

    std::set<DistributedAccountSubProfileEventType> addedTypes = {DistributedAccountSubProfileEventType::CREATED};
    DistributedAccountEventService::GetInstance()->AddSpaceTypes(addedTypes, callback);

    std::set<DistributedAccountSubProfileEventType> checkTypes = {DistributedAccountSubProfileEventType::CREATED,
        DistributedAccountSubProfileEventType::SWITCHED};
    EXPECT_FALSE(DistributedAccountEventService::GetInstance()->IsAllSpaceTypeExist(checkTypes, callback));

    DistributedAccountEventService::GetInstance()->DeleteSpaceCallback(callback);
}

/**
 * @tc.name: DistributedAccountEventService_OnSpaceAccountsChanged001
 * @tc.desc: Test OnSpaceAccountsChanged with no subscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SubscribeDistributedAccountModuleTest, OnSpaceAccountsChanged001, TestSize.Level3)
{
    DistributedAccountSubProfileEventData eventData;
    eventData.type_ = DistributedAccountSubProfileEventType::CREATED;
    eventData.osAccountId_ = 100;
    eventData.subspaceId_ = 200;

    ErrCode result = DistributedAccountEventService::GetInstance()->OnSpaceAccountsChanged(eventData);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: DistributedAccountEventService_OnSpaceAccountsChanged002
 * @tc.desc: Test OnSpaceAccountsChanged with subscriber - cover line 246-249
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SubscribeDistributedAccountModuleTest, OnSpaceAccountsChanged002, TestSize.Level3)
{
    auto callback = std::make_shared<MockDistributedAccountSubscribeCallback>();
    ASSERT_NE(callback, nullptr);

    std::set<DistributedAccountSubProfileEventType> types = {DistributedAccountSubProfileEventType::CREATED};
    DistributedAccountEventService::GetInstance()->AddSpaceTypes(types, callback);

    DistributedAccountSubProfileEventData eventData;
    eventData.type_ = DistributedAccountSubProfileEventType::CREATED;
    eventData.osAccountId_ = 100;
    eventData.subspaceId_ = 200;

    EXPECT_CALL(*callback, OnSpaceAccountsChanged(testing::_)).Times(1);
    ErrCode result = DistributedAccountEventService::GetInstance()->OnSpaceAccountsChanged(eventData);
    EXPECT_EQ(result, ERR_OK);

    DistributedAccountEventService::GetInstance()->DeleteSpaceCallback(callback);
}

/**
 * @tc.name: DistributedAccountEventService_OnSpaceAccountsChanged003
 * @tc.desc: Test OnSpaceAccountsChanged with multiple subscribers - cover line 246-249
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SubscribeDistributedAccountModuleTest, OnSpaceAccountsChanged003, TestSize.Level3)
{
    auto callback1 = std::make_shared<MockDistributedAccountSubscribeCallback>();
    ASSERT_NE(callback1, nullptr);
    auto callback2 = std::make_shared<MockDistributedAccountSubscribeCallback>();
    ASSERT_NE(callback2, nullptr);

    std::set<DistributedAccountSubProfileEventType> types = {DistributedAccountSubProfileEventType::CREATED};
    DistributedAccountEventService::GetInstance()->AddSpaceTypes(types, callback1);
    DistributedAccountEventService::GetInstance()->AddSpaceTypes(types, callback2);

    DistributedAccountSubProfileEventData eventData;
    eventData.type_ = DistributedAccountSubProfileEventType::CREATED;
    eventData.osAccountId_ = 100;
    eventData.subspaceId_ = 200;

    EXPECT_CALL(*callback1, OnSpaceAccountsChanged(testing::_)).Times(1);
    EXPECT_CALL(*callback2, OnSpaceAccountsChanged(testing::_)).Times(1);
    ErrCode result = DistributedAccountEventService::GetInstance()->OnSpaceAccountsChanged(eventData);
    EXPECT_EQ(result, ERR_OK);

    DistributedAccountEventService::GetInstance()->DeleteSpaceCallback(callback1);
    DistributedAccountEventService::GetInstance()->DeleteSpaceCallback(callback2);
}

/**
 * @tc.name: GetSpaceTypesToRemove005
 * @tc.desc: Test OnSpaceAccountsChanged with multiple subscribers - cover line 246-249
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SubscribeDistributedAccountModuleTest, GetSpaceTypesToRemove005, TestSize.Level3)
{
    auto callback1 = std::make_shared<MockDistributedAccountSubscribeCallback>();
    ASSERT_NE(callback1, nullptr);

    std::set<DistributedAccountSubProfileEventType> types = {DistributedAccountSubProfileEventType::CREATED};
    DistributedAccountEventService::GetInstance()->AddSpaceTypes(types, callback1);
    DistributedAccountEventService::GetInstance()->spaceTypeMap_.clear();
    std::set<DistributedAccountSubProfileEventType> removeTypes;
    DistributedAccountEventService::GetInstance()->GetSpaceTypesToRemove(callback1, removeTypes);
    EXPECT_EQ(removeTypes.size(), 0);
    DistributedAccountEventService::GetInstance()->DeleteSpaceCallback(callback1);
    EXPECT_EQ(DistributedAccountEventService::GetInstance()->spaceCallbackMap_.size(), 0);
}