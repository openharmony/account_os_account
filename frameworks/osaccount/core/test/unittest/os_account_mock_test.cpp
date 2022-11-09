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

#define private public
#include "os_account.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string STRING_NAME = "name";
const std::int32_t MAIN_ACCOUNT_ID = 100;
const std::string PHOTO_IMG =
    "data:image/"
    "png;base64,"
    "iVBORw0KGgoAAAANSUhEUgAAABUAAAAXCAIAAABrvZPKAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAEXRFWHRTb2Z0d2FyZQBTbmlwYXN0ZV0Xzt0AAA"
    "FBSURBVDiN7ZQ/S8NQFMVPxU/QCx06GBzrkqUZ42rBbHWUBDqYxSnUoTxXydCSycVsgltfBiFDR8HNdHGxY4nQQAPvMzwHsWn+KMWsPdN7h/"
    "vj3He5vIaUEjV0UAfe85X83KMBT7N75JEXVdSlfEAVfPRyZ5yfIrBoUkVlMU82Hkp8wu9ddt1vFew4sIiIiKwgzcXIvN7GTZOvpZRrbja3tDG/"
    "D3I1NZvmdCXz+XOv5wJANKHOVYjRTAghxIyh0FHKb+0QQH5+kXf2zkYGAG0oFr5RfnK8DAGkwY19wliRT2L448vjv0YGQFVa8VKdDXUU+"
    "faFUxpblhxYRNRzmd6FNnS0H3/X/VH6j0IIIRxMLJ5k/j/2L/"
    "zchW8pKj7iFAA0R2wajl5d46idlR3+GtPV2XOvQ3bBNvyFs8U39v9PLX0Bp0CN+yY0OAEAAAAASUVORK5CYII=";
const std::vector<std::string> CONSTANTS_VECTOR {
    "constraint.sms.use"
};
const std::string CONSTANT_PRINT = "constraint.print";
std::shared_ptr<OsAccount> g_osAccount = nullptr;
std::string storeID = "";
}  // namespace

class OsAccountMockTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void OsAccountMockTest::SetUpTestCase(void)
{
    g_osAccount = std::make_shared<OsAccount>();
}

void OsAccountMockTest::TearDownTestCase(void)
{}

void OsAccountMockTest::SetUp(void)
{}

void OsAccountMockTest::TearDown(void)
{}

/**
 * @tc.name: RemoveOsAccountMockTest001
 * @tc.desc: Test RemoveOsAccount getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, RemoveOsAccountMockTest001, TestSize.Level1)
{
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->RemoveOsAccount(MAIN_ACCOUNT_ID+1));
}

/**
 * @tc.name: IsOsAccountExistsTest001
 * @tc.desc: Test IsOsAccountExists getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, IsOsAccountExistsTest001, TestSize.Level1)
{
    bool isOsAccountExists;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->IsOsAccountExists(MAIN_ACCOUNT_ID, isOsAccountExists));
}

/**
 * @tc.name: IsOsAccountConstraintEnableTest001
 * @tc.desc: Test IsOsAccountConstraintEnable getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, IsOsAccountConstraintEnableTest001, TestSize.Level1)
{
    bool isConstraintEnable;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->IsOsAccountConstraintEnable(MAIN_ACCOUNT_ID, CONSTANT_PRINT, isConstraintEnable));
}

/**
 * @tc.name: IsMainOsAccountMockTest001
 * @tc.desc: Test IsMainOsAccount getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, IsMainOsAccountMockTest001, TestSize.Level1)
{
    bool isMainOsAccount;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->IsMainOsAccount(isMainOsAccount));
}

/**
 * @tc.name: QueryOsAccountByIdTest001
 * @tc.desc: Test QueryOsAccountById getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, QueryOsAccountByIdTest001, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->QueryOsAccountById(MAIN_ACCOUNT_ID, osAccountInfo));
}

/**
 * @tc.name: GetOsAccountProfilePhotoTest001
 * @tc.desc: Test GetOsAccountProfilePhoto getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, GetOsAccountProfilePhotoTest001, TestSize.Level1)
{
    std::string photo;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->GetOsAccountProfilePhoto(MAIN_ACCOUNT_ID, photo));
}

/**
 * @tc.name: SetOsAccountNameTest001
 * @tc.desc: Test SetOsAccountName getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, SetOsAccountNameTest001, TestSize.Level1)
{
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->SetOsAccountName(MAIN_ACCOUNT_ID, STRING_NAME));
}

/**
 * @tc.name: SetOsAccountConstraintsTest001
 * @tc.desc: Test SetOsAccountConstraints getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, SetOsAccountConstraintsTest001, TestSize.Level1)
{
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->SetOsAccountConstraints(MAIN_ACCOUNT_ID, CONSTANTS_VECTOR, true));
}

/**
 * @tc.name: SetOsAccountProfilePhotoTest001
 * @tc.desc: Test SetOsAccountProfilePhoto getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, SetOsAccountProfilePhotoTest001, TestSize.Level1)
{
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->SetOsAccountProfilePhoto(MAIN_ACCOUNT_ID, PHOTO_IMG));
}

/**
 * @tc.name: ActivateOsAccountMockTest001
 * @tc.desc: Test ActivateOsAccount getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, ActivateOsAccountMockTest001, TestSize.Level1)
{
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->ActivateOsAccount(MAIN_ACCOUNT_ID));
}

/**
 * @tc.name: StartOsAccountMockTest001
 * @tc.desc: Test StartOsAccount getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, StartOsAccountMockTest001, TestSize.Level1)
{
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->StartOsAccount(MAIN_ACCOUNT_ID));
}

/**
 * @tc.name: StopOsAccountMockTest001
 * @tc.desc: Test StopOsAccount getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, StopOsAccountMockTest001, TestSize.Level1)
{
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->StopOsAccount(MAIN_ACCOUNT_ID));
}

class TestOsAccountSubscriber : public OsAccountSubscriber {
public:
    virtual void OnAccountsChanged(const int& id)
    {
        return;
    }

    OHOS::ErrCode GetSubscribeInfo(OsAccountSubscribeInfo& subscribeInfo)
    {
        return OHOS::ERR_OK;
    }
};

/**
 * @tc.name: SubscribeOsAccountMockTest001
 * @tc.desc: Test SubscribeOsAccount getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, SubscribeOsAccountMockTest001, TestSize.Level1)
{
    std::shared_ptr<TestOsAccountSubscriber> subscriber = std::make_shared<TestOsAccountSubscriber>();
    EXPECT_EQ(ERR_APPACCOUNT_KIT_APP_ACCOUNT_PROXY_IS_NULLPTR,
        g_osAccount->SubscribeOsAccount(subscriber));
}

/**
 * @tc.name: UnsubscribeOsAccountMockTest001
 * @tc.desc: Test UnsubscribeOsAccount getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, UnsubscribeOsAccountMockTest001, TestSize.Level1)
{
    std::shared_ptr<TestOsAccountSubscriber> subscriber = std::make_shared<TestOsAccountSubscriber>();
    EXPECT_EQ(ERR_APPACCOUNT_KIT_APP_ACCOUNT_PROXY_IS_NULLPTR,
        g_osAccount->UnsubscribeOsAccount(subscriber));
}

/**
 * @tc.name: DumpStateTest001
 * @tc.desc: Test DumpState getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, DumpStateTest001, TestSize.Level1)
{
    std::vector<std::string> state;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->DumpState(MAIN_ACCOUNT_ID, state));
}

/**
 * @tc.name: IsOsAccountCompletedTest001
 * @tc.desc: Test IsOsAccountCompleted getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, IsOsAccountCompletedTest001, TestSize.Level1)
{
    bool isOsAccountCompleted;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->IsOsAccountCompleted(MAIN_ACCOUNT_ID, isOsAccountCompleted));
}

/**
 * @tc.name: SetOsAccountIsVerifiedTest001
 * @tc.desc: Test SetOsAccountIsVerified getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, SetOsAccountIsVerifiedTest001, TestSize.Level1)
{
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->SetOsAccountIsVerified(MAIN_ACCOUNT_ID, false));
}

/**
 * @tc.name: GetOsAccountFromDatabaseTest001
 * @tc.desc: Test GetOsAccountFromDatabase getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, GetOsAccountFromDatabaseTest001, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->GetOsAccountFromDatabase(storeID, MAIN_ACCOUNT_ID, osAccountInfo));
}

/**
 * @tc.name: QueryOsAccountConstraintSourceTypesTest001
 * @tc.desc: Test QueryOsAccountConstraintSourceTypes getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, QueryOsAccountConstraintSourceTypesTest001, TestSize.Level1)
{
    std::vector<ConstraintSourceTypeInfo> constraintSourceTypeInfos;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->QueryOsAccountConstraintSourceTypes(MAIN_ACCOUNT_ID, CONSTANT_PRINT, constraintSourceTypeInfos));
}

/**
 * @tc.name: SetGlobalOsAccountConstraintsTest001
 * @tc.desc: Test SetGlobalOsAccountConstraints getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, SetGlobalOsAccountConstraintsTest001, TestSize.Level1)
{
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->SetGlobalOsAccountConstraints(CONSTANTS_VECTOR, true, MAIN_ACCOUNT_ID, true));
}

/**
 * @tc.name: SetSpecificOsAccountConstraintsTest001
 * @tc.desc: Test SetSpecificOsAccountConstraints getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, SetSpecificOsAccountConstraintsTest001, TestSize.Level1)
{
    std::vector<ConstraintSourceTypeInfo> constraintSourceTypeInfos;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->SetSpecificOsAccountConstraints(CONSTANTS_VECTOR, true, MAIN_ACCOUNT_ID, MAIN_ACCOUNT_ID, true));
}
