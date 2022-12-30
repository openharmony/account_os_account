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
const std::string STRING_EMPTY = "";
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
const std::string STRING_DOMAIN_VALID = "TestDomainUT";
const std::string STRING_DOMAIN_ACCOUNT_NAME_VALID = "TestDomainAccountNameUT";

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
 * @tc.name: CreateOsAccountMockTest001
 * @tc.desc: Test CreateOsAccount getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, CreateOsAccountMockTest001, TestSize.Level1)
{
    OsAccountType type = NORMAL;
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->CreateOsAccount(STRING_NAME, type, osAccountInfo));
}

/**
 * @tc.name: CreateOsAccountForDomainMockTest001
 * @tc.desc: Test CreateOsAccountForDomain getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, CreateOsAccountForDomainMockTest001, TestSize.Level1)
{
    OsAccountType type = NORMAL;
    DomainAccountInfo domainInfo(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->CreateOsAccountForDomain(type, domainInfo, osAccountInfo));
}

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
 * @tc.name: IsOsAccountExistsMockTest001
 * @tc.desc: Test IsOsAccountExists getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, IsOsAccountExistsMockTest001, TestSize.Level1)
{
    bool isOsAccountExists;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->IsOsAccountExists(MAIN_ACCOUNT_ID, isOsAccountExists));
}

/**
 * @tc.name: IsOsAccountActivedMockTest001
 * @tc.desc: Test IsOsAccountActived getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, IsOsAccountActivedMockTest001, TestSize.Level1)
{
    bool isOsAccountActived;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->IsOsAccountActived(MAIN_ACCOUNT_ID, isOsAccountActived));
}

/**
 * @tc.name: IsOsAccountConstraintEnableMockTest001
 * @tc.desc: Test IsOsAccountConstraintEnable getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, IsOsAccountConstraintEnableMockTest001, TestSize.Level1)
{
    bool isConstraintEnable;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->IsOsAccountConstraintEnable(MAIN_ACCOUNT_ID, CONSTANT_PRINT, isConstraintEnable));
}

/**
 * @tc.name: IsOsAccountVerifiedMockTest001
 * @tc.desc: Test IsOsAccountVerified getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, IsOsAccountVerifiedMockTest001, TestSize.Level1)
{
    bool isVerified;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->IsOsAccountVerified(MAIN_ACCOUNT_ID, isVerified));
}

/**
 * @tc.name: GetCreatedOsAccountsCountMockTest001
 * @tc.desc: Test GetCreatedOsAccountsCount getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, GetCreatedOsAccountsCountMockTest001, TestSize.Level1)
{
    unsigned int osAccountsCount;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->GetCreatedOsAccountsCount(osAccountsCount));
}

/**
 * @tc.name: GetOsAccountLocalIdFromProcessMockTest001
 * @tc.desc: Test GetOsAccountLocalIdFromProcess getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, GetOsAccountLocalIdFromProcessMockTest001, TestSize.Level1)
{
    int id;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->GetOsAccountLocalIdFromProcess(id));
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
 * @tc.name: GetOsAccountLocalIdFromDomainMockTest001
 * @tc.desc: Test GetOsAccountLocalIdFromDomain getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, GetOsAccountLocalIdFromDomainMockTest001, TestSize.Level1)
{
    DomainAccountInfo domainInfo(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    int id;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->GetOsAccountLocalIdFromDomain(domainInfo, id));
}

/**
 * @tc.name: QueryMaxOsAccountNumberMockTest001
 * @tc.desc: Test QueryMaxOsAccountNumber getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, QueryMaxOsAccountNumberMockTest001, TestSize.Level1)
{
    int maxOsAccountNumber;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->QueryMaxOsAccountNumber(maxOsAccountNumber));
}

/**
 * @tc.name: GetOsAccountAllConstraintsMockTest001
 * @tc.desc: Test GetOsAccountAllConstraints getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, GetOsAccountAllConstraintsMockTest001, TestSize.Level1)
{
    std::vector<std::string> constraints;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->GetOsAccountAllConstraints(MAIN_ACCOUNT_ID, constraints));
}

/**
 * @tc.name: QueryAllCreatedOsAccountsMockTest001
 * @tc.desc: Test QueryAllCreatedOsAccounts getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, QueryAllCreatedOsAccountsMockTest001, TestSize.Level1)
{
    std::vector<OsAccountInfo> osAccountInfos;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->QueryAllCreatedOsAccounts(osAccountInfos));
}

/**
 * @tc.name: QueryCurrentOsAccountMockTest001
 * @tc.desc: Test QueryCurrentOsAccount getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, QueryCurrentOsAccountMockTest001, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->QueryCurrentOsAccount(osAccountInfo));
}

/**
 * @tc.name: QueryOsAccountByIdMockTest001
 * @tc.desc: Test QueryOsAccountById getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, QueryOsAccountByIdMockTest001, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->QueryOsAccountById(MAIN_ACCOUNT_ID, osAccountInfo));
}

/**
 * @tc.name: GetOsAccountTypeFromProcessMockTest001
 * @tc.desc: Test GetOsAccountTypeFromProcess getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, GetOsAccountTypeFromProcessMockTest001, TestSize.Level1)
{
    OsAccountType type;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->GetOsAccountTypeFromProcess(type));
}

/**
 * @tc.name: GetOsAccountProfilePhotoMockTest001
 * @tc.desc: Test GetOsAccountProfilePhoto getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, GetOsAccountProfilePhotoMockTest001, TestSize.Level1)
{
    std::string photo;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->GetOsAccountProfilePhoto(MAIN_ACCOUNT_ID, photo));
}

/**
 * @tc.name: IsMultiOsAccountEnableMockTest001
 * @tc.desc: Test IsMultiOsAccountEnable getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, IsMultiOsAccountEnableMockTest001, TestSize.Level1)
{
    bool isMultiOsAccountEnable;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->IsMultiOsAccountEnable(isMultiOsAccountEnable));
}

/**
 * @tc.name: SetOsAccountNameMockTest001
 * @tc.desc: Test SetOsAccountName getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, SetOsAccountNameMockTest001, TestSize.Level1)
{
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->SetOsAccountName(MAIN_ACCOUNT_ID, STRING_NAME));
}

/**
 * @tc.name: SetOsAccountConstraintsMockTest001
 * @tc.desc: Test SetOsAccountConstraints getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, SetOsAccountConstraintsMockTest001, TestSize.Level1)
{
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->SetOsAccountConstraints(MAIN_ACCOUNT_ID, CONSTANTS_VECTOR, true));
}

/**
 * @tc.name: SetOsAccountProfilePhotoMockTest001
 * @tc.desc: Test SetOsAccountProfilePhoto getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, SetOsAccountProfilePhotoMockTest001, TestSize.Level1)
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

/**
 * @tc.name: GetOsAccountLocalIdBySerialNumberMockTest001
 * @tc.desc: Test GetOsAccountLocalIdBySerialNumber getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, GetOsAccountLocalIdBySerialNumberMockTest001, TestSize.Level1)
{
    int id;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, g_osAccount->GetOsAccountLocalIdBySerialNumber(
        Constants::CARRY_NUM * Constants::SERIAL_NUMBER_NUM_START_FOR_ADMIN + 1, id));
}

/**
 * @tc.name: GetSerialNumberByOsAccountLocalIdMockTest001
 * @tc.desc: Test GetSerialNumberByOsAccountLocalId getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, GetSerialNumberByOsAccountLocalIdMockTest001, TestSize.Level1)
{
    int64_t serialNumber;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->GetSerialNumberByOsAccountLocalId(MAIN_ACCOUNT_ID, serialNumber));
}

class TestOsAccountSubscriber : public OsAccountSubscriber {
public:
    void OnAccountsChanged(const int& id) {}
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
 * @tc.name: GetOsAccountSwitchModMockTest001
 * @tc.desc: Test GetOsAccountSwitchMod getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, GetOsAccountSwitchModMockTest001, TestSize.Level1)
{
    EXPECT_EQ(OS_ACCOUNT_SWITCH_MOD::ERROR_MOD, g_osAccount->GetOsAccountSwitchMod());
}

/**
 * @tc.name: DumpStateMockTest001
 * @tc.desc: Test DumpState getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, DumpStateMockTest001, TestSize.Level1)
{
    std::vector<std::string> state;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->DumpState(MAIN_ACCOUNT_ID, state));
}

/**
 * @tc.name: IsCurrentOsAccountVerifiedMockTest001
 * @tc.desc: Test IsCurrentOsAccountVerified getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, IsCurrentOsAccountVerifiedMockTest001, TestSize.Level1)
{
    bool isVerified;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->IsCurrentOsAccountVerified(isVerified));
}

/**
 * @tc.name: IsOsAccountCompletedMockTest001
 * @tc.desc: Test IsOsAccountCompleted getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, IsOsAccountCompletedMockTest001, TestSize.Level1)
{
    bool isOsAccountCompleted;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->IsOsAccountCompleted(MAIN_ACCOUNT_ID, isOsAccountCompleted));
}

/**
 * @tc.name: SetCurrentOsAccountIsVerifiedMockTest001
 * @tc.desc: Test SetCurrentOsAccountIsVerified getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, SetCurrentOsAccountIsVerifiedMockTest001, TestSize.Level1)
{
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->SetCurrentOsAccountIsVerified(false));
}

/**
 * @tc.name: SetOsAccountIsVerifiedMockTest001
 * @tc.desc: Test SetOsAccountIsVerified getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, SetOsAccountIsVerifiedMockTest001, TestSize.Level1)
{
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->SetOsAccountIsVerified(MAIN_ACCOUNT_ID, false));
}

/**
 * @tc.name: GetCreatedOsAccountNumFromDatabaseMockTest001
 * @tc.desc: Test GetCreatedOsAccountNumFromDatabase getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, GetCreatedOsAccountNumFromDatabaseMockTest001, TestSize.Level1)
{
    int createdOsAccountNum;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->GetCreatedOsAccountNumFromDatabase(storeID, createdOsAccountNum));
}

/**
 * @tc.name: GetSerialNumberFromDatabaseMockTest001
 * @tc.desc: Test GetSerialNumberFromDatabase getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, GetSerialNumberFromDatabaseMockTest001, TestSize.Level1)
{
    int64_t serialNumber;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->GetSerialNumberFromDatabase(storeID, serialNumber));
}

/**
 * @tc.name: GetMaxAllowCreateIdFromDatabaseMockTest001
 * @tc.desc: Test GetMaxAllowCreateIdFromDatabase getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, GetMaxAllowCreateIdFromDatabaseMockTest001, TestSize.Level1)
{
    int id;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->GetMaxAllowCreateIdFromDatabase(storeID, id));
}

/**
 * @tc.name: GetOsAccountFromDatabaseMockTest001
 * @tc.desc: Test GetOsAccountFromDatabase getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, GetOsAccountFromDatabaseMockTest001, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->GetOsAccountFromDatabase(storeID, MAIN_ACCOUNT_ID, osAccountInfo));
}

/**
 * @tc.name: GetOsAccountListFromDatabaseMockTest001
 * @tc.desc: Test GetOsAccountListFromDatabase getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, GetOsAccountListFromDatabaseMockTest001, TestSize.Level1)
{
    std::vector<OsAccountInfo> osAccountList;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->GetOsAccountListFromDatabase(storeID, osAccountList));
}

/**
 * @tc.name: QueryActiveOsAccountIdsMockTest001
 * @tc.desc: Test QueryActiveOsAccountIds getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, QueryActiveOsAccountIdsMockTest001, TestSize.Level1)
{
    std::vector<int32_t> ids;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->QueryActiveOsAccountIds(ids));
}

/**
 * @tc.name: QueryOsAccountConstraintSourceTypesMockTest001
 * @tc.desc: Test QueryOsAccountConstraintSourceTypes getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, QueryOsAccountConstraintSourceTypesMockTest001, TestSize.Level1)
{
    std::vector<ConstraintSourceTypeInfo> constraintSourceTypeInfos;
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->QueryOsAccountConstraintSourceTypes(MAIN_ACCOUNT_ID, CONSTANT_PRINT, constraintSourceTypeInfos));
}

/**
 * @tc.name: SetGlobalOsAccountConstraintsMockTest001
 * @tc.desc: Test SetGlobalOsAccountConstraints getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, SetGlobalOsAccountConstraintsMockTest001, TestSize.Level1)
{
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->SetGlobalOsAccountConstraints(CONSTANTS_VECTOR, true, MAIN_ACCOUNT_ID, true));
}

/**
 * @tc.name: SetSpecificOsAccountConstraintsMockTest001
 * @tc.desc: Test SetSpecificOsAccountConstraints getosaccountproxy faild
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMockTest, SetSpecificOsAccountConstraintsMockTest001, TestSize.Level1)
{
    EXPECT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR,
        g_osAccount->SetSpecificOsAccountConstraints(CONSTANTS_VECTOR, true, MAIN_ACCOUNT_ID, MAIN_ACCOUNT_ID, true));
}
