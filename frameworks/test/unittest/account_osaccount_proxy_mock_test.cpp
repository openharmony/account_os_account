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

#include <gmock/gmock.h>
#include "os_account_constants.h"
#include "os_account_manager.h"

namespace OHOS {
namespace AccountTest {
namespace {
const std::int32_t TEST_USER_ID = 101;
const std::int32_t MAIN_ACCOUNT_ID = 100;
const std::string STRING_NAME = "name";
const std::string STRING_TEST_NAME = "test_account_name";
const std::string STRING_DOMAIN_VALID = "TestDomainMT";
const std::string STRING_DOMAIN_ACCOUNT_NAME_VALID = "TestDomainAccountNameMT";
const std::string CONSTANT_PRINT = "constraint.print";
const std::vector<std::string> CONSTANTS_VECTOR {
    "constraint.print",
    "constraint.screen.timeout.set",
    "constraint.share.into.profile"
};
const std::vector<std::string> CONSTANTS_VECTOR_TEST {
    "constraint.private.dns.set",
};
const std::string PHOTO_IMG =
    "data:image/"
    "png;base64,"
    "iVBORw0KGgoAAAANSUhEUgAAABUAAAAXCAIAAABrvZPKAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAEXRFWHRTb2Z0d2FyZQBTbmlwYXN0ZV0Xzt0AAA"
    "FBSURBVDiN7ZQ/S8NQFMVPxU/QCx06GBzrkqUZ42rBbHWUBDqYxSnUoTxXydCSycVsgltfBiFDR8HNdHGxY4nQQAPvMzwHsWn+KMWsPdN7h/"
    "vj3He5vIaUEjV0UAfe85X83KMBT7N75JEXVdSlfEAVfPRyZ5yfIrBoUkVlMU82Hkp8wu9ddt1vFew4sIiIiKwgzcXIvN7GTZOvpZRrbja3tDG/"
    "D3I1NZvmdCXz+XOv5wJANKHOVYjRTAghxIyh0FHKb+0QQH5+kXf2zkYGAG0oFr5RfnK8DAGkwY19wliRT2L448vjv0YGQFVa8VKdDXUU+"
    "faFUxpblhxYRNRzmd6FNnS0H3/X/VH6j0IIIRxMLJ5k/j/2L/"
    "zchW8pKj7iFAA0R2wajl5d46idlR3+GtPV2XOvQ3bBNvyFs8U39v9PLX0Bp0CN+yY0OAEAAAAASUVORK5CYII=";
}

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AccountSA;

class TestOsAccountSubscriber : public OsAccountSubscriber {
public:
    void OnAccountsChanged(const int& id) {}
};

class AccountOsProxyMockTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void AccountOsProxyMockTest::SetUpTestCase(void)
{}

void AccountOsProxyMockTest::TearDownTestCase(void)
{}

void AccountOsProxyMockTest::SetUp(void)
{}

void AccountOsProxyMockTest::TearDown(void)
{}

/**
 * @tc.name: OsAccountTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, OsAccountTest001, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = OsAccountManager::CreateOsAccount(STRING_TEST_NAME, OsAccountType::ADMIN, osAccountInfo);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}

/**
 * @tc.name: CreateOsAccountForDomainTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, CreateOsAccountForDomainTest001, TestSize.Level1)
{
    DomainAccountInfo domainInfo(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    OsAccountType type = NORMAL;
    OsAccountInfo osAccountInfo;
    ErrCode errCode = OsAccountManager::CreateOsAccountForDomain(type, domainInfo, osAccountInfo);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}

/**
 * @tc.name: RemoveOsAccountTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, RemoveOsAccountTest001, TestSize.Level1)
{
    ErrCode errCode = OsAccountManager::OsAccountManager::RemoveOsAccount(TEST_USER_ID);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}

/**
 * @tc.name: IsOsAccountExistsTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, IsOsAccountExistsTest001, TestSize.Level1)
{
    bool isOsAccountExists = false;
    ErrCode errCode = OsAccountManager::IsOsAccountExists(TEST_USER_ID, isOsAccountExists);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
    ASSERT_EQ(isOsAccountExists, false);
}

/**
 * @tc.name: IsOsAccountActivedTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, IsOsAccountActivedTest001, TestSize.Level1)
{
    bool isOsAccountActived = false;
    ErrCode errCode = OsAccountManager::IsOsAccountActived(TEST_USER_ID, isOsAccountActived);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
    ASSERT_EQ(isOsAccountActived, false);
}

/**
 * @tc.name: IsOsAccountConstraintEnableTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, IsOsAccountConstraintEnableTest001, TestSize.Level1)
{
    bool isEnable = true;
    ErrCode errCode =
        OsAccountManager::IsOsAccountConstraintEnable(TEST_USER_ID, CONSTANT_PRINT, isEnable);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
    ASSERT_EQ(isEnable, false);
}

/**
 * @tc.name: IsOsAccountVerifiedTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, IsOsAccountVerifiedTest001, TestSize.Level1)
{
    bool isVerified = true;
    ErrCode errCode = OsAccountManager::IsOsAccountVerified(TEST_USER_ID, isVerified);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
    ASSERT_EQ(isVerified, false);
}

/**
 * @tc.name: GetCreatedOsAccountsCountTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, GetCreatedOsAccountsCountTest001, TestSize.Level1)
{
    uint32_t osAccountsCount = 0;
    ErrCode errCode = OsAccountManager::GetCreatedOsAccountsCount(osAccountsCount);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}

/**
 * @tc.name: GetOsAccountLocalIdFromProcessTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, GetOsAccountLocalIdFromProcessTest001, TestSize.Level1)
{
    int32_t id = -1;
    ErrCode errCode = OsAccountManager::GetOsAccountLocalIdFromProcess(id);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}

/**
 * @tc.name: IsMainOsAccountTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, IsMainOsAccountTest001, TestSize.Level1)
{
    bool isMainOsAccount = false;
    ErrCode errCode = OsAccountManager::IsMainOsAccount(isMainOsAccount);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}

/**
 * @tc.name: GetOsAccountLocalIdFromDomainTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, GetOsAccountLocalIdFromDomainTest001, TestSize.Level1)
{
    std::string testDomainName = "test_domain_name";
    std::string testDomain = "test_domain";
    DomainAccountInfo domainInfo(testDomainName, testDomain);
    int32_t resID = -1;
    ErrCode errCode = OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, resID);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}

/**
 * @tc.name: QueryMaxOsAccountNumberTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, QueryMaxOsAccountNumberTest001, TestSize.Level1)
{
    int32_t maxOsAccountNumber = 0;
    ErrCode errCode = OsAccountManager::QueryMaxOsAccountNumber(maxOsAccountNumber);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}

/**
 * @tc.name: GetOsAccountAllConstraintsTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, GetOsAccountAllConstraintsTest001, TestSize.Level1)
{
    std::vector<std::string> constraints;
    ErrCode errCode = OsAccountManager::GetOsAccountAllConstraints(TEST_USER_ID, constraints);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}

/**
 * @tc.name: QueryAllCreatedOsAccountsTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, QueryAllCreatedOsAccountsTest001, TestSize.Level1)
{
    std::vector<std::string> constraints;
    ErrCode errCode = OsAccountManager::GetOsAccountAllConstraints(TEST_USER_ID, constraints);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}

/**
 * @tc.name: QueryCurrentOsAccountTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, QueryCurrentOsAccountTest001, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = OsAccountManager::QueryCurrentOsAccount(osAccountInfo);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}

/**
 * @tc.name: QueryOsAccountByIdTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, QueryOsAccountByIdTest001, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = OsAccountManager::QueryOsAccountById(TEST_USER_ID, osAccountInfo);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}

/**
 * @tc.name: GetOsAccountTypeFromProcessTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, GetOsAccountTypeFromProcessTest001, TestSize.Level1)
{
    OsAccountType type = OsAccountType::ADMIN;
    ErrCode errCode = OsAccountManager::GetOsAccountTypeFromProcess(type);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}

/**
 * @tc.name: GetOsAccountProfilePhotoTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, GetOsAccountProfilePhotoTest001, TestSize.Level1)
{
    std::string photo;
    ErrCode errCode = OsAccountManager::GetOsAccountProfilePhoto(TEST_USER_ID, photo);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}

/**
 * @tc.name: IsMultiOsAccountEnableTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, IsMultiOsAccountEnableTest001, TestSize.Level1)
{
    bool isMultiOsAccountEnable = false;
    ErrCode errCode = OsAccountManager::IsMultiOsAccountEnable(isMultiOsAccountEnable);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}

/**
 * @tc.name: SetOsAccountNameTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, SetOsAccountNameTest001, TestSize.Level1)
{
    ErrCode errCode = OsAccountManager::SetOsAccountName(TEST_USER_ID, STRING_NAME);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}

/**
 * @tc.name: SetOsAccountConstraintsTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, SetOsAccountConstraintsTest001, TestSize.Level1)
{
    bool enable = false;
    ErrCode errCode = OsAccountManager::SetOsAccountConstraints(TEST_USER_ID, CONSTANTS_VECTOR, enable);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}

/**
 * @tc.name: SetOsAccountProfilePhotoTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, SetOsAccountProfilePhotoTest001, TestSize.Level1)
{
    ErrCode errCode = OsAccountManager::SetOsAccountProfilePhoto(TEST_USER_ID, PHOTO_IMG);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}

/**
 * @tc.name: GetDistributedVirtualDeviceIdTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, GetDistributedVirtualDeviceIdTest001, TestSize.Level1)
{
    std::string deviceId;
    ErrCode errCode = OsAccountManager::GetDistributedVirtualDeviceId(deviceId);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_DISTRIBUTED_VIRTUAL_DEVICE_ID_ERROR, errCode);
}

/**
 * @tc.name: ActivateOsAccountTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, ActivateOsAccountTest001, TestSize.Level1)
{
    ErrCode errCode = OsAccountManager::ActivateOsAccount(TEST_USER_ID);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}

/**
 * @tc.name: StartOsAccountTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, StartOsAccountTest001, TestSize.Level1)
{
    ErrCode errCode = OsAccountManager::StartOsAccount(TEST_USER_ID);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}

/**
 * @tc.name: StopOsAccountTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, StopOsAccountTest001, TestSize.Level1)
{
    ErrCode errCode = OsAccountManager::StopOsAccount(TEST_USER_ID);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}

/**
 * @tc.name: GetOsAccountLocalIdBySerialNumberTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, GetOsAccountLocalIdBySerialNumberTest001, TestSize.Level1)
{
    int32_t id = 0;
    ErrCode errCode = OsAccountManager::GetOsAccountLocalIdBySerialNumber(
        Constants::CARRY_NUM * Constants::SERIAL_NUMBER_NUM_START_FOR_ADMIN + 1, id);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}

/**
 * @tc.name: GetSerialNumberByOsAccountLocalIdTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, GetSerialNumberByOsAccountLocalIdTest001, TestSize.Level1)
{
    int64_t serialNumber;
    ErrCode errCode = OsAccountManager::GetSerialNumberByOsAccountLocalId(TEST_USER_ID, serialNumber);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}

/**
 * @tc.name: SubscribeOsAccountTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, SubscribeOsAccountTest001, TestSize.Level1)
{
    auto subscriber = std::make_shared<TestOsAccountSubscriber>();
    ASSERT_NE(nullptr, subscriber);
    ErrCode errCode = OsAccountManager::SubscribeOsAccount(subscriber);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_APP_ACCOUNT_PROXY_IS_NULLPTR, errCode);
}

/**
 * @tc.name: UnsubscribeOsAccountTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, UnsubscribeOsAccountTest001, TestSize.Level1)
{
    auto subscriber = std::make_shared<TestOsAccountSubscriber>();
    ASSERT_NE(nullptr, subscriber);
    ErrCode errCode = OsAccountManager::UnsubscribeOsAccount(subscriber);
    ASSERT_EQ(ERR_APPACCOUNT_KIT_APP_ACCOUNT_PROXY_IS_NULLPTR, errCode);
}

/**
 * @tc.name: GetOsAccountSwitchModTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, GetOsAccountSwitchModTest001, TestSize.Level1)
{
    ASSERT_EQ(OS_ACCOUNT_SWITCH_MOD::ERROR_MOD, OsAccountManager::GetOsAccountSwitchMod());
}

/**
 * @tc.name: IsCurrentOsAccountVerifiedTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, IsCurrentOsAccountVerifiedTest001, TestSize.Level1)
{
    bool isVerified = true;
    ErrCode errCode = OsAccountManager::IsCurrentOsAccountVerified(isVerified);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}

/**
 * @tc.name: IsOsAccountCompletedTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, IsOsAccountCompletedTest001, TestSize.Level1)
{
    bool isOsAccountCompleted = true;
    ErrCode errCode = OsAccountManager::IsOsAccountCompleted(MAIN_ACCOUNT_ID, isOsAccountCompleted);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}

/**
 * @tc.name: SetCurrentOsAccountIsVerifiedTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, SetCurrentOsAccountIsVerifiedTest001, TestSize.Level1)
{
    ErrCode errCode = OsAccountManager::SetCurrentOsAccountIsVerified(false);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}

/**
 * @tc.name: SetOsAccountIsVerifiedTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, SetOsAccountIsVerifiedTest001, TestSize.Level1)
{
    ErrCode errCode = OsAccountManager::SetOsAccountIsVerified(TEST_USER_ID, true);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}

/**
 * @tc.name: GetCreatedOsAccountNumFromDatabaseTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, GetCreatedOsAccountNumFromDatabaseTest001, TestSize.Level1)
{
    int32_t createdOsAccountNum = -1;
    ErrCode errCode = OsAccountManager::GetCreatedOsAccountNumFromDatabase("", createdOsAccountNum);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}

/**
 * @tc.name: GetSerialNumberFromDatabaseTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, GetSerialNumberFromDatabaseTest001, TestSize.Level1)
{
    int64_t serialNumber = -1;
    ErrCode errCode = OsAccountManager::GetSerialNumberFromDatabase("", serialNumber);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}

/**
 * @tc.name: GetMaxAllowCreateIdFromDatabaseTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, GetMaxAllowCreateIdFromDatabaseTest001, TestSize.Level1)
{
    int32_t maxAllowCreateId = -1;
    ErrCode errCode = OsAccountManager::GetMaxAllowCreateIdFromDatabase("", maxAllowCreateId);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}

/**
 * @tc.name: GetOsAccountFromDatabaseTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, GetOsAccountFromDatabaseTest001, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = OsAccountManager::GetOsAccountFromDatabase("", MAIN_ACCOUNT_ID, osAccountInfo);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}

/**
 * @tc.name: GetOsAccountListFromDatabaseTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, GetOsAccountListFromDatabaseTest001, TestSize.Level1)
{
    std::vector<OsAccountInfo> osAccountList;
    ErrCode errCode = OsAccountManager::GetOsAccountListFromDatabase("", osAccountList);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}

/**
 * @tc.name: QueryActiveOsAccountIdsTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, QueryActiveOsAccountIdsTest001, TestSize.Level1)
{
    std::vector<int32_t> ids;
    ErrCode errCode = OsAccountManager::QueryActiveOsAccountIds(ids);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}

/**
 * @tc.name: QueryOsAccountConstraintSourceTypesTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, QueryOsAccountConstraintSourceTypesTest001, TestSize.Level1)
{
    std::vector<ConstraintSourceTypeInfo> constraintSourceTypeInfos;
    ErrCode errCode = OsAccountManager::QueryOsAccountConstraintSourceTypes(
        MAIN_ACCOUNT_ID, CONSTANT_PRINT, constraintSourceTypeInfos);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}

/**
 * @tc.name: SetGlobalOsAccountConstraintsTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, SetGlobalOsAccountConstraintsTest001, TestSize.Level1)
{
    ErrCode errCode = OsAccountManager::SetGlobalOsAccountConstraints(
        CONSTANTS_VECTOR_TEST, true, TEST_USER_ID, true);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}

/**
 * @tc.name: SetSpecificOsAccountConstraintsTest001
 * @tc.desc: Test func with proxy is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOsProxyMockTest, SetSpecificOsAccountConstraintsTest001, TestSize.Level1)
{
    ErrCode errCode = OsAccountManager::SetSpecificOsAccountConstraints(
        CONSTANTS_VECTOR, true, MAIN_ACCOUNT_ID, TEST_USER_ID, true);
    ASSERT_EQ(ERR_OSACCOUNT_KIT_GET_SYSTEM_ABILITY_MANAGER_ERROR, errCode);
}
}  // namespace AccountTest
}  // namespace OHOS