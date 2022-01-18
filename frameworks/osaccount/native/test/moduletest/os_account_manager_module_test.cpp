/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "account_info.h"
#include "account_proxy.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "os_account_manager.h"
#define private public
#include "account_file_operator.h"
#include "os_account_control_file_manager.h"
#undef private
#include "os_account_constants.h"
#include "parameter.h"
#include "system_ability.h"
#include "system_ability_definition.h"
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string STRING_EMPTY = "";
const std::string STRING_NAME = "name";
const std::string STRING_TEST_NAME = "test";
const OsAccountType INT_TEST_TYPE = OsAccountType::GUEST;
const OsAccountType INT_TEST_NEGATIVE_TYPE = OsAccountType::ADMIN;
const OsAccountType INT_TEST_MAX_TYPE = OsAccountType::ADMIN;
const int ERROR_LOCAL_ID = -1;

const std::vector<std::string> CONSTANTS_VECTOR {
    "constraint.print",
    "constraint.screen.timeout.set",
    "constraint.share.into.profile"
};
const std::string CONSTANTS_STRING_WIFI = "constraint.print";
const std::string STRING_NAME_OUT_OF_RANGE =
    "name_out_of_range_"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
const std::string STRING_PHOTO_OUT_OF_RANGE =
    "extra_info_out_of_range_"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
const std::string PHOTO_IMG =
    "data:image/"
    "png;base64,"
    "iVBORw0KGgoAAAANSUhEUgAAABUAAAAXCAIAAABrvZPKAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAEXRFWHRTb2Z0d2FyZQBTbmlwYXN0ZV0Xzt0AAA"
    "FBSURBVDiN7ZQ/S8NQFMVPxU/QCx06GBzrkqUZ42rBbHWUBDqYxSnUoTxXydCSycVsgltfBiFDR8HNdHGxY4nQQAPvMzwHsWn+KMWsPdN7h/"
    "vj3He5vIaUEjV0UAfe85X83KMBT7N75JEXVdSlfEAVfPRyZ5yfIrBoUkVlMU82Hkp8wu9ddt1vFew4sIiIiKwgzcXIvN7GTZOvpZRrbja3tDG/"
    "D3I1NZvmdCXz+XOv5wJANKHOVYjRTAghxIyh0FHKb+0QQH5+kXf2zkYGAG0oFr5RfnK8DAGkwY19wliRT2L448vjv0YGQFVa8VKdDXUU+"
    "faFUxpblhxYRNRzmd6FNnS0H3/X/VH6j0IIIRxMLJ5k/j/2L/"
    "zchW8pKj7iFAA0R2wajl5d46idlR3+GtPV2XOvQ3bBNvyFs8U39v9PLX0Bp0CN+yY0OAEAAAAASUVORK5CYII=";
const std::string PHOTO_IMG_ERROR =
    "iVBORw0KGgoAAAANSUhEUgAAABUAAAAXCAIAAABrvZPKAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAEXRFWHRTb2Z0d2FyZQBTbmlwYXN0ZV0Xzt0AAA"
    "FBSURBVDiN7ZQ/S8NQFMVPxU/QCx06GBzrkqUZ42rBbHWUBDqYxSnUoTxXydCSycVsgltfBiFDR8HNdHGxY4nQQAPvMzwHsWn+KMWsPdN7h/"
    "vj3He5vIaUEjV0UAfe85X83KMBT7N75JEXVdSlfEAVfPRyZ5yfIrBoUkVlMU82Hkp8wu9ddt1vFew4sIiIiKwgzcXIvN7GTZOvpZRrbja3tDG/"
    "D3I1NZvmdCXz+XOv5wJANKHOVYjRTAghxIyh0FHKb+0QQH5+kXf2zkYGAG0oFr5RfnK8DAGkwY19wliRT2L448vjv0YGQFVa8VKdDXUU+"
    "faFUxpblhxYRNRzmd6FNnS0H3/X/VH6j0IIIRxMLJ5k/j/2L/"
    "zchW8pKj7iFAA0R2wajl5d46idlR3+GtPV2XOvQ3bBNvyFs8U39v9PLX0Bp0CN+yY0OAEAAAAASUVORK5CYII=";
const std::string STRING_DOMAIN_NAME_OUT_OF_RANGE =
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "123456789012345678901234567890";
const std::string STRING_DOMAIN_ACCOUNT_NAME_OUT_OF_RANGE =
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
const std::string STRING_DOMAIN_VALID = "TestDomainMT";
const std::string STRING_DOMAIN_ACCOUNT_NAME_VALID = "TestDomainAccountNameMT";
const std::string TEST_ACCOUNT_NAME = "TestAccountNameOS";
const std::string TEST_ACCOUNT_UID = "123456789os";
const std::string TEST_EXPECTED_UID = "DC227A5106403E85993398FD1DCF8AC32E7A8091B220DC3FD96EE1EEEECD75EA";
}  // namespace

class OsAccountManagerModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

public:
    std::shared_ptr<OsAccountControlFileManager> osAccountControlFileManager_;
    std::shared_ptr<AccountFileOperator> accountFileOperator_;
};

void OsAccountManagerModuleTest::SetUpTestCase(void)
{}

void OsAccountManagerModuleTest::TearDownTestCase(void)
{}

void OsAccountManagerModuleTest::SetUp(void)
{
    osAccountControlFileManager_ = std::make_shared<OsAccountControlFileManager>();
    accountFileOperator_ = std::make_shared<AccountFileOperator>();
    osAccountControlFileManager_->Init();
}

void OsAccountManagerModuleTest::TearDown(void)
{}

/**
 * @tc.name: OsAccountManagerModuleTest001
 * @tc.desc: Test CreateOsAccount with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGV0U
 */

HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest001, TestSize.Level0)
{
    OsAccountInfo osAccountInfoOne;
    ErrCode errCode = OsAccountManager::CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_EQ(errCode, ERR_OK);
    OsAccountInfo osAccountInfoTwo;
    osAccountControlFileManager_->GetOsAccountInfoById(osAccountInfoOne.GetLocalId(), osAccountInfoTwo);
    EXPECT_EQ(osAccountInfoOne.ToString(), osAccountInfoTwo.ToString());
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerModuleTest002
 * @tc.desc: Test CreateOsAccount with unvaild name.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest002, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    ErrCode errCode = OsAccountManager::CreateOsAccount(STRING_NAME_OUT_OF_RANGE, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_NE(errCode, ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest003
 * @tc.desc: Test CreateOsAccount with unvaild name.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest003, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    ErrCode errCode = OsAccountManager::CreateOsAccount(STRING_EMPTY, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_NE(errCode, ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest004
 * @tc.desc: Test CreateOsAccount with unvaild type.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest004, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    ErrCode errCode = OsAccountManager::CreateOsAccount(STRING_TEST_NAME, INT_TEST_NEGATIVE_TYPE, osAccountInfoOne);
    EXPECT_EQ(errCode, ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest005
 * @tc.desc: Test CreateOsAccount with unvaild type.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest005, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    ErrCode errCode = OsAccountManager::CreateOsAccount(STRING_TEST_NAME, INT_TEST_MAX_TYPE, osAccountInfoOne);
    EXPECT_EQ(errCode, ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest006
 * @tc.desc: Test CreateOsAccount when cannot find account_list.json.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest006, TestSize.Level1)
{
    std::string fileContext;
    accountFileOperator_->GetFileContentByPath(
        Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + Constants::USER_LIST_FILE_NAME, fileContext);
    accountFileOperator_->DeleteDirOrFile(
        Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + Constants::USER_LIST_FILE_NAME);
    OsAccountInfo osAccountInfoOne;
    ErrCode errCode = OsAccountManager::CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_NE(errCode, ERR_OK);
    accountFileOperator_->InputFileByPathAndContent(
        Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + Constants::USER_LIST_FILE_NAME, fileContext);
}

/**
 * @tc.name: OsAccountManagerModuleTest007
 * @tc.desc: Test RemoveOsAccount with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGV0U
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest007, TestSize.Level0)
{
    OsAccountInfo osAccountInfoOne;
    OsAccountManager::CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    EXPECT_EQ(accountFileOperator_->IsExistDir(
                  Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + osAccountInfoOne.GetPrimeKey()),
        false);
}

/**
 * @tc.name: OsAccountManagerModuleTest008
 * @tc.desc: Test RemoveOsAccount with cannot remove id.
 * @tc.type: FUNC
 * @tc.require: SR000GGV0U
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest008, TestSize.Level1)
{
    EXPECT_NE(OsAccountManager::RemoveOsAccount(Constants::START_USER_ID), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest009
 * @tc.desc: Test RemoveOsAccount with does not exists id.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest009, TestSize.Level1)
{
    EXPECT_NE(OsAccountManager::RemoveOsAccount(Constants::MAX_USER_ID + 1), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest010
 * @tc.desc: Test IsOsAccountExists with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest010, TestSize.Level1)
{
    bool isOsAccountExists = false;
    EXPECT_EQ(OsAccountManager::IsOsAccountExists(Constants::START_USER_ID, isOsAccountExists), ERR_OK);
    EXPECT_EQ(isOsAccountExists, true);
}

/**
 * @tc.name: OsAccountManagerModuleTest011
 * @tc.desc: Test IsOsAccountExists with not exists data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest011, TestSize.Level1)
{
    bool isOsAccountExists = true;
    EXPECT_EQ(OsAccountManager::IsOsAccountExists(Constants::MAX_USER_ID + 1, isOsAccountExists), ERR_OK);
    EXPECT_EQ(isOsAccountExists, false);
}

/**
 * @tc.name: OsAccountManagerModuleTest012
 * @tc.desc: Test IsOsAccountActived with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest012, TestSize.Level0)
{
    bool isOsAccountActived = false;
    EXPECT_EQ(OsAccountManager::IsOsAccountExists(Constants::ADMIN_LOCAL_ID, isOsAccountActived), ERR_OK);
    EXPECT_EQ(isOsAccountActived, true);
}

/**
 * @tc.name: OsAccountManagerModuleTest013
 * @tc.desc: Test IsOsAccountActived with not active account id.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest013, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    OsAccountManager::CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    bool isOsAccountActived = false;
    EXPECT_EQ(OsAccountManager::IsOsAccountExists(osAccountInfoOne.GetLocalId(), isOsAccountActived), ERR_OK);
    EXPECT_EQ(isOsAccountActived, true);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerModuleTest014
 * @tc.desc: Test SetOsAccountConstraints with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFE
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest014, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    OsAccountManager::CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    bool enable = false;
    EXPECT_EQ(
        OsAccountManager::SetOsAccountConstraints(osAccountInfoOne.GetLocalId(), CONSTANTS_VECTOR, enable), ERR_OK);
    OsAccountInfo osAccountInfoTwo;
    osAccountControlFileManager_->GetOsAccountInfoById(osAccountInfoOne.GetLocalId(), osAccountInfoTwo);
    std::vector<std::string> contstans = osAccountInfoTwo.GetConstraints();
    for (auto it = contstans.begin(); it != contstans.end(); it++) {
        GTEST_LOG_(INFO) << *it;
    }
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerModuleTest015
 * @tc.desc: Test SetOsAccountConstraints with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFE
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest015, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    OsAccountManager::CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    bool enable = true;
    EXPECT_EQ(
        OsAccountManager::SetOsAccountConstraints(osAccountInfoOne.GetLocalId(), CONSTANTS_VECTOR, enable), ERR_OK);
    OsAccountInfo osAccountInfoTwo;
    osAccountControlFileManager_->GetOsAccountInfoById(osAccountInfoOne.GetLocalId(), osAccountInfoTwo);
    std::vector<std::string> contstans = osAccountInfoTwo.GetConstraints();
    for (auto it = contstans.begin(); it != contstans.end(); it++) {
        GTEST_LOG_(INFO) << *it;
    }
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerModuleTest016
 * @tc.desc: Test IsOsAccountConstraintEnable with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFE SR000GH18T
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest016, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    OsAccountManager::CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    bool enable = true;
    OsAccountManager::SetOsAccountConstraints(osAccountInfoOne.GetLocalId(), CONSTANTS_VECTOR, enable);
    bool isEnable = false;
    EXPECT_EQ(
        OsAccountManager::IsOsAccountConstraintEnable(osAccountInfoOne.GetLocalId(), CONSTANTS_STRING_WIFI, isEnable),
        ERR_OK);
    EXPECT_EQ(isEnable, true);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerModuleTest017
 * @tc.desc: Test IsOsAccountConstraintEnable with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFE SR000GH18T
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest017, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    OsAccountManager::CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    bool isEnable = true;
    EXPECT_EQ(
        OsAccountManager::IsOsAccountConstraintEnable(osAccountInfoOne.GetLocalId(), CONSTANTS_STRING_WIFI, isEnable),
        ERR_OK);
    EXPECT_EQ(isEnable, false);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerModuleTest018
 * @tc.desc: Test IsMultiOsAccountEnable
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest018, TestSize.Level1)
{
    bool isMultiOsAccountEnable = false;
    EXPECT_EQ(OsAccountManager::IsMultiOsAccountEnable(isMultiOsAccountEnable), ERR_OK);
    EXPECT_EQ(isMultiOsAccountEnable, true);
}

/**
 * @tc.name: OsAccountManagerModuleTest019
 * @tc.desc: Test IsOsAccountVerified with not verified os account id.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest019, TestSize.Level1)
{
    bool isVerified = true;
    EXPECT_EQ(OsAccountManager::IsOsAccountVerified(Constants::START_USER_ID, isVerified), ERR_OK);
    EXPECT_EQ(isVerified, false);
}

/**
 * @tc.name: OsAccountManagerModuleTest020
 * @tc.desc: Test IsOsAccountVerified with does not exists os account id.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest020, TestSize.Level1)
{
    bool isVerified = true;
    EXPECT_NE(OsAccountManager::IsOsAccountVerified(Constants::MAX_USER_ID + 1, isVerified), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest021
 * @tc.desc: Test IsOsAccountVerified with does not exists os account id.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest021, TestSize.Level1)
{
    bool isVerified = true;
    EXPECT_NE(OsAccountManager::IsOsAccountVerified(Constants::MAX_USER_ID + 1, isVerified), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest022
 * @tc.desc: Test GetCreatedOsAccountsCount.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest022, TestSize.Level1)
{
    int osAccountsCount = 0;
    EXPECT_EQ(OsAccountManager::GetCreatedOsAccountsCount(osAccountsCount), ERR_OK);
    EXPECT_NE(osAccountsCount, 0);
}

/**
 * @tc.name: OsAccountManagerModuleTest023
 * @tc.desc: Test GetOsAccountLocalIdFromProcess.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFF
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest023, TestSize.Level1)
{
    int id = -1;
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromProcess(id), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest024
 * @tc.desc: Test GetOsAccountLocalIdFromUid.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFF
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest024, TestSize.Level1)
{
    int uid = 0;
    int id = -1;
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromUid(uid, id), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest025
 * @tc.desc: Test QueryMaxOsAccountNumber.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest025, TestSize.Level1)
{
    int maxOsAccountNumber = 0;
    EXPECT_EQ(OsAccountManager::QueryMaxOsAccountNumber(maxOsAccountNumber), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest026
 * @tc.desc: Test GetOsAccountAllConstraints with exisit os account id.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFE SR000GH18T
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest026, TestSize.Level1)
{
    std::vector<std::string> constraints;
    EXPECT_EQ(OsAccountManager::GetOsAccountAllConstraints(Constants::START_USER_ID, constraints), ERR_OK);
    const unsigned int size = 0;
    EXPECT_NE(size, constraints.size());
}

/**
 * @tc.name: OsAccountManagerModuleTest027
 * @tc.desc: Test GetOsAccountAllConstraints with does not exisit os account id.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFE SR000GH18T
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest027, TestSize.Level1)
{
    std::vector<std::string> constraints;
    EXPECT_NE(OsAccountManager::GetOsAccountAllConstraints(Constants::MAX_USER_ID + 1, constraints), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest028
 * @tc.desc: Test QueryAllCreatedOsAccounts.
 * @tc.type: FUNC
 * @tc.require: SR000GH18T
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest028, TestSize.Level1)
{
    std::vector<OsAccountInfo> osAccountInfos;
    EXPECT_EQ(OsAccountManager::QueryAllCreatedOsAccounts(osAccountInfos), ERR_OK);
    const unsigned int size = 0;
    EXPECT_NE(size, osAccountInfos.size());
}

/**
 * @tc.name: OsAccountManagerModuleTest029
 * @tc.desc: Test QueryCurrentOsAccount.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest029, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(OsAccountManager::QueryCurrentOsAccount(osAccountInfo), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest030
 * @tc.desc: Test QueryOsAccountById with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFF
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest030, TestSize.Level0)
{
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(OsAccountManager::QueryOsAccountById(Constants::START_USER_ID, osAccountInfo), ERR_OK);
    EXPECT_EQ(Constants::START_USER_ID, osAccountInfo.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerModuleTest031
 * @tc.desc: Test QueryOsAccountById with unvalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFF
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest031, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    EXPECT_NE(OsAccountManager::QueryOsAccountById(Constants::MAX_USER_ID + 1, osAccountInfo), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest032
 * @tc.desc: Test GetOsAccountTypeFromProcess.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest032, TestSize.Level1)
{
    OsAccountType type = OsAccountType::ADMIN;
    EXPECT_EQ(OsAccountManager::GetOsAccountTypeFromProcess(type), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest033
 * @tc.desc: Test SetOsAccountName with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFF
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest033, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    OsAccountManager::CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_EQ(OsAccountManager::SetOsAccountName(osAccountInfoOne.GetLocalId(), STRING_NAME), ERR_OK);
    OsAccountInfo osAccountInfoTwo;
    OsAccountManager::QueryOsAccountById(osAccountInfoOne.GetLocalId(), osAccountInfoTwo);
    EXPECT_EQ(STRING_NAME, osAccountInfoTwo.GetLocalName());
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerModuleTest034
 * @tc.desc: Test SetOsAccountName with unvalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFF
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest034, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    OsAccountManager::CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_NE(OsAccountManager::SetOsAccountName(osAccountInfoOne.GetLocalId(), STRING_EMPTY), ERR_OK);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerModuleTest035
 * @tc.desc: Test SetOsAccountName with unvalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFF
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest035, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    OsAccountManager::CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_NE(OsAccountManager::SetOsAccountName(osAccountInfoOne.GetLocalId(), STRING_NAME_OUT_OF_RANGE), ERR_OK);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerModuleTest036
 * @tc.desc: Test GetDistributedVirtualDeviceId.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest036, TestSize.Level1)
{
    // before ohos account login
    std::string deviceId;
    ErrCode ret = OsAccountManager::GetDistributedVirtualDeviceId(deviceId);
    EXPECT_EQ(ret, ERR_OK);

    bool checkValid = (deviceId == "");
    EXPECT_EQ(checkValid, true);

    // ohos account login
    sptr<ISystemAbilityManager> systemMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(systemMgr, nullptr);
    sptr<IRemoteObject> accountObj = systemMgr->GetSystemAbility(SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN);
    ASSERT_NE(accountObj, nullptr);
    sptr<IAccount> ohosMgr = iface_cast<AccountProxy>(accountObj);
    checkValid = ohosMgr->UpdateOhosAccountInfo(TEST_ACCOUNT_NAME, TEST_ACCOUNT_UID, OHOS_ACCOUNT_EVENT_LOGIN);
    EXPECT_EQ(checkValid, true);

    // after ohos account login
    ret = OsAccountManager::GetDistributedVirtualDeviceId(deviceId);
    EXPECT_EQ(ret, ERR_OK);
    checkValid = (deviceId == TEST_EXPECTED_UID);
    EXPECT_EQ(checkValid, true);

    // ohos account logout
    checkValid = ohosMgr->UpdateOhosAccountInfo(TEST_ACCOUNT_NAME, TEST_ACCOUNT_UID, OHOS_ACCOUNT_EVENT_LOGOUT);
    EXPECT_EQ(checkValid, true);

    // after ohos account logout
    ret = OsAccountManager::GetDistributedVirtualDeviceId(deviceId);
    EXPECT_EQ(ret, ERR_OK);
    checkValid = (deviceId == "");
    EXPECT_EQ(checkValid, true);
}

/**
 * @tc.name: OsAccountManagerModuleTest037
 * @tc.desc: Test GetOsAccountLocalIdBySerialNumber with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFF
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest037, TestSize.Level1)
{
    int id = 0;
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdBySerialNumber(
                  Constants::CARRY_NUM * Constants::SERIAL_NUMBER_NUM_START_FOR_ADMIN + 1, id),
        ERR_OK);
    EXPECT_EQ(id, Constants::START_USER_ID);
}

/**
 * @tc.name: OsAccountManagerModuleTest038
 * @tc.desc: Test GetOsAccountLocalIdBySerialNumber with unvalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFF
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest038, TestSize.Level1)
{
    int id = 0;
    EXPECT_NE(OsAccountManager::GetOsAccountLocalIdBySerialNumber(123, id), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest039
 * @tc.desc: Test GetSerialNumberByOsAccountLocalId with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFF
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest039, TestSize.Level1)
{
    int64_t serialNumber;
    EXPECT_EQ(OsAccountManager::GetSerialNumberByOsAccountLocalId(Constants::START_USER_ID, serialNumber), ERR_OK);
    EXPECT_EQ(serialNumber, Constants::CARRY_NUM * Constants::SERIAL_NUMBER_NUM_START_FOR_ADMIN + 1);
}

/**
 * @tc.name: OsAccountManagerModuleTest040
 * @tc.desc: Test GetSerialNumberByOsAccountLocalId with unvalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFF
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest040, TestSize.Level1)
{
    int64_t serialNumber;
    EXPECT_NE(OsAccountManager::GetSerialNumberByOsAccountLocalId(Constants::MAX_USER_ID + 1, serialNumber), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest041
 * @tc.desc: Test SetOsAccountProfilePhoto with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFI
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest041, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    OsAccountManager::CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_EQ(OsAccountManager::SetOsAccountProfilePhoto(osAccountInfoOne.GetLocalId(), PHOTO_IMG), ERR_OK);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerModuleTest042
 * @tc.desc: Test SetOsAccountProfilePhoto with unvalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFI
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest042, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    OsAccountManager::CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_NE(
        OsAccountManager::SetOsAccountProfilePhoto(osAccountInfoOne.GetLocalId(), STRING_PHOTO_OUT_OF_RANGE), ERR_OK);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerModuleTest043
 * @tc.desc: Test SetOsAccountProfilePhoto with unvalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFI
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest043, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    OsAccountManager::CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_NE(OsAccountManager::SetOsAccountProfilePhoto(osAccountInfoOne.GetLocalId(), PHOTO_IMG_ERROR), ERR_OK);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerModuleTest044
 * @tc.desc: Test GetOsAccountProfilePhoto with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFF
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest044, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    OsAccountManager::CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    OsAccountManager::SetOsAccountProfilePhoto(osAccountInfoOne.GetLocalId(), PHOTO_IMG);
    std::string photo;
    EXPECT_EQ(OsAccountManager::GetOsAccountProfilePhoto(osAccountInfoOne.GetLocalId(), photo), ERR_OK);
    EXPECT_EQ(photo, PHOTO_IMG);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerModuleTest045
 * @tc.desc: Test GetOsAccountProfilePhoto with unvalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFF
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest045, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    OsAccountManager::CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    std::string photo;
    EXPECT_EQ(OsAccountManager::GetOsAccountProfilePhoto(osAccountInfoOne.GetLocalId(), photo),
        ERR_OSACCOUNT_KIT_GET_OS_ACCOUNT_PROFILE_PHOTO_ERROR);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerModuleTest046
 * @tc.desc: Test GetOsAccountProfilePhoto with unvalid id.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFF
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest046, TestSize.Level1)
{
    std::string photo;
    EXPECT_NE(OsAccountManager::GetOsAccountProfilePhoto(Constants::MAX_USER_ID + 1, photo), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest047
 * @tc.desc: Test StartOsAccount with valid id.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFJ
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest047, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    OsAccountManager::CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_EQ(OsAccountManager::StartOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    OsAccountManager::StopOsAccount(osAccountInfoOne.GetLocalId());
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerModuleTest048
 * @tc.desc: Test StartOsAccount with unvalid id.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFJ
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest048, TestSize.Level1)
{
    EXPECT_EQ(OsAccountManager::StartOsAccount(Constants::MAX_USER_ID + 1), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest049
 * @tc.desc: Test StartOsAccount with started id.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFJ
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest049, TestSize.Level1)
{
    EXPECT_EQ(OsAccountManager::StartOsAccount(Constants::START_USER_ID), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest050
 * @tc.desc: Test StopOsAccount with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFJ
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest050, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    OsAccountManager::CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    OsAccountManager::StartOsAccount(osAccountInfoOne.GetLocalId());
    EXPECT_EQ(OsAccountManager::StopOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerModuleTest051
 * @tc.desc: Test StopOsAccount with unvalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFJ
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest051, TestSize.Level1)
{
    EXPECT_EQ(OsAccountManager::StopOsAccount(Constants::MAX_USER_ID + 1), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest052
 * @tc.desc: Test ActivateOsAccount with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFJ
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest052, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    OsAccountManager::CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    OsAccountManager::ActivateOsAccount(Constants::START_USER_ID);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerModuleTest053
 * @tc.desc: Test IsOsAccountVerified with unvalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFJ
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest053, TestSize.Level1)
{
    bool isVerified = false;
    EXPECT_NE(OsAccountManager::IsOsAccountVerified(ERROR_LOCAL_ID, isVerified), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest054
 * @tc.desc: Create os account for domain, and remove it
 * @tc.type: FUNC
 * @tc.require: SR000GGVFL
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest054, TestSize.Level1)
{
    DomainAccountInfo domainInfo(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    OsAccountType type = NORMAL;
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(OsAccountManager::CreateOsAccountForDomain(type, domainInfo, osAccountInfo), ERR_OK);

    bool checkValid = (osAccountInfo.GetLocalId() > Constants::START_USER_ID);
    EXPECT_EQ(checkValid, true);

    DomainAccountInfo resDomainInfo;
    osAccountInfo.GetDomainInfo(resDomainInfo);
    checkValid = (resDomainInfo.accountName_ == domainInfo.accountName_);
    EXPECT_EQ(checkValid, true);
    checkValid = (resDomainInfo.domain_ == domainInfo.domain_);
    EXPECT_EQ(checkValid, true);

    std::string osAccountName = domainInfo.domain_ + "/" + domainInfo.accountName_;
    checkValid = (osAccountInfo.GetLocalName() == osAccountName);
    EXPECT_EQ(checkValid, true);
    
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(osAccountInfo.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest055
 * @tc.desc: Create os account for domain, and activate it.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFL
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest055, TestSize.Level1)
{
    // create
    DomainAccountInfo domainInfo(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    OsAccountType type = NORMAL;
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(OsAccountManager::CreateOsAccountForDomain(type, domainInfo, osAccountInfo), ERR_OK);

    bool checkValid = (osAccountInfo.GetLocalId() > Constants::START_USER_ID);
    EXPECT_EQ(checkValid, true);

    DomainAccountInfo resDomainInfo;
    osAccountInfo.GetDomainInfo(resDomainInfo);
    checkValid = (resDomainInfo.accountName_ == domainInfo.accountName_);
    EXPECT_EQ(checkValid, true);
    checkValid = (resDomainInfo.domain_ == domainInfo.domain_);
    EXPECT_EQ(checkValid, true);

    std::string osAccountName = domainInfo.domain_ + "/" + domainInfo.accountName_;
    checkValid = (osAccountInfo.GetLocalName() == osAccountName);
    EXPECT_EQ(checkValid, true);

    // activate
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(osAccountInfo.GetLocalId()), ERR_OK);

    // check
    OsAccountInfo queryAccountInfo;
    EXPECT_EQ(OsAccountManager::QueryOsAccountById(osAccountInfo.GetLocalId(), queryAccountInfo), ERR_OK);
    EXPECT_EQ(queryAccountInfo.GetLocalId(), osAccountInfo.GetLocalId());
    EXPECT_EQ(queryAccountInfo.GetIsActived(), true);
    checkValid = (queryAccountInfo.GetLocalName() == osAccountName);
    EXPECT_EQ(checkValid, true);

    // remove
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(osAccountInfo.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest056
 * @tc.desc: Create os account for domain use invalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFL
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest056, TestSize.Level1)
{
    DomainAccountInfo domainNameInvalid(STRING_DOMAIN_NAME_OUT_OF_RANGE, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    OsAccountType type = NORMAL;
    OsAccountInfo osAccountInfo;
    ErrCode ret = OsAccountManager::CreateOsAccountForDomain(type, domainNameInvalid, osAccountInfo);
    EXPECT_EQ(ret, ERR_OSACCOUNT_KIT_DOMAIN_NAME_LENGTH_INVALID_ERROR);

    DomainAccountInfo domainAccountNameInvalid(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_OUT_OF_RANGE);
    ret = OsAccountManager::CreateOsAccountForDomain(type, domainAccountNameInvalid, osAccountInfo);
    EXPECT_EQ(ret, ERR_OSACCOUNT_KIT_DOMAIN_ACCOUNT_NAME_LENGTH_INVALID_ERROR);

    DomainAccountInfo domainEmpty("", STRING_DOMAIN_ACCOUNT_NAME_VALID);
    ret = OsAccountManager::CreateOsAccountForDomain(type, domainEmpty, osAccountInfo);
    EXPECT_EQ(ret, ERR_OSACCOUNT_KIT_DOMAIN_NAME_LENGTH_INVALID_ERROR);

    DomainAccountInfo domainAccountEmpty(STRING_DOMAIN_VALID, "");
    ret = OsAccountManager::CreateOsAccountForDomain(type, domainAccountEmpty, osAccountInfo);
    EXPECT_EQ(ret, ERR_OSACCOUNT_KIT_DOMAIN_ACCOUNT_NAME_LENGTH_INVALID_ERROR);
}

/**
 * @tc.name: OsAccountManagerModuleTest057
 * @tc.desc: repeat create os account for domain
 * @tc.type: FUNC
 * @tc.require: SR000GGVFL
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest057, TestSize.Level1)
{
    // create
    DomainAccountInfo domainInfo(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    OsAccountType type = NORMAL;
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(OsAccountManager::CreateOsAccountForDomain(type, domainInfo, osAccountInfo), ERR_OK);

    // create again
    EXPECT_EQ(OsAccountManager::CreateOsAccountForDomain(type, domainInfo, osAccountInfo),
        ERR_OS_ACCOUNT_SERVICE_INNER_DOMAIN_ALREADY_BIND_ERROR);

    // remove
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(osAccountInfo.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest058
 * @tc.desc: repeat create os account for domain
 * @tc.type: FUNC
 * @tc.require: SR000GGVFL
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest058, TestSize.Level1)
{
    // create
    DomainAccountInfo domainInfo(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    OsAccountType type = NORMAL;
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(OsAccountManager::CreateOsAccountForDomain(type, domainInfo, osAccountInfo), ERR_OK);

    // create again
    EXPECT_EQ(OsAccountManager::CreateOsAccountForDomain(type, domainInfo, osAccountInfo),
        ERR_OS_ACCOUNT_SERVICE_INNER_DOMAIN_ALREADY_BIND_ERROR);

    // remove
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(osAccountInfo.GetLocalId()), ERR_OK);

    // create again
    EXPECT_EQ(OsAccountManager::CreateOsAccountForDomain(type, domainInfo, osAccountInfo), ERR_OK);

    // remove
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(osAccountInfo.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest059
 * @tc.desc: query os account by domain info
 * @tc.type: FUNC
 * @tc.require: SR000GGVFL
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest059, TestSize.Level1)
{
    // create
    DomainAccountInfo domainInfo(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    OsAccountType type = NORMAL;
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(OsAccountManager::CreateOsAccountForDomain(type, domainInfo, osAccountInfo), ERR_OK);

    // get os account local id by domain
    int resID = -1;
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, resID), ERR_OK);
    EXPECT_EQ(resID, osAccountInfo.GetLocalId());

    // remove
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(osAccountInfo.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest060
 * @tc.desc: query os account by domain info
 * @tc.type: FUNC
 * @tc.require: SR000GGVFL
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest060, TestSize.Level1)
{
    // create
    DomainAccountInfo domainInfo(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    OsAccountType type = NORMAL;
    OsAccountInfo osAccountInfo;
    ErrCode ret = OsAccountManager::CreateOsAccountForDomain(type, domainInfo, osAccountInfo);
    EXPECT_EQ(ret, ERR_OK);

    // get os account local id by domain
    int resID = -1;
    ret = OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, resID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(resID, osAccountInfo.GetLocalId());

    // remove
    ret = OsAccountManager::RemoveOsAccount(osAccountInfo.GetLocalId());
    EXPECT_EQ(ret, ERR_OK);

    // cannot query
    ret = OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, resID);
    EXPECT_EQ(ret, ERR_OSACCOUNT_KIT_GET_OS_ACCOUNT_LOCAL_ID_FOR_DOMAIN_ERROR);
}

/**
 * @tc.name: OsAccountManagerModuleTest061
 * @tc.desc: query os account by domain info
 * @tc.type: FUNC
 * @tc.require: SR000GGVFL
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest061, TestSize.Level1)
{
    DomainAccountInfo domainAllEmpty("", "");
    int resID = -1;
    ErrCode ret = OsAccountManager::GetOsAccountLocalIdFromDomain(domainAllEmpty, resID);
    EXPECT_EQ(ret, ERR_OSACCOUNT_KIT_DOMAIN_NAME_LENGTH_INVALID_ERROR);

    DomainAccountInfo domainNameEmpty("", STRING_DOMAIN_ACCOUNT_NAME_VALID);
    ret = OsAccountManager::GetOsAccountLocalIdFromDomain(domainNameEmpty, resID);
    EXPECT_EQ(ret, ERR_OSACCOUNT_KIT_DOMAIN_NAME_LENGTH_INVALID_ERROR);

    DomainAccountInfo domainAccountEmpty(STRING_DOMAIN_VALID, "");
    ret = OsAccountManager::GetOsAccountLocalIdFromDomain(domainAccountEmpty, resID);
    EXPECT_EQ(ret, ERR_OSACCOUNT_KIT_DOMAIN_ACCOUNT_NAME_LENGTH_INVALID_ERROR);

    DomainAccountInfo domainAllTooLong(STRING_DOMAIN_NAME_OUT_OF_RANGE, STRING_DOMAIN_ACCOUNT_NAME_OUT_OF_RANGE);
    ret = OsAccountManager::GetOsAccountLocalIdFromDomain(domainAllTooLong, resID);
    EXPECT_EQ(ret, ERR_OSACCOUNT_KIT_DOMAIN_NAME_LENGTH_INVALID_ERROR);

    DomainAccountInfo domainNameTooLong(STRING_DOMAIN_NAME_OUT_OF_RANGE, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    ret = OsAccountManager::GetOsAccountLocalIdFromDomain(domainNameTooLong, resID);
    EXPECT_EQ(ret, ERR_OSACCOUNT_KIT_DOMAIN_NAME_LENGTH_INVALID_ERROR);

    DomainAccountInfo domainAccountTooLong(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_OUT_OF_RANGE);
    ret = OsAccountManager::GetOsAccountLocalIdFromDomain(domainAccountTooLong, resID);
    EXPECT_EQ(ret, ERR_OSACCOUNT_KIT_DOMAIN_ACCOUNT_NAME_LENGTH_INVALID_ERROR);
}

/**
 * @tc.name: OsAccountManagerModuleTest062
 * @tc.desc: Test get os account info from database
 * @tc.type: FUNC
 * @tc.require: SR000GGVFK
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest062, TestSize.Level1)
{
    char udid[Constants::DEVICE_UUID_LENGTH] = {0};
    int ret = GetDevUdid(udid, Constants::DEVICE_UUID_LENGTH);
    if (ret != 0) {
        std::cout << "Error: GetDevUdid failed! error code " << ret << std::endl;
        return;
    }

    std::string storeID = std::string(udid);
    int createdOsAccountNum = -1;
    ret = OsAccountManager::GetCreatedOsAccountNumFromDatabase(storeID, createdOsAccountNum);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(createdOsAccountNum, -1);

    int64_t serialNumber = -1;
    ret = OsAccountManager::GetSerialNumberFromDatabase(storeID, serialNumber);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(serialNumber, -1);

    int id = -1;
    ret = OsAccountManager::GetMaxAllowCreateIdFromDatabase(storeID, id);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(id, Constants::MAX_USER_ID);

    OsAccountInfo osAccountInfo;
    ret = OsAccountManager::GetOsAccountFromDatabase(storeID, Constants::START_USER_ID, osAccountInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(osAccountInfo.GetLocalId(), Constants::START_USER_ID);

    std::vector<OsAccountInfo> osAccountList;
    ret = OsAccountManager::GetOsAccountListFromDatabase(storeID, osAccountList);
    EXPECT_EQ(ret, ERR_OK);

    bool checkValid = false;
    checkValid = (osAccountList.size() > 0);
    EXPECT_EQ(checkValid, true);

    for (size_t i = 0; i < osAccountList.size(); ++i) {
        if (osAccountList[i].GetLocalId() == Constants::START_USER_ID) {
            checkValid = true;
            break;
        }
    }
    EXPECT_EQ(checkValid, true);
    OsAccountManager::ActivateOsAccount(Constants::START_USER_ID);
}

/**
 * @tc.name: OsAccountManagerModuleTest063
 * @tc.desc: Test get os account info from database
 * @tc.type: FUNC
 * @tc.require: SR000GGVFK
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest063, TestSize.Level1)
{
    char udid[Constants::DEVICE_UUID_LENGTH] = {0};
    int ret = GetDevUdid(udid, Constants::DEVICE_UUID_LENGTH);
    if (ret != 0) {
        std::cout << "Error: GetDevUdid failed! error code " << ret << std::endl;
        return;
    }

    std::string storeID = std::string(udid);
    int createdOsAccountNum = -1;
    ret = OsAccountManager::GetCreatedOsAccountNumFromDatabase(storeID, createdOsAccountNum);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(createdOsAccountNum, -1);

    int createdOsAccountNumWithDefault = -1;
    ret = OsAccountManager::GetCreatedOsAccountNumFromDatabase(std::string(""), createdOsAccountNumWithDefault);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(createdOsAccountNumWithDefault, createdOsAccountNum);

    int64_t serialNumber = -1;
    ret = OsAccountManager::GetSerialNumberFromDatabase(storeID, serialNumber);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(serialNumber, -1);

    int64_t serialNumberWithDefault = -1;
    ret = OsAccountManager::GetSerialNumberFromDatabase(std::string(""), serialNumberWithDefault);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(serialNumber, serialNumberWithDefault);

    int id = -1;
    ret = OsAccountManager::GetMaxAllowCreateIdFromDatabase(storeID, id);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(id, Constants::MAX_USER_ID);

    int idWithDefault = -1;
    ret = OsAccountManager::GetMaxAllowCreateIdFromDatabase(std::string(""), idWithDefault);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(id, idWithDefault);

    OsAccountInfo osAccountInfo;
    ret = OsAccountManager::GetOsAccountFromDatabase(storeID, Constants::START_USER_ID, osAccountInfo);
    EXPECT_EQ(ret, ERR_OK);

    OsAccountInfo osAccountInfoByDefault;
    ret = OsAccountManager::GetOsAccountFromDatabase(std::string(""), Constants::START_USER_ID, osAccountInfoByDefault);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(osAccountInfo.GetLocalId(), osAccountInfoByDefault.GetLocalId());
    EXPECT_EQ(osAccountInfo.GetIsActived(), osAccountInfoByDefault.GetIsActived());
    EXPECT_EQ(osAccountInfo.GetType(), osAccountInfoByDefault.GetType());

    bool checkValid = (osAccountInfo.GetLocalName() == osAccountInfoByDefault.GetLocalName());
    EXPECT_EQ(checkValid, true);

    std::vector<OsAccountInfo> osAccountList;
    ret = OsAccountManager::GetOsAccountListFromDatabase(storeID, osAccountList);
    EXPECT_EQ(ret, ERR_OK);

    std::vector<OsAccountInfo> osAccountListByDefault;
    ret = OsAccountManager::GetOsAccountListFromDatabase(std::string(""), osAccountListByDefault);
    EXPECT_EQ(ret, ERR_OK);

    checkValid = (osAccountList.size() == osAccountListByDefault.size());
    EXPECT_EQ(checkValid, true);
    if (osAccountList.size() == osAccountListByDefault.size()) {
        for (size_t i = 0; i < osAccountList.size(); ++i) {
            EXPECT_EQ(osAccountList[i].GetLocalId(), osAccountListByDefault[i].GetLocalId());
        }
    }
}

/**
 * @tc.name: OsAccountManagerModuleTest064
 * @tc.desc: Test get os account info from database
 * @tc.type: FUNC
 * @tc.require: SR000GGVFK
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest064, TestSize.Level1)
{
    char udid[Constants::DEVICE_UUID_LENGTH] = {0};
    int ret = GetDevUdid(udid, Constants::DEVICE_UUID_LENGTH);
    if (ret != 0) {
        std::cout << "Error: GetDevUdid failed! error code " << ret << std::endl;
        return;
    }

    // get data before creating
    std::string storeID = std::string(udid);
    int createdOsAccountNum = -1;
    ret = OsAccountManager::GetCreatedOsAccountNumFromDatabase(storeID, createdOsAccountNum);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(createdOsAccountNum, -1);

    int64_t serialNumber = -1;
    ret = OsAccountManager::GetSerialNumberFromDatabase(storeID, serialNumber);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(serialNumber, -1);

    // create a new account
    OsAccountInfo osAccountInfoOne;
    EXPECT_EQ(OsAccountManager::CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne), ERR_OK);

    // get data after creating
    int afterCreatedCount = -1;
    ret = OsAccountManager::GetCreatedOsAccountNumFromDatabase(storeID, afterCreatedCount);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(afterCreatedCount, createdOsAccountNum + 1);

    int64_t serialNumberAfterCreate = -1;
    ret = OsAccountManager::GetSerialNumberFromDatabase(storeID, serialNumberAfterCreate);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(serialNumber + 1, serialNumberAfterCreate);

    int id = -1;
    ret = OsAccountManager::GetMaxAllowCreateIdFromDatabase(storeID, id);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(id, Constants::MAX_USER_ID);

    // get created account info
    OsAccountInfo osAccountInfo;
    ret = OsAccountManager::GetOsAccountFromDatabase(storeID, osAccountInfoOne.GetLocalId(), osAccountInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(osAccountInfo.GetLocalId(), osAccountInfoOne.GetLocalId());
    EXPECT_EQ(osAccountInfo.GetIsActived(), false);
    EXPECT_EQ(osAccountInfo.GetIsActived(), osAccountInfoOne.GetIsActived());
    EXPECT_EQ(osAccountInfo.GetType(), osAccountInfoOne.GetType());

    bool checkValid = (osAccountInfo.GetLocalName() == osAccountInfoOne.GetLocalName());
    EXPECT_EQ(checkValid, true);

    std::vector<OsAccountInfo> osAccountList;
    ret = OsAccountManager::GetOsAccountListFromDatabase(storeID, osAccountList);
    EXPECT_EQ(ret, ERR_OK);

    // check new account must be in the list
    checkValid = false;
    for (size_t i = 0; i < osAccountList.size(); ++i) {
        if (osAccountList[i].GetLocalId() == osAccountInfoOne.GetLocalId()) {
            checkValid = (osAccountList[i].GetLocalName() == osAccountInfoOne.GetLocalName());
            break;
        }
    }
    EXPECT_EQ(checkValid, true);

    // restore
    OsAccountManager::ActivateOsAccount(Constants::START_USER_ID);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerModuleTest065
 * @tc.desc: Test get os account info from database
 * @tc.type: FUNC
 * @tc.require: SR000GGVFK
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest065, TestSize.Level1)
{
    char udid[Constants::DEVICE_UUID_LENGTH] = {0};
    int ret = GetDevUdid(udid, Constants::DEVICE_UUID_LENGTH);
    if (ret != 0) {
        std::cout << "Error: GetDevUdid failed! error code " << ret << std::endl;
        return;
    }

    // create a new os account
    OsAccountInfo osAccountInfoOne;
    EXPECT_EQ(OsAccountManager::CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne), ERR_OK);

    // get created account info
    OsAccountInfo osAccountInfo;
    ret = OsAccountManager::GetOsAccountFromDatabase(std::string(""), osAccountInfoOne.GetLocalId(), osAccountInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(osAccountInfo.GetLocalId(), osAccountInfoOne.GetLocalId());
    EXPECT_EQ(osAccountInfo.GetIsActived(), false);
    EXPECT_EQ(osAccountInfo.GetIsActived(), osAccountInfoOne.GetIsActived());
    EXPECT_EQ(osAccountInfo.GetType(), osAccountInfoOne.GetType());

    // active the new os account
    ret = OsAccountManager::ActivateOsAccount(osAccountInfoOne.GetLocalId());
    EXPECT_EQ(ret, ERR_OK);

    // get data after activating
    OsAccountInfo osAccountInfoNow;
    ret = OsAccountManager::GetOsAccountFromDatabase(std::string(""), osAccountInfoOne.GetLocalId(), osAccountInfoNow);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(osAccountInfoNow.GetLocalId(), osAccountInfoOne.GetLocalId());
    EXPECT_EQ(osAccountInfoNow.GetIsActived(), true);

    // cannot find the account in database list either
    std::vector<OsAccountInfo> osAccountList;
    ret = OsAccountManager::GetOsAccountListFromDatabase(std::string(""), osAccountList);
    EXPECT_EQ(ret, ERR_OK);
    bool findIt = false;
    for (size_t i = 0; i < osAccountList.size(); ++i) {
        if (osAccountInfoOne.GetLocalId() == osAccountList[i].GetLocalId()) {
            findIt = osAccountList[i].GetIsActived();
        }
    }
    EXPECT_EQ(findIt, true);

    // restore
    OsAccountManager::ActivateOsAccount(Constants::START_USER_ID);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerModuleTest066
 * @tc.desc: Test get os account info from database
 * @tc.type: FUNC
 * @tc.require: SR000GGVFK
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest066, TestSize.Level1)
{
    char udid[Constants::DEVICE_UUID_LENGTH] = {0};
    int ret = GetDevUdid(udid, Constants::DEVICE_UUID_LENGTH);
    if (ret != 0) {
        std::cout << "Error: GetDevUdid failed! error code " << ret << std::endl;
        return;
    }
    std::string storeID = std::string(udid);

    // create a new os account
    OsAccountInfo osAccountInfoOne;
    EXPECT_EQ(OsAccountManager::CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne), ERR_OK);

    // get created account info
    OsAccountInfo osAccountInfo;
    ret = OsAccountManager::GetOsAccountFromDatabase(storeID, osAccountInfoOne.GetLocalId(), osAccountInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(osAccountInfo.GetLocalId(), osAccountInfoOne.GetLocalId());
    EXPECT_EQ(osAccountInfo.GetIsActived(), false);
    EXPECT_EQ(osAccountInfo.GetIsActived(), osAccountInfoOne.GetIsActived());
    EXPECT_EQ(osAccountInfo.GetType(), osAccountInfoOne.GetType());

    // active the new os account
    ret = OsAccountManager::ActivateOsAccount(osAccountInfoOne.GetLocalId());
    EXPECT_EQ(ret, ERR_OK);

    // get data after activating
    OsAccountInfo osAccountInfoNow;
    ret = OsAccountManager::GetOsAccountFromDatabase(storeID, osAccountInfoOne.GetLocalId(), osAccountInfoNow);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(osAccountInfoNow.GetLocalId(), osAccountInfoOne.GetLocalId());
    EXPECT_EQ(osAccountInfoNow.GetIsActived(), true);

    // remove the new os account
    OsAccountManager::ActivateOsAccount(Constants::START_USER_ID);
    ret = OsAccountManager::RemoveOsAccount(osAccountInfoOne.GetLocalId());
    EXPECT_EQ(ret, ERR_OK);

    // cannot find the account in database
    OsAccountInfo osAccountInfoAfterRm;
    ret = OsAccountManager::GetOsAccountFromDatabase(storeID, osAccountInfoOne.GetLocalId(), osAccountInfoAfterRm);
    EXPECT_NE(ret, ERR_OK);

    // cannot find the account in database list either
    std::vector<OsAccountInfo> osAccountList;
    ret = OsAccountManager::GetOsAccountListFromDatabase(storeID, osAccountList);
    EXPECT_EQ(ret, ERR_OK);
    bool findIt = false;
    for (size_t i = 0; i < osAccountList.size(); ++i) {
        if (osAccountInfoOne.GetLocalId() == osAccountList[i].GetLocalId()) {
            findIt = true;
        }
    }
    EXPECT_NE(findIt, true);
}
