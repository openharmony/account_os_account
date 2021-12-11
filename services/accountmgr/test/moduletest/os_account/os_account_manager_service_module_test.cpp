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

#include "account_error_no.h"
#define private public
#include "os_account_manager_service.h"
#include "account_file_operator.h"
#include "os_account_control_file_manager.h"
#undef private
#include "os_account_constants.h"

namespace OHOS {
namespace AccountSA {
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS;
using namespace AccountSA;

namespace {
const std::string STRING_EMPTY = "";
const std::string STRING_NAME = "name";
const std::string STRING_TEST_NAME = "test";
const int INT_TEST_TYPE = 1;
const int INT_TEST_NEGATIVE_TYPE = -21;
const int INT_TEST_MAX_TYPE = 10000;

const std::vector<std::string> CONSTANTS_VECTOR {"WIFI", "PHONE", "PHOTO"};
const std::string CONSTANTS_STRING_WIFI = "WIFI";
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
}  // namespace

class OsAccountManagerServiceModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

public:
    std::shared_ptr<OsAccountManagerService> osAccountManagerService_;
    std::shared_ptr<OsAccountControlFileManager> osAccountControlFileManager_;
    std::shared_ptr<AccountFileOperator> accountFileOperator_;
};

void OsAccountManagerServiceModuleTest::SetUpTestCase(void)
{}

void OsAccountManagerServiceModuleTest::TearDownTestCase(void)
{}

void OsAccountManagerServiceModuleTest::SetUp(void)
{
    osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    osAccountControlFileManager_ = std::make_shared<OsAccountControlFileManager>();
    accountFileOperator_ = std::make_shared<AccountFileOperator>();
    osAccountControlFileManager_->Init();
}

void OsAccountManagerServiceModuleTest::TearDown(void)
{}

/**
 * @tc.name: OsAccountManagerServiceModuleTest001
 * @tc.desc: Test CreateOsAccount with valid data.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest001, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfoOne;
    ErrCode errCode = osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_EQ(errCode, ERR_OK);
    OsAccountInfo osAccountInfoTwo;
    osAccountControlFileManager_->GetOsAccountInfoById(osAccountInfoOne.GetId(), osAccountInfoTwo);
    EXPECT_EQ(osAccountInfoOne.ToString(), osAccountInfoTwo.ToString());
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest002
 * @tc.desc: Test CreateOsAccount with unvaild name.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest002, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfoOne;
    ErrCode errCode =
        osAccountManagerService_->CreateOsAccount(STRING_NAME_OUT_OF_RANGE, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_EQ(errCode, ERR_OS_ACCOUNT_SERVICE_MANAGER_NAME_SIZE_OVERFLOW_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest003
 * @tc.desc: Test CreateOsAccount with unvaild name.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest003, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfoOne;
    ErrCode errCode = osAccountManagerService_->CreateOsAccount(STRING_EMPTY, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_EQ(errCode, ERR_OS_ACCOUNT_SERVICE_MANAGER_NAME_SIZE_EMPTY_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest004
 * @tc.desc: Test IsCurrentOsAccountVerified with vaild data.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest004, Function | MediumTest | Level1)
{
    bool isVerify = false;
    ErrCode errCode = osAccountManagerService_->IsCurrentOsAccountVerified(isVerify);
    EXPECT_EQ(errCode, ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest005
 * @tc.desc: Test CreateOsAccount with unvaild type.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest005, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfoOne;
    ErrCode errCode =
        osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_NEGATIVE_TYPE, osAccountInfoOne);
    EXPECT_EQ(errCode, ERR_OS_ACCOUNT_SERVICE_MANAGER_CREATE_OSACCOUNT_TYPE_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest006
 * @tc.desc: Test CreateOsAccount with unvaild type.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest006, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfoOne;
    ErrCode errCode = osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_MAX_TYPE, osAccountInfoOne);
    EXPECT_EQ(errCode, ERR_OS_ACCOUNT_SERVICE_INNER_GET_TTPE_CONSTRAINTS_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest007
 * @tc.desc: Test CreateOsAccount when cannot find account_list.json.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest007, Function | MediumTest | Level1)
{
    std::string fileContext;
    accountFileOperator_->GetFileContentByPath(
        Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + Constants::USER_LIST_FILE_NAME, fileContext);
    accountFileOperator_->DeleteDirOrFile(
        Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + Constants::USER_LIST_FILE_NAME);
    OsAccountInfo osAccountInfoOne;
    ErrCode errCode = osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_EQ(errCode, ERR_OS_ACCOUNT_SERVICE_INNER_GET_SERIAL_NUMBER_ERROR);
    accountFileOperator_->InputFileByPathAndContent(
        Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + Constants::USER_LIST_FILE_NAME, fileContext);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest008
 * @tc.desc: Test RemoveOsAccount with valid data.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest008, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfoOne;
    osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetId()), ERR_OK);
    EXPECT_EQ(accountFileOperator_->IsExistDir(
                  Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + osAccountInfoOne.GetPrimeKey()),
        false);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest009
 * @tc.desc: Test RemoveOsAccount with cannot remove id.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest009, Function | MediumTest | Level1)
{
    EXPECT_EQ(
        osAccountManagerService_->RemoveOsAccount(Constants::START_USER_ID), ERR_OS_ACCOUNT_SERVICE_MANAGER_ID_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest010
 * @tc.desc: Test RemoveOsAccount with does not exists id.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest010, Function | MediumTest | Level1)
{
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(Constants::MAX_USER_ID + 1),
        ERR_OS_ACCOUNT_SERVICE_INNER_CANNOT_FIND_OSACCOUNT_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest011
 * @tc.desc: Test IsOsAccountExists with valid data.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest011, Function | MediumTest | Level1)
{
    bool isOsAccountExists = false;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountExists(Constants::START_USER_ID, isOsAccountExists), ERR_OK);
    EXPECT_EQ(isOsAccountExists, true);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest012
 * @tc.desc: Test IsOsAccountExists with not exists data.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest012, Function | MediumTest | Level1)
{
    bool isOsAccountExists = true;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountExists(Constants::MAX_USER_ID + 1, isOsAccountExists), ERR_OK);
    EXPECT_EQ(isOsAccountExists, false);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest013
 * @tc.desc: Test IsOsAccountActived with valid data.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest013, Function | MediumTest | Level1)
{
    bool isOsAccountActived = false;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountExists(Constants::ADMIN_LOCAL_ID, isOsAccountActived), ERR_OK);
    EXPECT_EQ(isOsAccountActived, true);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest014
 * @tc.desc: Test IsOsAccountActived with not active account id.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest014, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfoOne;
    osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    bool isOsAccountActived = false;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountExists(osAccountInfoOne.GetId(), isOsAccountActived), ERR_OK);
    EXPECT_EQ(isOsAccountActived, true);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest015
 * @tc.desc: Test SetOsAccountConstraints with valid data.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest015, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfoOne;
    osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    bool enable = false;
    EXPECT_EQ(
        osAccountManagerService_->SetOsAccountConstraints(osAccountInfoOne.GetId(), CONSTANTS_VECTOR, enable), ERR_OK);
    OsAccountInfo osAccountInfoTwo;
    osAccountControlFileManager_->GetOsAccountInfoById(osAccountInfoOne.GetId(), osAccountInfoTwo);
    std::vector<std::string> contstans = osAccountInfoTwo.GetConstraints();
    for (auto it = contstans.begin(); it != contstans.end(); it++) {
        GTEST_LOG_(INFO) << *it;
    }
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest016
 * @tc.desc: Test SetOsAccountConstraints with valid data.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest016, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfoOne;
    osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    bool enable = true;
    EXPECT_EQ(
        osAccountManagerService_->SetOsAccountConstraints(osAccountInfoOne.GetId(), CONSTANTS_VECTOR, enable), ERR_OK);
    OsAccountInfo osAccountInfoTwo;
    osAccountControlFileManager_->GetOsAccountInfoById(osAccountInfoOne.GetId(), osAccountInfoTwo);
    std::vector<std::string> contstans = osAccountInfoTwo.GetConstraints();
    for (auto it = contstans.begin(); it != contstans.end(); it++) {
        GTEST_LOG_(INFO) << *it;
    }
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest017
 * @tc.desc: Test IsOsAccountConstraintEnable with valid data.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest017, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfoOne;
    osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    bool enable = true;
    osAccountManagerService_->SetOsAccountConstraints(osAccountInfoOne.GetId(), CONSTANTS_VECTOR, enable);
    bool isEnable = false;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountConstraintEnable(
                  osAccountInfoOne.GetId(), CONSTANTS_STRING_WIFI, isEnable),
        ERR_OK);
    EXPECT_EQ(isEnable, true);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest018
 * @tc.desc: Test IsOsAccountConstraintEnable with valid data.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest018, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfoOne;
    osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    bool isEnable = true;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountConstraintEnable(
                  osAccountInfoOne.GetId(), CONSTANTS_STRING_WIFI, isEnable),
        ERR_OK);
    EXPECT_EQ(isEnable, false);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest019
 * @tc.desc: Test IsMultiOsAccountEnable
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest019, Function | MediumTest | Level1)
{
    bool isMultiOsAccountEnable = false;
    EXPECT_EQ(osAccountManagerService_->IsMultiOsAccountEnable(isMultiOsAccountEnable), ERR_OK);
    EXPECT_EQ(isMultiOsAccountEnable, true);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest020
 * @tc.desc: Test IsOsAccountVerified with not verified os account id.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest020, Function | MediumTest | Level1)
{
    bool isOsAccountVerified = true;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountVerified(Constants::START_USER_ID, isOsAccountVerified), ERR_OK);
    EXPECT_EQ(isOsAccountVerified, false);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest021
 * @tc.desc: Test IsOsAccountVerified with does not exists os account id.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest021, Function | MediumTest | Level1)
{
    bool isOsAccountVerified = true;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountVerified(Constants::MAX_USER_ID + 1, isOsAccountVerified),
        ERR_OS_ACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest022
 * @tc.desc: Test IsOsAccountVerified with does not exists os account id.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest022, Function | MediumTest | Level1)
{
    bool isOsAccountVerified = true;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountVerified(Constants::MAX_USER_ID + 1, isOsAccountVerified),
        ERR_OS_ACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest023
 * @tc.desc: Test GetCreatedOsAccountsCount.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest023, Function | MediumTest | Level1)
{
    int osAccountsCount = 0;
    EXPECT_EQ(osAccountManagerService_->GetCreatedOsAccountsCount(osAccountsCount), ERR_OK);
    EXPECT_NE(osAccountsCount, 0);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest024
 * @tc.desc: Test GetOsAccountLocalIdFromProcess.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest024, Function | MediumTest | Level1)
{
    int id = -1;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountLocalIdFromProcess(id), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest025
 * @tc.desc: Test GetOsAccountLocalIdFromUid.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest025, Function | MediumTest | Level1)
{
    int uid = 0;
    int id = -1;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountLocalIdFromUid(uid, id), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest026
 * @tc.desc: Test QueryMaxOsAccountNumber.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest026, Function | MediumTest | Level1)
{
    int maxOsAccountNumber = 0;
    EXPECT_EQ(osAccountManagerService_->QueryMaxOsAccountNumber(maxOsAccountNumber), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest027
 * @tc.desc: Test GetOsAccountAllConstraints with exisit os account id.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest027, Function | MediumTest | Level1)
{
    std::vector<std::string> constraints;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountAllConstraints(Constants::START_USER_ID, constraints), ERR_OK);
    const unsigned int size = 0;
    EXPECT_NE(size, constraints.size());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest028
 * @tc.desc: Test GetOsAccountAllConstraints with does not exisit os account id.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest028, Function | MediumTest | Level1)
{
    std::vector<std::string> constraints;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountAllConstraints(Constants::MAX_USER_ID + 1, constraints),
        ERR_OS_ACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest029
 * @tc.desc: Test QueryAllCreatedOsAccounts.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest029, Function | MediumTest | Level1)
{
    std::vector<OsAccountInfo> osAccountInfos;
    EXPECT_EQ(osAccountManagerService_->QueryAllCreatedOsAccounts(osAccountInfos), ERR_OK);
    const unsigned int size = 0;
    EXPECT_NE(size, osAccountInfos.size());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest030
 * @tc.desc: Test QueryCurrentOsAccount.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest030, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(osAccountManagerService_->QueryCurrentOsAccount(osAccountInfo), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest031
 * @tc.desc: Test QueryOsAccountById with valid data.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest031, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(osAccountManagerService_->QueryOsAccountById(Constants::START_USER_ID, osAccountInfo), ERR_OK);
    EXPECT_EQ(Constants::START_USER_ID, osAccountInfo.GetId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest032
 * @tc.desc: Test QueryOsAccountById with unvalid data.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest032, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(osAccountManagerService_->QueryOsAccountById(Constants::MAX_USER_ID + 1, osAccountInfo),
        ERR_OS_ACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest033
 * @tc.desc: Test GetOsAccountTypeFromProcess.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest033, Function | MediumTest | Level1)
{
    int type;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountTypeFromProcess(type), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest034
 * @tc.desc: Test SetOsAccountName with valid data.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest034, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfoOne;
    osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_EQ(osAccountManagerService_->SetOsAccountName(osAccountInfoOne.GetId(), STRING_NAME), ERR_OK);
    OsAccountInfo osAccountInfoTwo;
    osAccountManagerService_->QueryOsAccountById(osAccountInfoOne.GetId(), osAccountInfoTwo);
    EXPECT_EQ(STRING_NAME, osAccountInfoTwo.GetName());
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest035
 * @tc.desc: Test SetOsAccountName with unvalid data.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest035, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfoOne;
    osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_NE(osAccountManagerService_->SetOsAccountName(osAccountInfoOne.GetId(), STRING_EMPTY), ERR_OK);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest036
 * @tc.desc: Test SetOsAccountName with unvalid data.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest036, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfoOne;
    osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_NE(osAccountManagerService_->SetOsAccountName(osAccountInfoOne.GetId(), STRING_NAME_OUT_OF_RANGE), ERR_OK);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest037
 * @tc.desc: Test GetDistributedVirtualDeviceId.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest037, Function | MediumTest | Level1)
{
    std::int32_t deviceId;
    EXPECT_EQ(osAccountManagerService_->GetDistributedVirtualDeviceId(deviceId), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest038
 * @tc.desc: Test GetOsAccountLocalIdForSerialNumber with valid data.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest038, Function | MediumTest | Level1)
{
    int id = 0;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountLocalIdForSerialNumber(
                  Constants::CARRY_NUM * Constants::SERIAL_NUMBER_NUM_START_FOR_ADMIN + Constants::START_USER_ID, id),
        ERR_OK);
    EXPECT_EQ(id, Constants::START_USER_ID);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest039
 * @tc.desc: Test GetOsAccountLocalIdForSerialNumber with unvalid data.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest039, Function | MediumTest | Level1)
{
    int id = 0;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountLocalIdForSerialNumber(123, id),
        ERR_OS_ACCOUNT_SERVICE_INNER_SELECT_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest040
 * @tc.desc: Test GetSerialNumberForOsAccount with valid data.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest040, Function | MediumTest | Level1)
{
    int64_t serialNumber;
    EXPECT_EQ(osAccountManagerService_->GetSerialNumberForOsAccount(Constants::START_USER_ID, serialNumber), ERR_OK);
    EXPECT_EQ(
        serialNumber, Constants::CARRY_NUM * Constants::SERIAL_NUMBER_NUM_START_FOR_ADMIN + Constants::START_USER_ID);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest041
 * @tc.desc: Test GetSerialNumberForOsAccount with unvalid data.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest041, Function | MediumTest | Level1)
{
    int64_t serialNumber;
    EXPECT_NE(osAccountManagerService_->GetSerialNumberForOsAccount(Constants::MAX_USER_ID + 1, serialNumber), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest042
 * @tc.desc: Test SetOsAccountProfilePhoto with valid data.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest042, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfoOne;
    osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_EQ(osAccountManagerService_->SetOsAccountProfilePhoto(osAccountInfoOne.GetId(), PHOTO_IMG), ERR_OK);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest043
 * @tc.desc: Test SetOsAccountProfilePhoto with unvalid data.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest043, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfoOne;
    osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_NE(osAccountManagerService_->SetOsAccountProfilePhoto(osAccountInfoOne.GetId(), STRING_PHOTO_OUT_OF_RANGE),
        ERR_OK);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest044
 * @tc.desc: Test SetOsAccountProfilePhoto with unvalid data.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest044, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfoOne;
    osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_NE(osAccountManagerService_->SetOsAccountProfilePhoto(osAccountInfoOne.GetId(), PHOTO_IMG_ERROR), ERR_OK);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest045
 * @tc.desc: Test GetOsAccountProfilePhoto with valid data.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest045, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfoOne;
    osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    osAccountManagerService_->SetOsAccountProfilePhoto(osAccountInfoOne.GetId(), PHOTO_IMG);
    std::string photo;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountProfilePhoto(osAccountInfoOne.GetId(), photo), ERR_OK);
    EXPECT_EQ(photo, PHOTO_IMG);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest046
 * @tc.desc: Test GetOsAccountProfilePhoto with unvalid data.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest046, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfoOne;
    osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    std::string photo;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountProfilePhoto(osAccountInfoOne.GetId(), photo),
        ERR_OS_ACCOUNT_SERVICE_INNER_DONNOT_HAVE_PHOTO_ERROR);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest047
 * @tc.desc: Test GetOsAccountProfilePhoto with unvalid id.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest047, Function | MediumTest | Level1)
{
    std::string photo;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountProfilePhoto(Constants::MAX_USER_ID + 1, photo),
        ERR_OS_ACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest048
 * @tc.desc: Test StartOsAccount with valid id.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest048, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfoOne;
    osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_EQ(osAccountManagerService_->StartOsAccount(osAccountInfoOne.GetId()), ERR_OK);
    osAccountManagerService_->StopOsAccount(osAccountInfoOne.GetId());
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest049
 * @tc.desc: Test StartOsAccount with unvalid id.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest049, Function | MediumTest | Level1)
{
    EXPECT_EQ(osAccountManagerService_->StartOsAccount(Constants::MAX_USER_ID + 1),
        ERR_OS_ACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest050
 * @tc.desc: Test StartOsAccount with started id.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest050, Function | MediumTest | Level1)
{
    EXPECT_EQ(osAccountManagerService_->StartOsAccount(Constants::START_USER_ID),
        ERR_OS_ACCOUNT_SERVICE_INNER_ACCOUNT_ALREAD_ACTIVE_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest051
 * @tc.desc: Test StopOsAccount with valid data.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest051, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfoOne;
    osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    osAccountManagerService_->StartOsAccount(osAccountInfoOne.GetId());
    EXPECT_EQ(osAccountManagerService_->StopOsAccount(osAccountInfoOne.GetId()), ERR_OK);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest052
 * @tc.desc: Test StopOsAccount with unvalid data.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest052, Function | MediumTest | Level1)
{
    EXPECT_EQ(osAccountManagerService_->StopOsAccount(Constants::MAX_USER_ID + 1),
        ERR_OS_ACCOUNT_SERVICE_INNER_ACCOUNT_STOP_ACTIVE_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest053
 * @tc.desc: Test ActivateOsAccount with valid data.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest053, Function | MediumTest | Level1)
{
    OsAccountInfo osAccountInfoOne;
    osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_EQ(osAccountManagerService_->ActivateOsAccount(osAccountInfoOne.GetId()), ERR_OK);
    osAccountManagerService_->ActivateOsAccount(Constants::START_USER_ID);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest054
 * @tc.desc: Test IsOsAccountCompleted with valid data.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest054, Function | MediumTest | Level1)
{
    bool isOsAccountCompleted = false;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountCompleted(Constants::START_USER_ID, isOsAccountCompleted), ERR_OK);
    EXPECT_EQ(isOsAccountCompleted, true);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest055
 * @tc.desc: Test IsOsAccountCompleted with unvalid data.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest055, Function | MediumTest | Level1)
{
    bool isOsAccountCompleted = false;
    EXPECT_NE(osAccountManagerService_->IsOsAccountCompleted(Constants::MAX_USER_ID + 1, isOsAccountCompleted), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest056
 * @tc.desc: Test SetOsAccountIsVerified with valid data.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest056, Function | MediumTest | Level1)
{
    bool isOsAccountVerified = true;
    OsAccountInfo osAccountInfoOne;
    osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_EQ(osAccountManagerService_->SetOsAccountIsVerified(osAccountInfoOne.GetId(), isOsAccountVerified), ERR_OK);
    OsAccountInfo osAccountInfoTwo;
    osAccountManagerService_->QueryOsAccountById(osAccountInfoOne.GetId(), osAccountInfoTwo);
    EXPECT_EQ(isOsAccountVerified, osAccountInfoTwo.GetIsAccountVerified());
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest057
 * @tc.desc: Test SetOsAccountIsVerified with unvalid data.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest057, Function | MediumTest | Level1)
{
    bool isOsAccountVerified = true;
    EXPECT_NE(
        osAccountManagerService_->SetOsAccountIsVerified(Constants::MAX_USER_ID + 1, isOsAccountVerified), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest058
 * @tc.desc: Test SetCurrentOsAccountIsVerified with valid data.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest058, Function | MediumTest | Level1)
{
    bool isOsAccountVerified = true;
    EXPECT_EQ(osAccountManagerService_->SetCurrentOsAccountIsVerified(isOsAccountVerified), ERR_OK);
}
}  // namespace AccountSA
}  // namespace OHOS