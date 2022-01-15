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
#include <thread>
#include "account_error_no.h"
#include "os_account_constants.h"
#define private public
#include "account_file_operator.h"
#include "os_account_control_file_manager.h"
#include "os_account_manager_service.h"
#undef private

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
const OsAccountType INT_TEST_TYPE = OsAccountType::GUEST;
const OsAccountType INT_TEST_ADMIN_TYPE = OsAccountType::ADMIN;

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
const std::int32_t DELAY_FOR_OPERATION = 20 * 1000;
std::shared_ptr<OsAccountManagerService> g_osAccountManagerService_;
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
}  // namespace

class OsAccountManagerServiceModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

public:
    std::shared_ptr<OsAccountControlFileManager> osAccountControlFileManager_;
    std::shared_ptr<AccountFileOperator> accountFileOperator_;
};

void OsAccountManagerServiceModuleTest::SetUpTestCase(void)
{
    g_osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_OPERATION));
}
void OsAccountManagerServiceModuleTest::TearDownTestCase(void)
{}

void OsAccountManagerServiceModuleTest::SetUp(void)
{
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
 * @tc.require: SR000GGV0U
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest001, TestSize.Level0)
{
    OsAccountInfo osAccountInfoOne;
    ErrCode errCode = g_osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_EQ(errCode, ERR_OK);
    OsAccountInfo osAccountInfoTwo;
    osAccountControlFileManager_->GetOsAccountInfoById(osAccountInfoOne.GetLocalId(), osAccountInfoTwo);
    EXPECT_EQ(osAccountInfoOne.ToString(), osAccountInfoTwo.ToString());
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest002
 * @tc.desc: Test CreateOsAccount with unvaild name.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest002, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    ErrCode errCode =
        g_osAccountManagerService_->CreateOsAccount(STRING_NAME_OUT_OF_RANGE, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_EQ(errCode, ERR_OS_ACCOUNT_SERVICE_MANAGER_NAME_SIZE_OVERFLOW_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest003
 * @tc.desc: Test CreateOsAccount with unvaild name.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest003, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    ErrCode errCode = g_osAccountManagerService_->CreateOsAccount(STRING_EMPTY, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_EQ(errCode, ERR_OS_ACCOUNT_SERVICE_MANAGER_NAME_SIZE_EMPTY_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest004
 * @tc.desc: Test IsCurrentOsAccountVerified with unvaild data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest004, TestSize.Level1)
{
    bool isVerify = false;
    ErrCode errCode = g_osAccountManagerService_->IsCurrentOsAccountVerified(isVerify);
    EXPECT_EQ(errCode, ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest005
 * @tc.desc: Test CreateOsAccount with vaild type.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFH
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest005, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    ErrCode errCode =
        g_osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_ADMIN_TYPE, osAccountInfoOne);
    EXPECT_EQ(errCode, ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest006
 * @tc.desc: Test actived os account can be remove.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFJ
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest006, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    g_osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    g_osAccountManagerService_->ActivateOsAccount(osAccountInfoOne.GetLocalId());
    EXPECT_EQ(g_osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest007
 * @tc.desc: Test CreateOsAccount when cannot find account_list.json.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest007, TestSize.Level1)
{
    std::string fileContext;
    accountFileOperator_->GetFileContentByPath(
        Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + Constants::USER_LIST_FILE_NAME, fileContext);
    accountFileOperator_->DeleteDirOrFile(
        Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + Constants::USER_LIST_FILE_NAME);
    OsAccountInfo osAccountInfoOne;
    ErrCode errCode = g_osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_EQ(errCode, ERR_OS_ACCOUNT_SERVICE_INNER_GET_SERIAL_NUMBER_ERROR);
    accountFileOperator_->InputFileByPathAndContent(
        Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + Constants::USER_LIST_FILE_NAME, fileContext);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest008
 * @tc.desc: Test RemoveOsAccount with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGV0U
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest008, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    g_osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_EQ(g_osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    EXPECT_EQ(accountFileOperator_->IsExistDir(
        Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + osAccountInfoOne.GetPrimeKey()), false);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest009
 * @tc.desc: Test RemoveOsAccount with cannot remove id.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest009, TestSize.Level1)
{
    EXPECT_EQ(g_osAccountManagerService_->RemoveOsAccount(Constants::START_USER_ID),
        ERR_OS_ACCOUNT_SERVICE_MANAGER_ID_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest010
 * @tc.desc: Test RemoveOsAccount with does not exists id.
 * @tc.type: FUNC
 * @tc.require: SR000GGV0U
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest010, TestSize.Level1)
{
    EXPECT_EQ(g_osAccountManagerService_->RemoveOsAccount(Constants::MAX_USER_ID + 1),
        ERR_OS_ACCOUNT_SERVICE_INNER_CANNOT_FIND_OSACCOUNT_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest011
 * @tc.desc: Test IsOsAccountExists with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest011, TestSize.Level1)
{
    bool isOsAccountExists = false;
    EXPECT_EQ(g_osAccountManagerService_->IsOsAccountExists(Constants::START_USER_ID, isOsAccountExists), ERR_OK);
    EXPECT_EQ(isOsAccountExists, true);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest012
 * @tc.desc: Test IsOsAccountExists with not exists data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest012, TestSize.Level1)
{
    bool isOsAccountExists = true;
    EXPECT_EQ(g_osAccountManagerService_->IsOsAccountExists(Constants::MAX_USER_ID + 1, isOsAccountExists), ERR_OK);
    EXPECT_EQ(isOsAccountExists, false);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest013
 * @tc.desc: Test IsOsAccountActived with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest013, TestSize.Level1)
{
    bool isOsAccountActived = false;
    EXPECT_EQ(g_osAccountManagerService_->IsOsAccountExists(Constants::START_USER_ID, isOsAccountActived), ERR_OK);
    EXPECT_EQ(isOsAccountActived, true);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest014
 * @tc.desc: Test IsOsAccountActived with not active account id.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest014, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    g_osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    bool isOsAccountActived = false;
    EXPECT_EQ(g_osAccountManagerService_->IsOsAccountExists(osAccountInfoOne.GetLocalId(), isOsAccountActived), ERR_OK);
    EXPECT_EQ(isOsAccountActived, true);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest015
 * @tc.desc: Test SetOsAccountConstraints with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFM
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest015, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    g_osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    bool enable = false;
    EXPECT_EQ(g_osAccountManagerService_->SetOsAccountConstraints(
        osAccountInfoOne.GetLocalId(), CONSTANTS_VECTOR, enable), ERR_OK);
    OsAccountInfo osAccountInfoTwo;
    osAccountControlFileManager_->GetOsAccountInfoById(osAccountInfoOne.GetLocalId(), osAccountInfoTwo);
    std::vector<std::string> contstans = osAccountInfoTwo.GetConstraints();
    for (auto it = contstans.begin(); it != contstans.end(); it++) {
        GTEST_LOG_(INFO) << *it;
    }
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest016
 * @tc.desc: Test SetOsAccountConstraints with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFM
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest016, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    g_osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    bool enable = true;
    EXPECT_EQ(g_osAccountManagerService_->SetOsAccountConstraints(
        osAccountInfoOne.GetLocalId(), CONSTANTS_VECTOR, enable), ERR_OK);
    OsAccountInfo osAccountInfoTwo;
    osAccountControlFileManager_->GetOsAccountInfoById(osAccountInfoOne.GetLocalId(), osAccountInfoTwo);
    std::vector<std::string> contstans = osAccountInfoTwo.GetConstraints();
    for (auto it = contstans.begin(); it != contstans.end(); it++) {
        GTEST_LOG_(INFO) << *it;
    }
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest017
 * @tc.desc: Test IsOsAccountConstraintEnable with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFM
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest017, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    g_osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    bool enable = true;
    g_osAccountManagerService_->SetOsAccountConstraints(osAccountInfoOne.GetLocalId(), CONSTANTS_VECTOR, enable);
    bool isEnable = false;
    EXPECT_EQ(g_osAccountManagerService_->IsOsAccountConstraintEnable(
        osAccountInfoOne.GetLocalId(), CONSTANTS_STRING_WIFI, isEnable), ERR_OK);
    EXPECT_EQ(isEnable, true);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest018
 * @tc.desc: Test IsOsAccountConstraintEnable with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFM
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest018, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    g_osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    bool isEnable = true;
    EXPECT_EQ(g_osAccountManagerService_->IsOsAccountConstraintEnable(
        osAccountInfoOne.GetLocalId(), CONSTANTS_STRING_WIFI, isEnable), ERR_OK);
    EXPECT_EQ(isEnable, false);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest019
 * @tc.desc: Test IsMultiOsAccountEnable
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest019, TestSize.Level0)
{
    bool isMultiOsAccountEnable = false;
    EXPECT_EQ(g_osAccountManagerService_->IsMultiOsAccountEnable(isMultiOsAccountEnable), ERR_OK);
    EXPECT_EQ(isMultiOsAccountEnable, true);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest020
 * @tc.desc: Test IsOsAccountVerified with not verified os account id.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest020, TestSize.Level1)
{
    bool isVerified = true;
    EXPECT_EQ(g_osAccountManagerService_->IsOsAccountVerified(Constants::START_USER_ID, isVerified), ERR_OK);
    EXPECT_EQ(isVerified, false);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest021
 * @tc.desc: Test IsOsAccountVerified with does not exists os account id.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest021, TestSize.Level1)
{
    bool isVerified = true;
    EXPECT_EQ(g_osAccountManagerService_->IsOsAccountVerified(Constants::MAX_USER_ID + 1, isVerified),
        ERR_OS_ACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest022
 * @tc.desc: Test IsOsAccountVerified with does not exists os account id.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest022, TestSize.Level1)
{
    bool isVerified = true;
    EXPECT_EQ(g_osAccountManagerService_->IsOsAccountVerified(Constants::MAX_USER_ID + 1, isVerified),
        ERR_OS_ACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest023
 * @tc.desc: Test GetCreatedOsAccountsCount.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest023, TestSize.Level1)
{
    int osAccountsCount = 0;
    EXPECT_EQ(g_osAccountManagerService_->GetCreatedOsAccountsCount(osAccountsCount), ERR_OK);
    EXPECT_NE(osAccountsCount, 0);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest024
 * @tc.desc: Test GetOsAccountLocalIdFromProcess.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest024, TestSize.Level1)
{
    int id = -1;
    EXPECT_EQ(g_osAccountManagerService_->GetOsAccountLocalIdFromProcess(id), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest025
 * @tc.desc: Test GetOsAccountLocalIdFromUid.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest025, TestSize.Level1)
{
    int uid = 0;
    int id = -1;
    EXPECT_EQ(g_osAccountManagerService_->GetOsAccountLocalIdFromUid(uid, id), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest026
 * @tc.desc: Test QueryMaxOsAccountNumber.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest026, TestSize.Level1)
{
    int maxOsAccountNumber = 0;
    EXPECT_EQ(g_osAccountManagerService_->QueryMaxOsAccountNumber(maxOsAccountNumber), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest027
 * @tc.desc: Test GetOsAccountAllConstraints with exisit os account id.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest027, TestSize.Level1)
{
    std::vector<std::string> constraints;
    EXPECT_EQ(g_osAccountManagerService_->GetOsAccountAllConstraints(Constants::START_USER_ID, constraints), ERR_OK);
    const unsigned int size = 0;
    EXPECT_NE(size, constraints.size());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest028
 * @tc.desc: Test GetOsAccountAllConstraints with does not exisit os account id.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFH
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest028, TestSize.Level1)
{
    std::vector<std::string> constraints;
    EXPECT_EQ(g_osAccountManagerService_->GetOsAccountAllConstraints(Constants::MAX_USER_ID + 1, constraints),
        ERR_OS_ACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest029
 * @tc.desc: Test QueryAllCreatedOsAccounts.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest029, TestSize.Level1)
{
    std::vector<OsAccountInfo> osAccountInfos;
    EXPECT_EQ(g_osAccountManagerService_->QueryAllCreatedOsAccounts(osAccountInfos), ERR_OK);
    const unsigned int size = 0;
    EXPECT_NE(size, osAccountInfos.size());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest030
 * @tc.desc: Test QueryCurrentOsAccount.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest030, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(g_osAccountManagerService_->QueryCurrentOsAccount(osAccountInfo), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest031
 * @tc.desc: Test QueryOsAccountById with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest031, TestSize.Level0)
{
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(g_osAccountManagerService_->QueryOsAccountById(Constants::START_USER_ID, osAccountInfo), ERR_OK);
    EXPECT_EQ(Constants::START_USER_ID, osAccountInfo.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest032
 * @tc.desc: Test QueryOsAccountById with unvalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest032, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(g_osAccountManagerService_->QueryOsAccountById(Constants::MAX_USER_ID + 1, osAccountInfo),
        ERR_OS_ACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest033
 * @tc.desc: Test GetOsAccountTypeFromProcess.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest033, TestSize.Level1)
{
    OsAccountType type;
    EXPECT_EQ(g_osAccountManagerService_->GetOsAccountTypeFromProcess(type), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest034
 * @tc.desc: Test SetOsAccountName with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFI
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest034, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    g_osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_EQ(g_osAccountManagerService_->SetOsAccountName(osAccountInfoOne.GetLocalId(), STRING_NAME), ERR_OK);
    OsAccountInfo osAccountInfoTwo;
    g_osAccountManagerService_->QueryOsAccountById(osAccountInfoOne.GetLocalId(), osAccountInfoTwo);
    EXPECT_EQ(STRING_NAME, osAccountInfoTwo.GetLocalName());
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest035
 * @tc.desc: Test SetOsAccountName with unvalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFI
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest035, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    g_osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_NE(g_osAccountManagerService_->SetOsAccountName(osAccountInfoOne.GetLocalId(), STRING_EMPTY), ERR_OK);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest036
 * @tc.desc: Test SetOsAccountName with unvalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest036, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    g_osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_NE(g_osAccountManagerService_->SetOsAccountName(
        osAccountInfoOne.GetLocalId(), STRING_NAME_OUT_OF_RANGE), ERR_OK);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest037
 * @tc.desc: Test GetDistributedVirtualDeviceId.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest037, TestSize.Level1)
{
    std::string deviceId;
    EXPECT_EQ(g_osAccountManagerService_->GetDistributedVirtualDeviceId(deviceId), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest038
 * @tc.desc: Test GetOsAccountLocalIdBySerialNumber with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest038, TestSize.Level1)
{
    int id = 0;
    EXPECT_EQ(g_osAccountManagerService_->GetOsAccountLocalIdBySerialNumber(
        Constants::CARRY_NUM * Constants::SERIAL_NUMBER_NUM_START_FOR_ADMIN + 1, id), ERR_OK);
    EXPECT_EQ(id, Constants::START_USER_ID);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest039
 * @tc.desc: Test GetOsAccountLocalIdBySerialNumber with unvalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest039, TestSize.Level1)
{
    int id = 0;
    EXPECT_NE(g_osAccountManagerService_->GetOsAccountLocalIdBySerialNumber(123, id), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest040
 * @tc.desc: Test GetSerialNumberByOsAccountLocalId with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest040, TestSize.Level1)
{
    int64_t serialNumber;
    EXPECT_EQ(g_osAccountManagerService_->GetSerialNumberByOsAccountLocalId(
        Constants::START_USER_ID, serialNumber), ERR_OK);
    EXPECT_EQ(serialNumber, Constants::CARRY_NUM * Constants::SERIAL_NUMBER_NUM_START_FOR_ADMIN + 1);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest041
 * @tc.desc: Test GetSerialNumberByOsAccountLocalId with unvalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest041, TestSize.Level1)
{
    int64_t serialNumber;
    EXPECT_NE(g_osAccountManagerService_->GetSerialNumberByOsAccountLocalId(
        Constants::MAX_USER_ID + 1, serialNumber), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest042
 * @tc.desc: Test SetOsAccountProfilePhoto with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFI
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest042, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    g_osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_EQ(g_osAccountManagerService_->SetOsAccountProfilePhoto(osAccountInfoOne.GetLocalId(), PHOTO_IMG), ERR_OK);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest043
 * @tc.desc: Test SetOsAccountProfilePhoto with unvalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest043, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    g_osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_NE(g_osAccountManagerService_->SetOsAccountProfilePhoto(
        osAccountInfoOne.GetLocalId(), STRING_PHOTO_OUT_OF_RANGE), ERR_OK);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest044
 * @tc.desc: Test SetOsAccountProfilePhoto with unvalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest044, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    g_osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_NE(g_osAccountManagerService_->SetOsAccountProfilePhoto(
        osAccountInfoOne.GetLocalId(), PHOTO_IMG_ERROR), ERR_OK);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest045
 * @tc.desc: Test GetOsAccountProfilePhoto with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest045, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    g_osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    g_osAccountManagerService_->SetOsAccountProfilePhoto(osAccountInfoOne.GetLocalId(), PHOTO_IMG);
    std::string photo;
    EXPECT_EQ(g_osAccountManagerService_->GetOsAccountProfilePhoto(osAccountInfoOne.GetLocalId(), photo), ERR_OK);
    EXPECT_EQ(photo, PHOTO_IMG);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest046
 * @tc.desc: Test GetOsAccountProfilePhoto with unvalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest046, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    g_osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    std::string photo;
    EXPECT_EQ(g_osAccountManagerService_->GetOsAccountProfilePhoto(osAccountInfoOne.GetLocalId(), photo),
        ERR_OS_ACCOUNT_SERVICE_INNER_DONNOT_HAVE_PHOTO_ERROR);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest047
 * @tc.desc: Test GetOsAccountProfilePhoto with unvalid id.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest047, TestSize.Level1)
{
    std::string photo;
    EXPECT_EQ(g_osAccountManagerService_->GetOsAccountProfilePhoto(Constants::MAX_USER_ID + 1, photo),
        ERR_OS_ACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest048
 * @tc.desc: Test StartOsAccount with valid id.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFJ
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest048, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    g_osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_EQ(g_osAccountManagerService_->StartOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    g_osAccountManagerService_->StopOsAccount(osAccountInfoOne.GetLocalId());
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest049
 * @tc.desc: Test StartOsAccount with unvalid id.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFJ
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest049, TestSize.Level1)
{
    EXPECT_EQ(g_osAccountManagerService_->StartOsAccount(Constants::MAX_USER_ID + 1),
        ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest050
 * @tc.desc: Test StartOsAccount with started id.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFJ
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest050, TestSize.Level1)
{
    EXPECT_EQ(g_osAccountManagerService_->StartOsAccount(Constants::START_USER_ID),
        ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest051
 * @tc.desc: Test StopOsAccount with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFJ
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest051, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    g_osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    g_osAccountManagerService_->StartOsAccount(osAccountInfoOne.GetLocalId());
    EXPECT_EQ(g_osAccountManagerService_->StopOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest052
 * @tc.desc: Test StopOsAccount with unvalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFJ
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest052, TestSize.Level1)
{
    EXPECT_EQ(g_osAccountManagerService_->StopOsAccount(Constants::MAX_USER_ID + 1),
        ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest053
 * @tc.desc: Test ActivateOsAccount with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFJ
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest053, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    g_osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_EQ(g_osAccountManagerService_->ActivateOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    g_osAccountManagerService_->ActivateOsAccount(Constants::START_USER_ID);
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest054
 * @tc.desc: Test IsOsAccountCompleted with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFJ
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest054, TestSize.Level1)
{
    bool isOsAccountCompleted = false;
    EXPECT_EQ(g_osAccountManagerService_->IsOsAccountCompleted(
        Constants::START_USER_ID, isOsAccountCompleted), ERR_OK);
    EXPECT_EQ(isOsAccountCompleted, true);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest055
 * @tc.desc: Test IsOsAccountCompleted with unvalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest055, TestSize.Level1)
{
    bool isOsAccountCompleted = false;
    EXPECT_NE(g_osAccountManagerService_->IsOsAccountCompleted(
        Constants::MAX_USER_ID + 1, isOsAccountCompleted), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest056
 * @tc.desc: Test SetOsAccountIsVerified with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest056, TestSize.Level1)
{
    bool isVerified = true;
    OsAccountInfo osAccountInfoOne;
    g_osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_EQ(g_osAccountManagerService_->SetOsAccountIsVerified(osAccountInfoOne.GetLocalId(), isVerified), ERR_OK);
    OsAccountInfo osAccountInfoTwo;
    g_osAccountManagerService_->QueryOsAccountById(osAccountInfoOne.GetLocalId(), osAccountInfoTwo);
    EXPECT_EQ(isVerified, osAccountInfoTwo.GetIsVerified());
    osAccountControlFileManager_->DelOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest057
 * @tc.desc: Test SetOsAccountIsVerified with unvalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest057, TestSize.Level1)
{
    bool isVerified = true;
    EXPECT_NE(g_osAccountManagerService_->SetOsAccountIsVerified(Constants::MAX_USER_ID + 1, isVerified), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest058
 * @tc.desc: Test SetCurrentOsAccountIsVerified with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFI
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest058, TestSize.Level1)
{
    bool isVerified = true;
    EXPECT_NE(g_osAccountManagerService_->SetCurrentOsAccountIsVerified(isVerified), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest059
 * @tc.desc: create an os account by domain, and remove it
 * @tc.type: FUNC
 * @tc.require: SR000GGVFL
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest059, TestSize.Level1)
{
    OsAccountType type = NORMAL;
    DomainAccountInfo domainInfo(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(g_osAccountManagerService_->CreateOsAccountForDomain(type, domainInfo, osAccountInfo), ERR_OK);

    bool checkValid = (osAccountInfo.GetLocalId() > Constants::START_USER_ID);
    EXPECT_EQ(checkValid, true);

    OsAccountInfo resOsAccountInfo;
    EXPECT_EQ(osAccountControlFileManager_->GetOsAccountInfoById(osAccountInfo.GetLocalId(), resOsAccountInfo),
        ERR_OK);

    DomainAccountInfo resDomainInfo;
    resOsAccountInfo.GetDomainInfo(resDomainInfo);
    checkValid = (resDomainInfo.accountName_ == domainInfo.accountName_);
    EXPECT_EQ(checkValid, true);
    checkValid = (resDomainInfo.domain_ == domainInfo.domain_);
    EXPECT_EQ(checkValid, true);

    std::string osAccountName = domainInfo.domain_ + "/" + domainInfo.accountName_;
    checkValid = (resOsAccountInfo.GetLocalName() == osAccountName);
    EXPECT_EQ(checkValid, true);

    EXPECT_EQ(osAccountControlFileManager_->DelOsAccount(resOsAccountInfo.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest060
 * @tc.desc: create an os account by domain, and activate it
 * @tc.type: FUNC
 * @tc.require: SR000GGVFL
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest060, TestSize.Level1)
{
    // create
    DomainAccountInfo domainInfo(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    OsAccountType type = NORMAL;
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(g_osAccountManagerService_->CreateOsAccountForDomain(type, domainInfo, osAccountInfo), ERR_OK);

    bool checkValid = (osAccountInfo.GetLocalId() > Constants::START_USER_ID);
    EXPECT_EQ(checkValid, true);

    OsAccountInfo resOsAccountInfo;
    EXPECT_EQ(osAccountControlFileManager_->GetOsAccountInfoById(osAccountInfo.GetLocalId(), resOsAccountInfo),
        ERR_OK);

    DomainAccountInfo resDomainInfo;
    resOsAccountInfo.GetDomainInfo(resDomainInfo);
    checkValid = (resDomainInfo.accountName_ == domainInfo.accountName_);
    EXPECT_EQ(checkValid, true);
    checkValid = (resDomainInfo.domain_ == domainInfo.domain_);
    EXPECT_EQ(checkValid, true);

    std::string osAccountName = domainInfo.domain_ + "/" + domainInfo.accountName_;
    checkValid = (resOsAccountInfo.GetLocalName() == osAccountName);
    EXPECT_EQ(checkValid, true);

    // activate
    EXPECT_EQ(g_osAccountManagerService_->ActivateOsAccount(osAccountInfo.GetLocalId()), ERR_OK);

    // check
    OsAccountInfo queryAccountInfo;
    EXPECT_EQ(g_osAccountManagerService_->QueryOsAccountById(osAccountInfo.GetLocalId(), queryAccountInfo), ERR_OK);
    EXPECT_EQ(queryAccountInfo.GetLocalId(), osAccountInfo.GetLocalId());
    EXPECT_EQ(queryAccountInfo.GetIsActived(), true);
    checkValid = (queryAccountInfo.GetLocalName() == osAccountName);
    EXPECT_EQ(checkValid, true);

    // remove
    EXPECT_EQ(osAccountControlFileManager_->DelOsAccount(osAccountInfo.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest061
 * @tc.desc: Create os account for domain use invalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFL
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest061, TestSize.Level1)
{
    DomainAccountInfo domainNameInvalid(STRING_DOMAIN_NAME_OUT_OF_RANGE, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    OsAccountType type = NORMAL;
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(g_osAccountManagerService_->CreateOsAccountForDomain(type, domainNameInvalid, osAccountInfo),
        ERR_OS_ACCOUNT_SERVICE_MANAGER_NAME_SIZE_OVERFLOW_ERROR);

    DomainAccountInfo domainAccountNameInvalid(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_OUT_OF_RANGE);
    EXPECT_EQ(g_osAccountManagerService_->CreateOsAccountForDomain(type, domainAccountNameInvalid, osAccountInfo),
        ERR_OS_ACCOUNT_SERVICE_MANAGER_NAME_SIZE_OVERFLOW_ERROR);

    DomainAccountInfo domainEmpty("", STRING_DOMAIN_ACCOUNT_NAME_VALID);
    EXPECT_EQ(g_osAccountManagerService_->CreateOsAccountForDomain(type, domainEmpty, osAccountInfo),
        ERR_OS_ACCOUNT_SERVICE_MANAGER_NAME_SIZE_EMPTY_ERROR);

    DomainAccountInfo domainAccountEmpty(STRING_DOMAIN_VALID, "");
    EXPECT_EQ(g_osAccountManagerService_->CreateOsAccountForDomain(type, domainAccountEmpty, osAccountInfo),
        ERR_OS_ACCOUNT_SERVICE_MANAGER_NAME_SIZE_EMPTY_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest062
 * @tc.desc: repeat create os account for domain
 * @tc.type: FUNC
 * @tc.require: SR000GGVFL
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest062, TestSize.Level1)
{
    // create
    DomainAccountInfo domainInfo(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    OsAccountType type = NORMAL;
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(g_osAccountManagerService_->CreateOsAccountForDomain(type, domainInfo, osAccountInfo), ERR_OK);

    // create again
    EXPECT_EQ(g_osAccountManagerService_->CreateOsAccountForDomain(type, domainInfo, osAccountInfo),
        ERR_OS_ACCOUNT_SERVICE_INNER_DOMAIN_ALREADY_BIND_ERROR);

    // remove
    EXPECT_EQ(osAccountControlFileManager_->DelOsAccount(osAccountInfo.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest063
 * @tc.desc: repeat create os account for domain
 * @tc.type: FUNC
 * @tc.require: SR000GGVFL
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest063, TestSize.Level1)
{
    // create
    DomainAccountInfo domainInfo(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    OsAccountType type = NORMAL;
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(g_osAccountManagerService_->CreateOsAccountForDomain(type, domainInfo, osAccountInfo), ERR_OK);

    // create again
    EXPECT_EQ(g_osAccountManagerService_->CreateOsAccountForDomain(type, domainInfo, osAccountInfo),
        ERR_OS_ACCOUNT_SERVICE_INNER_DOMAIN_ALREADY_BIND_ERROR);

    // remove
    EXPECT_EQ(osAccountControlFileManager_->DelOsAccount(osAccountInfo.GetLocalId()), ERR_OK);

    // create again
    EXPECT_EQ(g_osAccountManagerService_->CreateOsAccountForDomain(type, domainInfo, osAccountInfo), ERR_OK);

    // remove
    EXPECT_EQ(osAccountControlFileManager_->DelOsAccount(osAccountInfo.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest064
 * @tc.desc: query os account by domain info
 * @tc.type: FUNC
 * @tc.require: SR000GGVFL
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest064, TestSize.Level1)
{
    // create
    DomainAccountInfo domainInfo(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    OsAccountType type = NORMAL;
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(g_osAccountManagerService_->CreateOsAccountForDomain(type, domainInfo, osAccountInfo), ERR_OK);

    // get os account local id by domain
    int resID = -1;
    EXPECT_EQ(g_osAccountManagerService_->GetOsAccountLocalIdFromDomain(domainInfo, resID), ERR_OK);
    EXPECT_EQ(resID, osAccountInfo.GetLocalId());

    // remove
    EXPECT_EQ(osAccountControlFileManager_->DelOsAccount(osAccountInfo.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest065
 * @tc.desc: query os account by domain info
 * @tc.type: FUNC
 * @tc.require: SR000GGVFL
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest065, TestSize.Level1)
{
    // create
    DomainAccountInfo domainInfo(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    OsAccountType type = NORMAL;
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(g_osAccountManagerService_->CreateOsAccountForDomain(type, domainInfo, osAccountInfo), ERR_OK);

    // get os account local id by domain
    int resID = -1;
    EXPECT_EQ(g_osAccountManagerService_->GetOsAccountLocalIdFromDomain(domainInfo, resID), ERR_OK);
    EXPECT_EQ(resID, osAccountInfo.GetLocalId());

    // remove
    EXPECT_EQ(osAccountControlFileManager_->DelOsAccount(osAccountInfo.GetLocalId()), ERR_OK);

    // cannot query
    EXPECT_EQ(g_osAccountManagerService_->GetOsAccountLocalIdFromDomain(domainInfo, resID),
        ERR_OSACCOUNT_KIT_GET_OS_ACCOUNT_LOCAL_ID_FOR_DOMAIN_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest066
 * @tc.desc: query os account by domain info
 * @tc.type: FUNC
 * @tc.require: SR000GGVFL
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest066, TestSize.Level1)
{
    DomainAccountInfo domainAllEmpty("", "");
    int resLocalId = -1;
    ErrCode ret = g_osAccountManagerService_->GetOsAccountLocalIdFromDomain(domainAllEmpty, resLocalId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SERVICE_INNER_DOMAIN_NAME_LEN_ERROR);

    DomainAccountInfo domainNameEmpty("", STRING_DOMAIN_ACCOUNT_NAME_VALID);
    ret = g_osAccountManagerService_->GetOsAccountLocalIdFromDomain(domainNameEmpty, resLocalId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SERVICE_INNER_DOMAIN_NAME_LEN_ERROR);

    DomainAccountInfo domainAccountEmpty(STRING_DOMAIN_VALID, "");
    ret = g_osAccountManagerService_->GetOsAccountLocalIdFromDomain(domainAccountEmpty, resLocalId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SERVICE_INNER_DOMAIN_ACCOUNT_NAME_LEN_ERROR);

    DomainAccountInfo domainAllTooLong(STRING_DOMAIN_NAME_OUT_OF_RANGE, STRING_DOMAIN_ACCOUNT_NAME_OUT_OF_RANGE);
    ret = g_osAccountManagerService_->GetOsAccountLocalIdFromDomain(domainAllTooLong, resLocalId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SERVICE_INNER_DOMAIN_NAME_LEN_ERROR);

    DomainAccountInfo domainNameTooLong(STRING_DOMAIN_NAME_OUT_OF_RANGE, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    ret = g_osAccountManagerService_->GetOsAccountLocalIdFromDomain(domainNameTooLong, resLocalId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SERVICE_INNER_DOMAIN_NAME_LEN_ERROR);

    DomainAccountInfo domainAccountTooLong(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_OUT_OF_RANGE);
    ret = g_osAccountManagerService_->GetOsAccountLocalIdFromDomain(domainAccountTooLong, resLocalId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SERVICE_INNER_DOMAIN_ACCOUNT_NAME_LEN_ERROR);
}
}  // namespace AccountSA
}  // namespace OHOS
