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
#include <cerrno>
#include <gtest/gtest.h>
#include <thread>
#include <unistd.h>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "os_account_constants.h"
#define private public
#include "account_file_operator.h"
#include "iinner_os_account_manager.h"
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
const uid_t ACCOUNT_UID = 3058;
const gid_t ACCOUNT_GID = 3058;

const std::vector<std::string> CONSTANTS_VECTOR {
    "constraint.print",
    "constraint.screen.timeout.set",
    "constraint.share.into.profile"
};
const std::vector<std::string> CONSTANTS_VECTOR_TEST {
    "constraint.wifi",
};
const std::string CONSTANT_PRINT = "constraint.print";
const std::string CONSTANT_WIFI = "constraint.wifi";
const std::string CONSTANTS_STRING_WIFI = "constraint.print";
const std::vector<std::string> INVALID_CONSTRAINT = {
    "invalid_constraint"
};
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
const std::int32_t DELAY_FOR_OPERATION = 2000;
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
const std::int32_t MAIN_ACCOUNT_ID = 100;
const std::int32_t INVALID_ACCOUNT_ID = 200;
}  // namespace

class OsAccountManagerServiceModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::shared_ptr<OsAccountManagerService>
        osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    std::shared_ptr<OsAccountControlFileManager> osAccountControlFileManager_ =
        std::make_shared<OsAccountControlFileManager>();
    std::shared_ptr<AccountFileOperator> g_accountFileOperator = std::make_shared<AccountFileOperator>();
};

void OsAccountManagerServiceModuleTest::SetUpTestCase(void)
{}

void OsAccountManagerServiceModuleTest::TearDownTestCase(void)
{
    GTEST_LOG_(INFO) << "TearDownTestCase enter!";
    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
    std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_OPERATION));
    GTEST_LOG_(INFO) << "TearDownTestCase exit!";
}

void OsAccountManagerServiceModuleTest::SetUp(void)
{
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
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest001");
    OsAccountInfo osAccountInfoOne;
    ErrCode errCode = osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_EQ(errCode, ERR_OK);
    OsAccountInfo osAccountInfoTwo;
    errCode = osAccountManagerService_->QueryOsAccountById(osAccountInfoOne.GetLocalId(), osAccountInfoTwo);
    EXPECT_EQ(errCode, ERR_OK);
    EXPECT_EQ(osAccountInfoOne.ToString(), osAccountInfoTwo.ToString());
    errCode = osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId());
    EXPECT_EQ(errCode, ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest002
 * @tc.desc: Test CreateOsAccount with invalid name.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest002, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest002");
    OsAccountInfo osAccountInfoOne;
    ErrCode errCode =
        osAccountManagerService_->CreateOsAccount(STRING_NAME_OUT_OF_RANGE, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_EQ(errCode, ERR_OSACCOUNT_SERVICE_MANAGER_NAME_SIZE_OVERFLOW_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest003
 * @tc.desc: Test CreateOsAccount with invalid name.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest003, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest003");
    OsAccountInfo osAccountInfoOne;
    ErrCode errCode = osAccountManagerService_->CreateOsAccount(STRING_EMPTY, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_EQ(errCode, ERR_OSACCOUNT_SERVICE_MANAGER_NAME_SIZE_EMPTY_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest004
 * @tc.desc: Test IsCurrentOsAccountVerified with invalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest004, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest004");
    bool isVerify = false;
    ErrCode errCode = osAccountManagerService_->IsCurrentOsAccountVerified(isVerify);
    EXPECT_EQ(errCode, ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest005
 * @tc.desc: Test CreateOsAccount with valid type.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFH
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest005, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest005");
    OsAccountInfo osAccountInfoOne;
    ErrCode errCode = osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, OsAccountType::ADMIN,
        osAccountInfoOne);
    EXPECT_EQ(errCode, ERR_OK);
    errCode = osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId());
    EXPECT_EQ(errCode, ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest006
 * @tc.desc: Test active os account can be remove.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFJ
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest006, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest006");
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->ActivateOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest007
 * @tc.desc: Test CreateOsAccount when cannot find account_list.json.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest007, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest007");
    // save file content to fileContext first
    std::string fileContext;
    g_accountFileOperator->GetFileContentByPath(Constants::ACCOUNT_LIST_FILE_JSON_PATH, fileContext);

    // remove file
    g_accountFileOperator->DeleteDirOrFile(Constants::ACCOUNT_LIST_FILE_JSON_PATH);
    OsAccountInfo osAccountInfoOne;
    ErrCode errCode = osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_EQ(errCode, ERR_OSACCOUNT_SERVICE_INNER_GET_SERIAL_NUMBER_ERROR);

    // restore file content
    g_accountFileOperator->InputFileByPathAndContent(Constants::ACCOUNT_LIST_FILE_JSON_PATH, fileContext);

    // recover permission
    if (chmod(Constants::ACCOUNT_LIST_FILE_JSON_PATH.c_str(), S_IRUSR | S_IWUSR) != 0) {
        ACCOUNT_LOGE("OsAccountManagerModuleTest006, chmod failed! errno %{public}d.", errno);
    }
    if (chown(Constants::ACCOUNT_LIST_FILE_JSON_PATH.c_str(), ACCOUNT_UID, ACCOUNT_GID) != 0) {
        ACCOUNT_LOGE("OsAccountManagerModuleTest006, chown failed! errno %{public}d.", errno);
    }
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest008
 * @tc.desc: Test RemoveOsAccount with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGV0U
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest008, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest008");
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    EXPECT_EQ(g_accountFileOperator->IsExistDir(
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
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest009");
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(Constants::START_USER_ID),
        ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest010
 * @tc.desc: Test RemoveOsAccount with does not exists id.
 * @tc.type: FUNC
 * @tc.require: SR000GGV0U
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest010, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest010");
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(Constants::MAX_USER_ID + 1),
        ERR_OSACCOUNT_KIT_LOCAL_ID_INVALID_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest011
 * @tc.desc: Test IsOsAccountExists with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest011, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest011");
    bool isOsAccountExists = false;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountExists(Constants::START_USER_ID, isOsAccountExists), ERR_OK);
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
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest012");
    bool isOsAccountExists = true;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountExists(Constants::MAX_USER_ID + 1, isOsAccountExists), ERR_OK);
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
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest013");
    bool isOsAccountActive = false;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountActived(Constants::START_USER_ID, isOsAccountActive), ERR_OK);
    EXPECT_EQ(isOsAccountActive, true);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest014
 * @tc.desc: Test IsOsAccountActived with not active account id.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest014, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest014");
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne),
        ERR_OK);
    bool isOsAccountActived = false;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountActived(osAccountInfoOne.GetLocalId(), isOsAccountActived),
        ERR_OK);
    EXPECT_EQ(isOsAccountActived, false);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest015
 * @tc.desc: Test SetOsAccountConstraints with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFE
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest015, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest015");
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne),
        ERR_OK);
    bool enable = false;
    EXPECT_EQ(osAccountManagerService_->SetOsAccountConstraints(
        osAccountInfoOne.GetLocalId(), CONSTANTS_VECTOR, enable), ERR_OK);
    OsAccountInfo osAccountInfoTwo;
    EXPECT_EQ(osAccountManagerService_->QueryOsAccountById(osAccountInfoOne.GetLocalId(), osAccountInfoTwo),
        ERR_OK);

    std::vector<std::string> constraints = osAccountInfoTwo.GetConstraints();
    for (auto it = constraints.begin(); it != constraints.end(); it++) {
        GTEST_LOG_(INFO) << *it;
    }
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest016
 * @tc.desc: Test SetOsAccountConstraints with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFE
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest016, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest016");
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne), ERR_OK);
    bool enable = true;
    EXPECT_EQ(osAccountManagerService_->SetOsAccountConstraints(
        osAccountInfoOne.GetLocalId(), CONSTANTS_VECTOR, enable), ERR_OK);
    OsAccountInfo osAccountInfoTwo;
    EXPECT_EQ(osAccountManagerService_->QueryOsAccountById(osAccountInfoOne.GetLocalId(), osAccountInfoTwo),
        ERR_OK);
    std::vector<std::string> constraints = osAccountInfoTwo.GetConstraints();
    for (auto it = constraints.begin(); it != constraints.end(); it++) {
        GTEST_LOG_(INFO) << *it;
    }
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest017
 * @tc.desc: Test IsOsAccountConstraintEnable with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFE SR000GH18T
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest017, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest017");
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne), ERR_OK);
    bool enable = true;
    osAccountManagerService_->SetOsAccountConstraints(osAccountInfoOne.GetLocalId(), CONSTANTS_VECTOR, enable);
    bool isEnable = false;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountConstraintEnable(
        osAccountInfoOne.GetLocalId(), CONSTANTS_STRING_WIFI, isEnable), ERR_OK);
    EXPECT_EQ(isEnable, true);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest018
 * @tc.desc: Test IsOsAccountConstraintEnable with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFE SR000GH18T
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest018, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest018");
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne), ERR_OK);
    bool isEnable = true;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountConstraintEnable(
        osAccountInfoOne.GetLocalId(), CONSTANTS_STRING_WIFI, isEnable), ERR_OK);
    EXPECT_EQ(isEnable, false);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest019
 * @tc.desc: Test IsMultiOsAccountEnable
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest019, TestSize.Level0)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest019");
    bool isMultiOsAccountEnable = false;
    EXPECT_EQ(osAccountManagerService_->IsMultiOsAccountEnable(isMultiOsAccountEnable), ERR_OK);
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
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest020");
    bool isVerified = true;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountVerified(Constants::START_USER_ID, isVerified), ERR_OK);
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
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest021");
    bool isVerified = true;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountVerified(Constants::MAX_USER_ID + 1, isVerified),
        ERR_OSACCOUNT_KIT_LOCAL_ID_INVALID_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest022
 * @tc.desc: Test IsOsAccountVerified with does not exists os account id.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest022, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest022");
    bool isVerified = true;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountVerified(Constants::MAX_USER_ID + 1, isVerified),
        ERR_OSACCOUNT_KIT_LOCAL_ID_INVALID_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest023
 * @tc.desc: Test GetCreatedOsAccountsCount.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest023, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest023");
    unsigned int osAccountsCount = 0;
    EXPECT_EQ(osAccountManagerService_->GetCreatedOsAccountsCount(osAccountsCount), ERR_OK);
    bool checkExpected = (osAccountsCount > 0);
    EXPECT_EQ(checkExpected, true);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest024
 * @tc.desc: Test GetOsAccountLocalIdFromProcess.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFF
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest024, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest024");
    int id = -1;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountLocalIdFromProcess(id), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest025
 * @tc.desc: Test QueryMaxOsAccountNumber.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest025, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest025");
    int maxOsAccountNumber = 0;
    EXPECT_EQ(osAccountManagerService_->QueryMaxOsAccountNumber(maxOsAccountNumber), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest026
 * @tc.desc: Test GetOsAccountAllConstraints with exist os account id.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFE SR000GH18T
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest026, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest026");
    std::vector<std::string> constraints;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountAllConstraints(Constants::START_USER_ID, constraints), ERR_OK);
    const unsigned int size = 0;
    EXPECT_NE(size, constraints.size());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest027
 * @tc.desc: Test GetOsAccountAllConstraints with does not exist os account id.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFE SR000GH18T
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest027, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest027");
    std::vector<std::string> constraints;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountAllConstraints(Constants::MAX_USER_ID + 1, constraints),
        ERR_OSACCOUNT_KIT_LOCAL_ID_INVALID_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest028
 * @tc.desc: Test QueryAllCreatedOsAccounts.
 * @tc.type: FUNC
 * @tc.require: SR000GH18T
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest028, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest028");
    std::vector<OsAccountInfo> osAccountInfos;
    EXPECT_EQ(osAccountManagerService_->QueryAllCreatedOsAccounts(osAccountInfos), ERR_OK);
    const unsigned int size = 0;
    EXPECT_NE(size, osAccountInfos.size());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest029
 * @tc.desc: Test QueryCurrentOsAccount.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest029, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest029");
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(osAccountManagerService_->QueryCurrentOsAccount(osAccountInfo), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest030
 * @tc.desc: Test QueryOsAccountById with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFF
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest030, TestSize.Level0)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest030");
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(osAccountManagerService_->QueryOsAccountById(Constants::START_USER_ID, osAccountInfo), ERR_OK);
    EXPECT_EQ(Constants::START_USER_ID, osAccountInfo.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest031
 * @tc.desc: Test QueryOsAccountById with invalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFF
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest031, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest031");
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(osAccountManagerService_->QueryOsAccountById(Constants::MAX_USER_ID + 1, osAccountInfo),
        ERR_OSACCOUNT_KIT_LOCAL_ID_INVALID_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest032
 * @tc.desc: Test GetOsAccountTypeFromProcess.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest032, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest032");
    OsAccountType type;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountTypeFromProcess(type), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest033
 * @tc.desc: Test SetOsAccountName with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFF
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest033, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest033");
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne),
        ERR_OK);
    EXPECT_EQ(osAccountManagerService_->SetOsAccountName(osAccountInfoOne.GetLocalId(), STRING_NAME), ERR_OK);
    OsAccountInfo osAccountInfoTwo;
    EXPECT_EQ(osAccountManagerService_->QueryOsAccountById(osAccountInfoOne.GetLocalId(), osAccountInfoTwo),
        ERR_OK);
    EXPECT_EQ(STRING_NAME, osAccountInfoTwo.GetLocalName());
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest034
 * @tc.desc: Test SetOsAccountName with invalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFF
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest034, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest034");
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne),
        ERR_OK);
    EXPECT_NE(osAccountManagerService_->SetOsAccountName(osAccountInfoOne.GetLocalId(), STRING_EMPTY), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest035
 * @tc.desc: Test SetOsAccountName with invalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFF
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest035, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest035");
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne),
        ERR_OK);
    EXPECT_NE(osAccountManagerService_->SetOsAccountName(
        osAccountInfoOne.GetLocalId(), STRING_NAME_OUT_OF_RANGE), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest036
 * @tc.desc: Test GetOsAccountLocalIdBySerialNumber with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFF
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest036, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest036");
    int id = 0;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountLocalIdBySerialNumber(
        Constants::CARRY_NUM * Constants::SERIAL_NUMBER_NUM_START_FOR_ADMIN + 1, id), ERR_OK);
    EXPECT_EQ(id, Constants::START_USER_ID);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest037
 * @tc.desc: Test GetOsAccountLocalIdBySerialNumber with invalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFF
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest037, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest037");
    int id = 0;
    EXPECT_NE(osAccountManagerService_->GetOsAccountLocalIdBySerialNumber(123, id), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest038
 * @tc.desc: Test GetSerialNumberByOsAccountLocalId with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFF
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest038, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest038");
    int64_t serialNumber;
    EXPECT_EQ(osAccountManagerService_->GetSerialNumberByOsAccountLocalId(
        Constants::START_USER_ID, serialNumber), ERR_OK);
    EXPECT_EQ(serialNumber, Constants::CARRY_NUM * Constants::SERIAL_NUMBER_NUM_START_FOR_ADMIN + 1);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest039
 * @tc.desc: Test GetSerialNumberByOsAccountLocalId with invalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFF
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest039, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest039");
    int64_t serialNumber;
    EXPECT_NE(osAccountManagerService_->GetSerialNumberByOsAccountLocalId(
        Constants::MAX_USER_ID + 1, serialNumber), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest040
 * @tc.desc: Test SetOsAccountProfilePhoto with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFI
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest040, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest040");
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->SetOsAccountProfilePhoto(osAccountInfoOne.GetLocalId(), PHOTO_IMG), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest041
 * @tc.desc: Test SetOsAccountProfilePhoto with invalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest041, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest041");
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne), ERR_OK);
    EXPECT_NE(osAccountManagerService_->SetOsAccountProfilePhoto(
        osAccountInfoOne.GetLocalId(), STRING_PHOTO_OUT_OF_RANGE), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest042
 * @tc.desc: Test SetOsAccountProfilePhoto with invalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFN
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest042, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest042");
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne), ERR_OK);
    EXPECT_NE(osAccountManagerService_->SetOsAccountProfilePhoto(
        osAccountInfoOne.GetLocalId(), PHOTO_IMG_ERROR), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest043
 * @tc.desc: Test GetOsAccountProfilePhoto with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFF
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest043, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest043");
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne), ERR_OK);
    ASSERT_EQ(osAccountManagerService_->SetOsAccountProfilePhoto(osAccountInfoOne.GetLocalId(), PHOTO_IMG), ERR_OK);
    std::string photo;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountProfilePhoto(osAccountInfoOne.GetLocalId(), photo), ERR_OK);
    EXPECT_EQ(photo, PHOTO_IMG);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest044
 * @tc.desc: Test GetOsAccountProfilePhoto with invalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFF
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest044, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest044");
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne), ERR_OK);
    std::string photo;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountProfilePhoto(osAccountInfoOne.GetLocalId(), photo), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest045
 * @tc.desc: Test GetOsAccountProfilePhoto with invalid id.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFF
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest045, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest045");
    std::string photo;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountProfilePhoto(Constants::MAX_USER_ID + 1, photo),
        ERR_OSACCOUNT_KIT_LOCAL_ID_INVALID_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest046
 * @tc.desc: Test StartOsAccount with valid id.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFJ
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest046, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest046");
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->StartOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->StopOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest047
 * @tc.desc: Test StartOsAccount with invalid id.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFJ
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest047, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest047");
    EXPECT_EQ(osAccountManagerService_->StartOsAccount(Constants::MAX_USER_ID + 1),
        ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest048
 * @tc.desc: Test StartOsAccount with started id.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFJ
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest048, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest048");
    EXPECT_EQ(osAccountManagerService_->StartOsAccount(Constants::START_USER_ID),
        ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest049
 * @tc.desc: Test StopOsAccount with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFJ
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest049, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest049");
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->StartOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->StopOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest050
 * @tc.desc: Test StopOsAccount with invalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFJ
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest050, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest050");
    EXPECT_EQ(osAccountManagerService_->StopOsAccount(Constants::MAX_USER_ID + 1),
        ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest051
 * @tc.desc: Test ActivateOsAccount with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFJ
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest051, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest051");
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->ActivateOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_OPERATION));
    std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_OPERATION));
    EXPECT_EQ(osAccountManagerService_->ActivateOsAccount(Constants::START_USER_ID), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest052
 * @tc.desc: Test IsOsAccountCompleted with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFJ
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest052, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest052");
    bool isOsAccountCompleted = false;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountCompleted(
        Constants::START_USER_ID, isOsAccountCompleted), ERR_OK);
    EXPECT_EQ(isOsAccountCompleted, true);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest053
 * @tc.desc: Test IsOsAccountCompleted with invalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest053, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest053");
    bool isOsAccountCompleted = false;
    EXPECT_NE(osAccountManagerService_->IsOsAccountCompleted(
        Constants::MAX_USER_ID + 1, isOsAccountCompleted), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest054
 * @tc.desc: Test SetOsAccountIsVerified with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFF
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest054, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest054");
    bool isVerified = true;
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->SetOsAccountIsVerified(osAccountInfoOne.GetLocalId(), isVerified), ERR_OK);
    OsAccountInfo osAccountInfoTwo;
    EXPECT_EQ(osAccountManagerService_->QueryOsAccountById(osAccountInfoOne.GetLocalId(), osAccountInfoTwo), ERR_OK);
    EXPECT_EQ(isVerified, osAccountInfoTwo.GetIsVerified());
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest055
 * @tc.desc: Test SetOsAccountIsVerified with invalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFG
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest055, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest055");
    bool isVerified = true;
    EXPECT_NE(osAccountManagerService_->SetOsAccountIsVerified(Constants::MAX_USER_ID + 1, isVerified), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest056
 * @tc.desc: Test SetCurrentOsAccountIsVerified with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFI
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest056, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest056");
    bool isVerified = true;
    EXPECT_NE(osAccountManagerService_->SetCurrentOsAccountIsVerified(isVerified), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest057
 * @tc.desc: create an os account by domain, and remove it
 * @tc.type: FUNC
 * @tc.require: SR000GGVFL
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest057, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest057");
    OsAccountType type = NORMAL;
    DomainAccountInfo domainInfo(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    OsAccountInfo osAccountInfo;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccountForDomain(type, domainInfo, osAccountInfo), ERR_OK);

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

    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(resOsAccountInfo.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest058
 * @tc.desc: create an os account by domain, and activate it
 * @tc.type: FUNC
 * @tc.require: SR000GGVFL
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest058, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest058");
    // create
    DomainAccountInfo domainInfo(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    OsAccountType type = NORMAL;
    OsAccountInfo osAccountInfo;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccountForDomain(type, domainInfo, osAccountInfo), ERR_OK);

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
    EXPECT_EQ(osAccountManagerService_->ActivateOsAccount(osAccountInfo.GetLocalId()), ERR_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_OPERATION));

    // check
    OsAccountInfo queryAccountInfo;
    EXPECT_EQ(osAccountManagerService_->QueryOsAccountById(osAccountInfo.GetLocalId(), queryAccountInfo), ERR_OK);
    EXPECT_EQ(queryAccountInfo.GetLocalId(), osAccountInfo.GetLocalId());
    EXPECT_EQ(queryAccountInfo.GetIsActived(), true);
    checkValid = (queryAccountInfo.GetLocalName() == osAccountName);
    EXPECT_EQ(checkValid, true);

    // remove
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfo.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest059
 * @tc.desc: Create os account for domain use invalid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFL
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest059, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest059");
    DomainAccountInfo domainNameInvalid(STRING_DOMAIN_NAME_OUT_OF_RANGE, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    OsAccountType type = NORMAL;
    OsAccountInfo osAccountInfo;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccountForDomain(type, domainNameInvalid, osAccountInfo),
        ERR_OSACCOUNT_SERVICE_MANAGER_NAME_SIZE_OVERFLOW_ERROR);

    DomainAccountInfo domainAccountNameInvalid(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_OUT_OF_RANGE);
    EXPECT_EQ(osAccountManagerService_->CreateOsAccountForDomain(type, domainAccountNameInvalid, osAccountInfo),
        ERR_OSACCOUNT_SERVICE_MANAGER_NAME_SIZE_OVERFLOW_ERROR);

    DomainAccountInfo domainEmpty("", STRING_DOMAIN_ACCOUNT_NAME_VALID);
    EXPECT_EQ(osAccountManagerService_->CreateOsAccountForDomain(type, domainEmpty, osAccountInfo),
        ERR_OSACCOUNT_SERVICE_MANAGER_NAME_SIZE_EMPTY_ERROR);

    DomainAccountInfo domainAccountEmpty(STRING_DOMAIN_VALID, "");
    EXPECT_EQ(osAccountManagerService_->CreateOsAccountForDomain(type, domainAccountEmpty, osAccountInfo),
        ERR_OSACCOUNT_SERVICE_MANAGER_NAME_SIZE_EMPTY_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest060
 * @tc.desc: repeat create os account for domain by service
 * @tc.type: FUNC
 * @tc.require: SR000GGVFL
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest060, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest060");
    // create
    DomainAccountInfo domainInfo(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    OsAccountType type = NORMAL;
    OsAccountInfo osAccountInfo;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccountForDomain(type, domainInfo, osAccountInfo), ERR_OK);

    // create again
    EXPECT_EQ(osAccountManagerService_->CreateOsAccountForDomain(type, domainInfo, osAccountInfo),
        ERR_OSACCOUNT_SERVICE_INNER_DOMAIN_ALREADY_BIND_ERROR);

    // remove
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfo.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest061
 * @tc.desc: repeat create os account for domain after remove by service
 * @tc.type: FUNC
 * @tc.require: SR000GGVFL
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest061, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest061");
    // create
    DomainAccountInfo domainInfo(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    OsAccountType type = NORMAL;
    OsAccountInfo osAccountInfo;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccountForDomain(type, domainInfo, osAccountInfo), ERR_OK);

    // create again
    EXPECT_EQ(osAccountManagerService_->CreateOsAccountForDomain(type, domainInfo, osAccountInfo),
        ERR_OSACCOUNT_SERVICE_INNER_DOMAIN_ALREADY_BIND_ERROR);

    // remove
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfo.GetLocalId()), ERR_OK);

    // create again
    ASSERT_EQ(osAccountManagerService_->CreateOsAccountForDomain(type, domainInfo, osAccountInfo), ERR_OK);

    // remove
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfo.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest062
 * @tc.desc: query os account by domain info
 * @tc.type: FUNC
 * @tc.require: SR000GGVFL
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest062, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest062");
    // create
    DomainAccountInfo domainInfo(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    OsAccountType type = NORMAL;
    OsAccountInfo osAccountInfo;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccountForDomain(type, domainInfo, osAccountInfo), ERR_OK);

    // get os account local id by domain
    int resID = -1;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountLocalIdFromDomain(domainInfo, resID), ERR_OK);
    EXPECT_EQ(resID, osAccountInfo.GetLocalId());

    // remove
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfo.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest063
 * @tc.desc: query os account by domain info
 * @tc.type: FUNC
 * @tc.require: SR000GGVFL
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest063, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest063");
    // create
    DomainAccountInfo domainInfo(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    OsAccountType type = NORMAL;
    OsAccountInfo osAccountInfo;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccountForDomain(type, domainInfo, osAccountInfo), ERR_OK);

    // get os account local id by domain
    int resID = -1;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountLocalIdFromDomain(domainInfo, resID), ERR_OK);
    EXPECT_EQ(resID, osAccountInfo.GetLocalId());

    // remove
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfo.GetLocalId()), ERR_OK);

    // cannot query
    EXPECT_EQ(osAccountManagerService_->GetOsAccountLocalIdFromDomain(domainInfo, resID),
        ERR_OSACCOUNT_KIT_GET_OS_ACCOUNT_LOCAL_ID_FOR_DOMAIN_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest064
 * @tc.desc: query os account by domain info
 * @tc.type: FUNC
 * @tc.require: SR000GGVFL
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest064, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest064");
    DomainAccountInfo domainAllEmpty("", "");
    int resLocalId = -1;
    ErrCode ret = osAccountManagerService_->GetOsAccountLocalIdFromDomain(domainAllEmpty, resLocalId);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_DOMAIN_NAME_LEN_ERROR);

    DomainAccountInfo domainNameEmpty("", STRING_DOMAIN_ACCOUNT_NAME_VALID);
    ret = osAccountManagerService_->GetOsAccountLocalIdFromDomain(domainNameEmpty, resLocalId);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_DOMAIN_NAME_LEN_ERROR);

    DomainAccountInfo domainAccountEmpty(STRING_DOMAIN_VALID, "");
    ret = osAccountManagerService_->GetOsAccountLocalIdFromDomain(domainAccountEmpty, resLocalId);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_DOMAIN_ACCOUNT_NAME_LEN_ERROR);

    DomainAccountInfo domainAllTooLong(STRING_DOMAIN_NAME_OUT_OF_RANGE, STRING_DOMAIN_ACCOUNT_NAME_OUT_OF_RANGE);
    ret = osAccountManagerService_->GetOsAccountLocalIdFromDomain(domainAllTooLong, resLocalId);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_DOMAIN_NAME_LEN_ERROR);

    DomainAccountInfo domainNameTooLong(STRING_DOMAIN_NAME_OUT_OF_RANGE, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    ret = osAccountManagerService_->GetOsAccountLocalIdFromDomain(domainNameTooLong, resLocalId);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_DOMAIN_NAME_LEN_ERROR);

    DomainAccountInfo domainAccountTooLong(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_OUT_OF_RANGE);
    ret = osAccountManagerService_->GetOsAccountLocalIdFromDomain(domainAccountTooLong, resLocalId);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_DOMAIN_ACCOUNT_NAME_LEN_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest067
 * @tc.desc: Test query active os account ids.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFQ
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest067, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest067");
    std::vector<int32_t> ids;
    EXPECT_EQ(osAccountManagerService_->QueryActiveOsAccountIds(ids), ERR_OK);
    for (auto it = ids.begin(); it != ids.end(); it++) {
        GTEST_LOG_(INFO) << *it;
    }
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest068
 * @tc.desc: Test IsMainOsAccount.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFF
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest068, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest068");
    bool isMainOsAccount = false;
    EXPECT_EQ(osAccountManagerService_->IsMainOsAccount(isMainOsAccount), ERR_OK);
    int id = -1;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountLocalIdFromProcess(id), ERR_OK);
    if (id == MAIN_ACCOUNT_ID) {
        EXPECT_EQ(isMainOsAccount, true);
    } else {
        EXPECT_EQ(isMainOsAccount, false);
    }
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest069
 * @tc.desc: Test GetCreatedOsAccountNumFromDatabase with empty storeID.
 * @tc.type: FUNC
 * @tc.require: issueI4M8FW
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest069, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest069");
    std::string storeID = "";
    int createdOsAccountNum = -1;
    ErrCode ret = osAccountManagerService_->GetCreatedOsAccountNumFromDatabase(storeID, createdOsAccountNum);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(createdOsAccountNum, -1);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest070
 * @tc.desc: Test GetCreatedOsAccountNumFromDatabase with invalid storeID.
 * @tc.type: FUNC
 * @tc.require: issueI4M8FW
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest070, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest070");
    std::string storeID = "testStoreID";
    int createdOsAccountNum = -1;
    ErrCode ret = osAccountManagerService_->GetCreatedOsAccountNumFromDatabase(storeID, createdOsAccountNum);
    EXPECT_NE(ret, ERR_OK);
    EXPECT_EQ(createdOsAccountNum, -1);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest071
 * @tc.desc: Test DumpState with two accounts.
 * @tc.type: FUNC
 * @tc.require: issueI4M8FW
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest071, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest071");
    std::vector<OsAccountInfo> osAccountInfos;
    EXPECT_EQ(osAccountManagerService_->QueryAllCreatedOsAccounts(osAccountInfos), ERR_OK);
    std::vector<std::string> state;
    ASSERT_EQ(osAccountManagerService_->DumpOsAccountInfo(state), ERR_OK);
    int cnt = 0;
    for (auto const &curString : state) {
        if (curString == "\n") {
            ++cnt;
        }
    }
    EXPECT_EQ(cnt, osAccountInfos.size());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest072
 * @tc.desc: Test QueryOsAccountConstraintSourceTypes normal case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest072, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest072");
    std::vector<ConstraintSourceTypeInfo> constraintSourceTypeInfos;
    EXPECT_EQ(osAccountManagerService_->QueryOsAccountConstraintSourceTypes(
        MAIN_ACCOUNT_ID, CONSTANT_WIFI, constraintSourceTypeInfos), ERR_OK);
    EXPECT_NE(constraintSourceTypeInfos.size(), 0);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest073
 * @tc.desc: Test DumpState normal case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest073, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest073");
    std::vector<std::string> state;
    // id is -1, refers to query all accounts info
    EXPECT_EQ(osAccountManagerService_->DumpState(-1, state), ERR_OK);
    EXPECT_NE(state.size(), 0);

    EXPECT_EQ(osAccountManagerService_->DumpState(MAIN_ACCOUNT_ID, state), ERR_OK);
    EXPECT_NE(state.size(), 0);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest074
 * @tc.desc: Test DumpState with invalid local id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest074, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest074");
    std::vector<std::string> state;
    
    EXPECT_NE(osAccountManagerService_->DumpState(INVALID_ACCOUNT_ID, state), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest075
 * @tc.desc: Test GetSerialNumberFromDatabase with invalid store id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest075, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest075");
    std::string storeID = "testStoreID";
    int64_t serialNumber = -1;
    EXPECT_NE(osAccountManagerService_->GetSerialNumberFromDatabase(storeID, serialNumber), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest076
 * @tc.desc: Test GetSerialNumberFromDatabase normal case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest076, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest076");
    std::string storeID = "";
    int64_t serialNumber = -1;
    EXPECT_EQ(osAccountManagerService_->GetSerialNumberFromDatabase(storeID, serialNumber), ERR_OK);
    EXPECT_NE(serialNumber, -1);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest077
 * @tc.desc: Test GetMaxAllowCreateIdFromDatabase with invalid store id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest077, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest077");
    std::string storeID = "testStoreID";
    int id = -1;
    EXPECT_NE(osAccountManagerService_->GetMaxAllowCreateIdFromDatabase(storeID, id), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest078
 * @tc.desc: Test GetMaxAllowCreateIdFromDatabase normal case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest078, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest078");
    std::string storeID = "";
    int id = 0;
    EXPECT_EQ(osAccountManagerService_->GetMaxAllowCreateIdFromDatabase(storeID, id), ERR_OK);
    EXPECT_NE(id, 0);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest079
 * @tc.desc: Test GetOsAccountFromDatabase with invalid local id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest079, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest079");
    std::string storeID = "";
    int invalidLocalID = -1;
    OsAccountInfo osAccountInfo;
    EXPECT_NE(osAccountManagerService_->GetOsAccountFromDatabase(storeID, invalidLocalID, osAccountInfo), ERR_OK);
    invalidLocalID = 1100;
    EXPECT_NE(osAccountManagerService_->GetOsAccountFromDatabase(storeID, invalidLocalID, osAccountInfo), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest080
 * @tc.desc: Test GetOsAccountFromDatabase with invalid store id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest080, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest080");
    std::string storeID = "testStoreID";
    OsAccountInfo osAccountInfo;
    EXPECT_NE(osAccountManagerService_->GetOsAccountFromDatabase(storeID, MAIN_ACCOUNT_ID, osAccountInfo), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest081
 * @tc.desc: Test GetOsAccountFromDatabase normal case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest081, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest081");
    std::string storeID = "";
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountFromDatabase(storeID, MAIN_ACCOUNT_ID, osAccountInfo), ERR_OK);
    EXPECT_EQ(osAccountInfo.GetLocalId(), MAIN_ACCOUNT_ID);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest082
 * @tc.desc: Test GetOsAccountListFromDatabase normal case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest082, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest082");
    std::string storeID = "";
    std::vector<OsAccountInfo> osAccountList;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountListFromDatabase(storeID, osAccountList), ERR_OK);
    EXPECT_NE(osAccountList.size(), 0);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest083
 * @tc.desc: Test GetOsAccountListFromDatabase with invalid store id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest083, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest083");
    std::string storeID = "testStoreID";
    std::vector<OsAccountInfo> osAccountList;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountListFromDatabase(storeID, osAccountList), ERR_OK);
    EXPECT_EQ(osAccountList.size(), 0);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest084
 * @tc.desc: Test SetGlobalOsAccountConstraints normal case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest084, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest084");

    bool isConstraintEnable = false;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountConstraintEnable(
        MAIN_ACCOUNT_ID, CONSTANT_PRINT, isConstraintEnable), ERR_OK);
    EXPECT_EQ(isConstraintEnable, false);
    EXPECT_EQ(osAccountManagerService_->SetGlobalOsAccountConstraints(
        CONSTANTS_VECTOR, true, MAIN_ACCOUNT_ID, true), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->IsOsAccountConstraintEnable(
        MAIN_ACCOUNT_ID, CONSTANT_PRINT, isConstraintEnable), ERR_OK);
    EXPECT_EQ(isConstraintEnable, true);
    EXPECT_EQ(osAccountManagerService_->SetGlobalOsAccountConstraints(
        CONSTANTS_VECTOR, false, MAIN_ACCOUNT_ID, true), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->IsOsAccountConstraintEnable(
        MAIN_ACCOUNT_ID, CONSTANT_PRINT, isConstraintEnable), ERR_OK);
    EXPECT_EQ(isConstraintEnable, false);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest085
 * @tc.desc: Test SetGlobalOsAccountConstraints exception case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest085, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest073");
    bool isConstraintEnable = false;
    // test invalid id
    EXPECT_NE(osAccountManagerService_->IsOsAccountConstraintEnable(
        INVALID_ACCOUNT_ID, CONSTANT_WIFI, isConstraintEnable), ERR_OK);
    // set exit constraints
    EXPECT_EQ(osAccountManagerService_->SetGlobalOsAccountConstraints(
        CONSTANTS_VECTOR_TEST, true, MAIN_ACCOUNT_ID, true), ERR_OK);
    // test invalid enforcer id
    EXPECT_NE(osAccountManagerService_->SetGlobalOsAccountConstraints(
        CONSTANTS_VECTOR, true, INVALID_ACCOUNT_ID, true), ERR_OK);
    // remove not exit constraints
    EXPECT_EQ(osAccountManagerService_->SetGlobalOsAccountConstraints(
        CONSTANTS_VECTOR, false, MAIN_ACCOUNT_ID, true), ERR_OK);
    // add invalid constraints
    EXPECT_NE(osAccountManagerService_->SetGlobalOsAccountConstraints(
        INVALID_CONSTRAINT, true, MAIN_ACCOUNT_ID, true), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest086
 * @tc.desc: Test SetSpecificOsAccountConstraints normal case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest086, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest073");
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfo);
    EXPECT_EQ(errCode, ERR_OK);
    bool isConstraintEnable = false;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountConstraintEnable(
        MAIN_ACCOUNT_ID, CONSTANT_PRINT, isConstraintEnable), ERR_OK);
    EXPECT_EQ(isConstraintEnable, false);
    EXPECT_EQ(osAccountManagerService_->SetSpecificOsAccountConstraints(
        CONSTANTS_VECTOR, true, osAccountInfo.GetLocalId(), MAIN_ACCOUNT_ID, false), ERR_OK);

    EXPECT_EQ(osAccountManagerService_->IsOsAccountConstraintEnable(
        osAccountInfo.GetLocalId(), CONSTANT_PRINT, isConstraintEnable), ERR_OK);
    EXPECT_EQ(isConstraintEnable, true);

    EXPECT_EQ(osAccountManagerService_->SetSpecificOsAccountConstraints(
        CONSTANTS_VECTOR, false, osAccountInfo.GetLocalId(), MAIN_ACCOUNT_ID, false), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->IsOsAccountConstraintEnable(
        MAIN_ACCOUNT_ID, CONSTANT_PRINT, isConstraintEnable), ERR_OK);
    EXPECT_EQ(isConstraintEnable, false);

    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfo.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest087
 * @tc.desc: Test SetSpecificOsAccountConstraints exception case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest087, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountManagerServiceModuleTest087");
    // test invalid target id
    EXPECT_NE(osAccountManagerService_->SetSpecificOsAccountConstraints(
        CONSTANTS_VECTOR, true, INVALID_ACCOUNT_ID, MAIN_ACCOUNT_ID, false), ERR_OK);
    // test invalid enforcer id
    EXPECT_NE(osAccountManagerService_->SetSpecificOsAccountConstraints(
        CONSTANTS_VECTOR, true, MAIN_ACCOUNT_ID, INVALID_ACCOUNT_ID, false), ERR_OK);
    // set exit constraints
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfo);
    EXPECT_EQ(errCode, ERR_OK);
    EXPECT_EQ(osAccountManagerService_->SetSpecificOsAccountConstraints(
        CONSTANTS_VECTOR_TEST, true, MAIN_ACCOUNT_ID, osAccountInfo.GetLocalId(), true), ERR_OK);
    // add invalid constraints
    EXPECT_NE(osAccountManagerService_->SetSpecificOsAccountConstraints(
        INVALID_CONSTRAINT, true, MAIN_ACCOUNT_ID, osAccountInfo.GetLocalId(), false), ERR_OK);
    // remove not exit constraints
    EXPECT_EQ(osAccountManagerService_->SetSpecificOsAccountConstraints(
        CONSTANTS_VECTOR, false, osAccountInfo.GetLocalId(), MAIN_ACCOUNT_ID, false), ERR_OK);

    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfo.GetLocalId()), ERR_OK);
}
}  // namespace AccountSA
}  // namespace OHOS
