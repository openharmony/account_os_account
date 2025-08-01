/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
#include <filesystem>
#include <gtest/gtest.h>
#include <thread>
#include <unistd.h>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_test_common.h"
#include "os_account_constants.h"
#include "accesstoken_kit.h"
#include "token_setproc.h"
#include "ipc_skeleton.h"
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
using namespace OHOS::AccountSA::Constants;
using namespace OHOS::Security::AccessToken;

namespace {
const std::string STRING_EMPTY = "";
const std::string STRING_NAME = "name";
const std::string STRING_TEST_NAME = "test";
const std::string STORE_ID = "testStoreID";
const std::string EMPTY_STORE_ID = "";
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
const OsAccountType INT_TEST_TYPE = OsAccountType::GUEST;
const gid_t ACCOUNT_GID = 3058;
const int32_t NATIVE_TOKEN = 1;
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS
const std::int32_t ROOT_UID = 0;
const std::int32_t TEST_UID = 1;

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
const std::string STRING_NAME_OUT_OF_RANGE(1200, '1');  // length 1200
const std::string STRING_CONSTRAINT_OUT_OF_RANGE(300, '1');  // length 300
const std::string STRING_PHOTO_OUT_OF_RANGE(1024 * 1024 + 1, '1');  // length 1024*1024*10+1
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
const std::string CONFIG_JSON_NORMAL = "{\"maxOsAccountNum\": 5, \"maxLoggedInOsAccountNum\": 3}";
const std::string CONFIG_JSON_LAGER_LOGGED_IN_NUM = "{\"maxOsAccountNum\": 5, \"maxLoggedInOsAccountNum\": 9}";
const std::string CONFIG_JSON_INVALID_KEY_OR_VALUE = "{\"version\": 1, \"maxLoggedInOsAccountNum\": -1}";
const std::string CONFIG_JSON_INVALID_FORMAT = "maxOsAccountNum=5, maxLoggedInOsAccountNum=3";
const std::string CONFIG_PATH = "/data/service/el1/public/account/test/os_account_config.json";
const std::string STRING_DOMAIN_NAME_OUT_OF_RANGE(200, '1');  // length 200
const std::string STRING_DOMAIN_ACCOUNT_NAME_OUT_OF_RANGE(600, '1');  // length 600
const std::string STRING_DOMAIN_VALID = "TestDomainMT";
const std::string STRING_DOMAIN_ACCOUNT_NAME_VALID = "TestDomainAccountNameMT";
const std::int32_t MAIN_ACCOUNT_ID = 100;
const std::int32_t INVALID_ACCOUNT_ID = 200;
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
const std::uint32_t MAX_OS_ACCOUNT_NUM = 5;
const std::uint32_t MAX_LOGGED_IN_OS_ACCOUNT_NUM = 3;
const std::uint32_t DEFAULT_MAX_OS_ACCOUNT_NUM = 999;
const std::uint32_t DEFAULT_MAX_LOGGED_IN_OS_ACCOUNT_NUM = 999;
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS
#ifdef ENABLE_FILE_WATCHER
const std::shared_ptr<AccountFileOperator> g_accountFileOperator =
    AccountFileWatcherMgr::GetInstance().accountFileOperator_;
#else
const std::shared_ptr<AccountFileOperator> g_accountFileOperator = std::make_shared<AccountFileOperator>();
#endif // ENABLE_FILE_WATCHER
}  // namespace

class OsAccountManagerServiceModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::shared_ptr<OsAccountManagerService>
        osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
};

void OsAccountManagerServiceModuleTest::SetUpTestCase(void)
{
    ASSERT_NE(GetAllAccountPermission(), 0);
#ifdef ACCOUNT_TEST
    AccountFileOperator osAccountFileOperator;
    osAccountFileOperator.DeleteDirOrFile(USER_INFO_BASE);
    GTEST_LOG_(INFO) << "delete account test path " << USER_INFO_BASE;
#endif  // ACCOUNT_TEST
    ASSERT_NE(g_accountFileOperator, nullptr);
    IInnerOsAccountManager::GetInstance().Init();
    IInnerOsAccountManager::GetInstance().ActivateDefaultOsAccount();
}

void OsAccountManagerServiceModuleTest::TearDownTestCase(void)
{
#ifdef ACCOUNT_TEST
    AccountFileOperator osAccountFileOperator;
    osAccountFileOperator.DeleteDirOrFile(USER_INFO_BASE);
    GTEST_LOG_(INFO) << "delete account test path " << USER_INFO_BASE;
#endif  // ACCOUNT_TEST
}

void OsAccountManagerServiceModuleTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());

    setuid(ROOT_UID);
}

void OsAccountManagerServiceModuleTest::TearDown(void)
{
    setuid(ROOT_UID);
}


/**
 * @tc.name: InnerOsAccountManagerTest001
 * @tc.desc: coverage ValidateShortName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, InnerOsAccountManagerTest001, TestSize.Level1)
{
    ErrCode ret = osAccountManagerService_->ValidateShortName("sdfgse*");
    EXPECT_NE(ret, ERR_OK);
    ret = osAccountManagerService_->ValidateShortName("..");
    EXPECT_NE(ret, ERR_OK);
    ret = osAccountManagerService_->ValidateShortName("");
    EXPECT_NE(ret, ERR_OK);
    ret = osAccountManagerService_->ValidateShortName("asdfgtr");
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest001
 * @tc.desc: Test CreateOsAccount with valid data.
 * @tc.type: FUNC
 * @tc.require:
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest001, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    ErrCode errCode = osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_EQ(errCode, ERR_OK);
    OsAccountInfo osAccountInfoTwo;
    errCode = osAccountManagerService_->QueryOsAccountById(osAccountInfoOne.GetLocalId(), osAccountInfoTwo);
    EXPECT_EQ(errCode, ERR_OK);
    DomainAccountInfo domainInfo;
    osAccountInfoTwo.GetDomainInfo(domainInfo);
    domainInfo.status_ = DomainAccountStatus::LOG_END;
    osAccountInfoTwo.SetDomainInfo(domainInfo);
    EXPECT_EQ(osAccountInfoOne.ToString(), osAccountInfoTwo.ToString());
    errCode = osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId());
    EXPECT_EQ(errCode, ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest002
 * @tc.desc: Test CreateOsAccount with invalid name.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest002, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    ErrCode errCode =
        osAccountManagerService_->CreateOsAccount(STRING_NAME_OUT_OF_RANGE, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest003
 * @tc.desc: Test CreateOsAccount with invalid name.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest003, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    ErrCode errCode = osAccountManagerService_->CreateOsAccount(STRING_EMPTY, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: OsAccountManagerServiceModuleTest004
 * @tc.desc: Test IsCurrentOsAccountVerified with invalid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest004, TestSize.Level1)
{
    bool isVerify = false;
    ErrCode errCode = osAccountManagerService_->IsCurrentOsAccountVerified(isVerify);
    EXPECT_EQ(errCode, ERR_OK);
}

#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest005, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    ErrCode errCode = osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, OsAccountType::ADMIN,
        osAccountInfoOne);
    EXPECT_EQ(errCode, ERR_OK);
    errCode = osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId());
    EXPECT_EQ(errCode, ERR_OK);
    errCode = osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, OsAccountType::END,
        osAccountInfoOne);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest006
 * @tc.desc: Test active os account can be remove.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest006, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->ActivateOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest007
 * @tc.desc: Test CreateOsAccount when cannot find account_list.json.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest007, TestSize.Level1)
{
    // save file content to fileContext first
    std::string fileContext;
    g_accountFileOperator->GetFileContentByPath(Constants::ACCOUNT_LIST_FILE_JSON_PATH, fileContext);

    // remove file
    g_accountFileOperator->DeleteDirOrFile(Constants::ACCOUNT_LIST_FILE_JSON_PATH);
    OsAccountInfo osAccountInfoOne;
    ErrCode errCode = osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne);
    EXPECT_NE(errCode, ERR_OK);
    osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId());

    // restore file content
    g_accountFileOperator->InputFileByPathAndContent(Constants::ACCOUNT_LIST_FILE_JSON_PATH, fileContext);

    // recover permission
    if (chmod(Constants::ACCOUNT_LIST_FILE_JSON_PATH.c_str(), S_IRUSR | S_IWUSR) != 0) {
        ACCOUNT_LOGE("OsAccountManagerServiceModuleTest007, chmod failed! errno %{public}d.", errno);
    }
    if (chown(Constants::ACCOUNT_LIST_FILE_JSON_PATH.c_str(), ACCOUNT_GID, ACCOUNT_GID) != 0) {
        ACCOUNT_LOGE("OsAccountManagerServiceModuleTest007, chown failed! errno %{public}d.", errno);
    }
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest008
 * @tc.desc: Test RemoveOsAccount with valid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest008, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    EXPECT_EQ(g_accountFileOperator->IsExistDir(
        Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + osAccountInfoOne.GetPrimeKey()), false);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: OsAccountManagerServiceModuleTest009
 * @tc.desc: Test RemoveOsAccount with cannot remove id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest009, TestSize.Level1)
{
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(Constants::START_USER_ID),
        ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest010
 * @tc.desc: Test RemoveOsAccount with does not exists id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest010, TestSize.Level1)
{
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(Constants::MAX_USER_ID + 1),
        ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest011
 * @tc.desc: Test IsOsAccountExists with valid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest011, TestSize.Level1)
{
    bool isOsAccountExists = false;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountExists(Constants::START_USER_ID, isOsAccountExists), ERR_OK);
    EXPECT_EQ(isOsAccountExists, true);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest012
 * @tc.desc: Test IsOsAccountExists with not exists data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest012, TestSize.Level1)
{
    bool isOsAccountExists = true;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountExists(Constants::MAX_USER_ID + 1, isOsAccountExists), ERR_OK);
    EXPECT_EQ(isOsAccountExists, false);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest013
 * @tc.desc: Test IsOsAccountActived with valid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest013, TestSize.Level1)
{
    bool isOsAccountActive = false;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountActived(Constants::START_USER_ID, isOsAccountActive), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest014
 * @tc.desc: Test IsOsAccountActived with not active account id.
 * @tc.type: FUNC
 * @tc.require:
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest014, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfoOne),
        ERR_OK);
    bool isOsAccountActived = true;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountActived(osAccountInfoOne.GetLocalId(), isOsAccountActived),
        ERR_OK);
    EXPECT_EQ(isOsAccountActived, false);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);

    int localId = Constants::MAX_USER_ID + 1;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountActived(localId, isOsAccountActived),
        ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest015
 * @tc.desc: Test SetOsAccountConstraints with valid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest015, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount("Test015", INT_TEST_TYPE, osAccountInfoOne),
        ERR_OK);
    bool enable = false;
    EXPECT_EQ(osAccountManagerService_->SetOsAccountConstraints(
        osAccountInfoOne.GetLocalId(), CONSTANTS_VECTOR, enable), ERR_OK);
    std::vector<std::string> testSet = {"test"};
    EXPECT_EQ(osAccountManagerService_->SetOsAccountConstraints(
        osAccountInfoOne.GetLocalId(), testSet, enable), ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest016
 * @tc.desc: Test SetOsAccountConstraints with valid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest016, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount("Test016", INT_TEST_TYPE, osAccountInfoOne), ERR_OK);
    bool enable = true;
    EXPECT_EQ(osAccountManagerService_->SetOsAccountConstraints(
        osAccountInfoOne.GetLocalId(), CONSTANTS_VECTOR, enable), ERR_OK);
    OsAccountInfo osAccountInfoTwo;
    EXPECT_EQ(osAccountManagerService_->QueryOsAccountById(osAccountInfoOne.GetLocalId(), osAccountInfoTwo),
        ERR_OK);
    std::vector<std::string> constraints = osAccountInfoTwo.GetConstraints();
    EXPECT_TRUE(constraints.size() > CONSTANTS_VECTOR.size());
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);

    int localId = Constants::START_USER_ID - 1;
    EXPECT_EQ(osAccountManagerService_->SetOsAccountConstraints(localId, CONSTANTS_VECTOR, enable),
        ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest017
 * @tc.desc: Test IsOsAccountConstraintEnable with valid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest017, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount("Test017", INT_TEST_TYPE, osAccountInfoOne), ERR_OK);
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
 * @tc.desc: Test IsOsAccountConstraintEnable/CheckOsAccountConstraintEnabled with valid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest018, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount("Test018", INT_TEST_TYPE, osAccountInfoOne), ERR_OK);
    bool isEnable = true;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountConstraintEnable(
        osAccountInfoOne.GetLocalId(), CONSTANTS_STRING_WIFI, isEnable), ERR_OK);
    EXPECT_EQ(isEnable, false);
    EXPECT_EQ(osAccountManagerService_->CheckOsAccountConstraintEnabled(
        osAccountInfoOne.GetLocalId(), CONSTANTS_STRING_WIFI, isEnable), ERR_OK);
    EXPECT_EQ(isEnable, false);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);

    int localId = Constants::START_USER_ID - 1;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountConstraintEnable(localId, CONSTANTS_STRING_WIFI, isEnable),
        ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
    EXPECT_EQ(osAccountManagerService_->CheckOsAccountConstraintEnabled(localId, CONSTANTS_STRING_WIFI, isEnable),
        ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: OsAccountManagerServiceModuleTest019
 * @tc.desc: Test IsMultiOsAccountEnable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest019, TestSize.Level1)
{
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
    bool isMultiOsAccountEnable = false;
#else
    bool isMultiOsAccountEnable = true;
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS
    EXPECT_EQ(osAccountManagerService_->IsMultiOsAccountEnable(isMultiOsAccountEnable), ERR_OK);
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
    EXPECT_EQ(isMultiOsAccountEnable, true);
#else
    EXPECT_EQ(isMultiOsAccountEnable, false);
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest020
 * @tc.desc: Test IsOsAccountVerified with not verified os account id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest020, TestSize.Level1)
{
    bool isVerified = false;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountVerified(Constants::START_USER_ID, isVerified), ERR_OK);
    EXPECT_EQ(isVerified, true);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest021
 * @tc.desc: Test IsOsAccountVerified with does not exists os account id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest021, TestSize.Level1)
{
    bool isVerified = true;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountVerified(Constants::MAX_USER_ID + 1, isVerified),
        ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest022
 * @tc.desc: Test IsOsAccountVerified with does not exists os account id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest022, TestSize.Level1)
{
    bool isVerified = true;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountVerified(Constants::MAX_USER_ID + 1, isVerified),
        ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest023
 * @tc.desc: Test GetCreatedOsAccountsCount.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest023, TestSize.Level1)
{
    unsigned int osAccountsCount = 0;
    EXPECT_EQ(osAccountManagerService_->GetCreatedOsAccountsCount(osAccountsCount), ERR_OK);
    bool checkExpected = (osAccountsCount > 0);
    EXPECT_EQ(checkExpected, true);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest024
 * @tc.desc: Test GetOsAccountLocalIdFromProcess.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest024, TestSize.Level1)
{
    int id = -1;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountLocalIdFromProcess(id), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest025
 * @tc.desc: Test QueryMaxOsAccountNumber.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest025, TestSize.Level1)
{
    uint32_t maxOsAccountNumber = 0;
    EXPECT_EQ(osAccountManagerService_->QueryMaxOsAccountNumber(maxOsAccountNumber), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest026
 * @tc.desc: Test GetOsAccountAllConstraints with exist os account id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest026, TestSize.Level1)
{
    std::vector<std::string> constraints;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountAllConstraints(Constants::START_USER_ID, constraints), ERR_OK);
    EXPECT_NE(0, constraints.size());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest027
 * @tc.desc: Test GetOsAccountAllConstraints with does not exist os account id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest027, TestSize.Level1)
{
    std::vector<std::string> constraints;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountAllConstraints(Constants::MAX_USER_ID + 1, constraints),
        ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest028
 * @tc.desc: Test QueryAllCreatedOsAccounts.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest028, TestSize.Level1)
{
    std::vector<OsAccountInfo> osAccountInfos;
    EXPECT_EQ(osAccountManagerService_->QueryAllCreatedOsAccounts(osAccountInfos), ERR_OK);
    const unsigned int size = 0;
    EXPECT_NE(size, osAccountInfos.size());
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest029
 * @tc.desc: Test QueryCurrentOsAccount.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest029, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(osAccountManagerService_->QueryCurrentOsAccount(osAccountInfo), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest030
 * @tc.desc: Test QueryOsAccountById with valid data.
 * @tc.type: FUNC
 * @tc.require:
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest030, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount("Test030", INT_TEST_TYPE, osAccountInfoOne),
        ERR_OK);
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(osAccountManagerService_->QueryOsAccountById(osAccountInfoOne.GetLocalId(), osAccountInfo), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: OsAccountManagerServiceModuleTest031
 * @tc.desc: Test QueryOsAccountById with invalid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest031, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(osAccountManagerService_->QueryOsAccountById(Constants::MAX_USER_ID + 1, osAccountInfo),
        ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest032
 * @tc.desc: Test GetOsAccountTypeFromProcess.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest032, TestSize.Level1)
{
    int32_t type;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountTypeFromProcess(type), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest033
 * @tc.desc: Test SetOsAccountName with valid data.
 * @tc.type: FUNC
 * @tc.require:
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest033, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount("Test033", INT_TEST_TYPE, osAccountInfoOne),
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
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest034, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount("Test034", INT_TEST_TYPE, osAccountInfoOne),
        ERR_OK);
    EXPECT_NE(osAccountManagerService_->SetOsAccountName(osAccountInfoOne.GetLocalId(), STRING_EMPTY), ERR_OK);

    EXPECT_EQ(osAccountManagerService_->SetOsAccountName(Constants::START_USER_ID, STRING_EMPTY),
        ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest035
 * @tc.desc: Test SetOsAccountName with invalid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest035, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount("Test035", INT_TEST_TYPE, osAccountInfoOne),
        ERR_OK);
    EXPECT_NE(osAccountManagerService_->SetOsAccountName(
        osAccountInfoOne.GetLocalId(), STRING_NAME_OUT_OF_RANGE), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: OsAccountManagerServiceModuleTest036
 * @tc.desc: Test GetOsAccountLocalIdBySerialNumber with valid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest036, TestSize.Level1)
{
    int id = 0;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountLocalIdBySerialNumber(
        Constants::CARRY_NUM * Constants::SERIAL_NUMBER_NUM_START_FOR_ADMIN + 1, id), ERR_OK);
    EXPECT_EQ(id, Constants::START_USER_ID);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest037
 * @tc.desc: Test GetOsAccountLocalIdBySerialNumber with invalid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest037, TestSize.Level1)
{
    int id = 0;
    EXPECT_NE(osAccountManagerService_->GetOsAccountLocalIdBySerialNumber(123, id), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest038
 * @tc.desc: Test GetSerialNumberByOsAccountLocalId with valid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest038, TestSize.Level1)
{
    int64_t serialNumber;
    EXPECT_EQ(osAccountManagerService_->GetSerialNumberByOsAccountLocalId(
        Constants::START_USER_ID, serialNumber), ERR_OK);
    EXPECT_EQ(serialNumber, Constants::CARRY_NUM * Constants::SERIAL_NUMBER_NUM_START_FOR_ADMIN + 1);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest039
 * @tc.desc: Test GetSerialNumberByOsAccountLocalId with invalid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest039, TestSize.Level1)
{
    int64_t serialNumber;
    EXPECT_NE(osAccountManagerService_->GetSerialNumberByOsAccountLocalId(
        Constants::MAX_USER_ID + 1, serialNumber), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest040
 * @tc.desc: Test SetOsAccountProfilePhoto with valid data.
 * @tc.type: FUNC
 * @tc.require:
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest040, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount("Test040", INT_TEST_TYPE, osAccountInfoOne), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->SetOsAccountProfilePhoto(osAccountInfoOne.GetLocalId(), PHOTO_IMG), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest041
 * @tc.desc: Test SetOsAccountProfilePhoto with invalid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest041, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount("Test041", INT_TEST_TYPE, osAccountInfoOne), ERR_OK);
    EXPECT_NE(osAccountManagerService_->SetOsAccountProfilePhoto(
        osAccountInfoOne.GetLocalId(), STRING_PHOTO_OUT_OF_RANGE), ERR_OK);

    EXPECT_EQ(osAccountManagerService_->SetOsAccountProfilePhoto(Constants::START_USER_ID, STRING_PHOTO_OUT_OF_RANGE),
        ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest042
 * @tc.desc: Test SetOsAccountProfilePhoto with invalid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest042, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount("Test042", INT_TEST_TYPE, osAccountInfoOne), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->SetOsAccountProfilePhoto(
        osAccountInfoOne.GetLocalId(), PHOTO_IMG_ERROR), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest043
 * @tc.desc: Test GetOsAccountProfilePhoto with valid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest043, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount("Test043", INT_TEST_TYPE, osAccountInfoOne), ERR_OK);
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
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest044, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount("Test044", INT_TEST_TYPE, osAccountInfoOne), ERR_OK);
    std::string photo;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountProfilePhoto(osAccountInfoOne.GetLocalId(), photo), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: OsAccountManagerServiceModuleTest045
 * @tc.desc: Test GetOsAccountProfilePhoto with invalid id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest045, TestSize.Level1)
{
    std::string photo;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountProfilePhoto(Constants::MAX_USER_ID + 1, photo),
        ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest046
 * @tc.desc: Test StartOsAccount with valid id.
 * @tc.type: FUNC
 * @tc.require:
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest046, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount("Test046", INT_TEST_TYPE, osAccountInfoOne), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->StartOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->DeactivateOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: OsAccountManagerServiceModuleTest047
 * @tc.desc: Test StartOsAccount with invalid id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest047, TestSize.Level1)
{
    EXPECT_EQ(osAccountManagerService_->StartOsAccount(Constants::MAX_USER_ID + 1),
        ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest048
 * @tc.desc: Test StartOsAccount with started id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest048, TestSize.Level1)
{
    EXPECT_EQ(osAccountManagerService_->StartOsAccount(Constants::START_USER_ID),
        ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest051
 * @tc.desc: Test ActivateOsAccount with valid data.
 * @tc.type: FUNC
 * @tc.require:
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest051, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount("Test051", INT_TEST_TYPE, osAccountInfoOne), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->ActivateOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->ActivateOsAccount(Constants::START_USER_ID), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);

    int localId = Constants::START_USER_ID - 1;
    EXPECT_EQ(osAccountManagerService_->ActivateOsAccount(localId), ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: OsAccountManagerServiceModuleTest052
 * @tc.desc: Test IsOsAccountCompleted with valid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest052, TestSize.Level1)
{
    bool isOsAccountCompleted = false;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountCompleted(
        Constants::START_USER_ID, isOsAccountCompleted), ERR_OK);
    EXPECT_EQ(isOsAccountCompleted, true);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest053
 * @tc.desc: Test IsOsAccountCompleted with invalid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest053, TestSize.Level1)
{
    bool isOsAccountCompleted = true;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountCompleted(
        Constants::MAX_USER_ID + 1, isOsAccountCompleted), ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
    EXPECT_TRUE(isOsAccountCompleted);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest054
 * @tc.desc: Test SetOsAccountIsVerified with valid data.
 * @tc.type: FUNC
 * @tc.require:
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest054, TestSize.Level1)
{
    bool isVerified = true;
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount("Test054", INT_TEST_TYPE, osAccountInfoOne), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->SetOsAccountIsVerified(osAccountInfoOne.GetLocalId(), isVerified), ERR_OK);
    OsAccountInfo osAccountInfoTwo;
    EXPECT_EQ(osAccountManagerService_->QueryOsAccountById(osAccountInfoOne.GetLocalId(), osAccountInfoTwo), ERR_OK);
    EXPECT_EQ(isVerified, osAccountInfoTwo.GetIsVerified());
    ErrCode ret = osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId());
    if (ret == ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_OPERATING_ERROR) {
        sleep(1);
        EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    } else {
        EXPECT_EQ(ret, ERR_OK);
    }
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: OsAccountManagerServiceModuleTest055
 * @tc.desc: Test SetOsAccountIsVerified with invalid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest055, TestSize.Level1)
{
    bool isVerified = true;
    EXPECT_NE(osAccountManagerService_->SetOsAccountIsVerified(Constants::MAX_USER_ID + 1, isVerified), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest056
 * @tc.desc: Test SetCurrentOsAccountIsVerified with valid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest056, TestSize.Level1)
{
    bool isVerified = true;
    EXPECT_EQ(
        osAccountManagerService_->SetCurrentOsAccountIsVerified(isVerified), ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest065
 * @tc.desc: Test query active os account ids.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest065, TestSize.Level1)
{
    std::vector<int32_t> ids;
    EXPECT_EQ(osAccountManagerService_->QueryActiveOsAccountIds(ids), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest066
 * @tc.desc: Test IsMainOsAccount.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest066, TestSize.Level1)
{
    bool isMainOsAccount = false;
    EXPECT_EQ(osAccountManagerService_->IsMainOsAccount(isMainOsAccount), ERR_OK);
    int id = -1;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountLocalIdFromProcess(id), ERR_OK);
    EXPECT_EQ(isMainOsAccount, id == MAIN_ACCOUNT_ID);
}

#if defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
/**
 * @tc.name: OsAccountManagerServiceModuleTest067
 * @tc.desc: Test GetCreatedOsAccountNumFromDatabase with empty storeID.
 * @tc.type: FUNC
 * @tc.require: issueI4M8FW
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest067, TestSize.Level1)
{
    int createdOsAccountNum = -1;
    ErrCode ret = osAccountManagerService_->GetCreatedOsAccountNumFromDatabase(EMPTY_STORE_ID, createdOsAccountNum);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(createdOsAccountNum, -1);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest068
 * @tc.desc: Test GetCreatedOsAccountNumFromDatabase with invalid storeID.
 * @tc.type: FUNC
 * @tc.require: issueI4M8FW
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest068, TestSize.Level1)
{
    int createdOsAccountNum = -1;
    ErrCode ret = osAccountManagerService_->GetCreatedOsAccountNumFromDatabase(STORE_ID, createdOsAccountNum);
    EXPECT_NE(ret, ERR_OK);
}
#endif // defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)

/**
 * @tc.name: OsAccountManagerServiceModuleTest069
 * @tc.desc: Test DumpState with two accounts.
 * @tc.type: FUNC
 * @tc.require: issueI4M8FW
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest069, TestSize.Level1)
{
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
 * @tc.name: OsAccountManagerServiceModuleTest070
 * @tc.desc: Test QueryOsAccountConstraintSourceTypes normal case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest070, TestSize.Level1)
{
    std::vector<ConstraintSourceTypeInfo> constraintSourceTypeInfos;
    EXPECT_EQ(osAccountManagerService_->QueryOsAccountConstraintSourceTypes(
        MAIN_ACCOUNT_ID, CONSTANT_WIFI, constraintSourceTypeInfos), ERR_OK);
    EXPECT_NE(constraintSourceTypeInfos.size(), 0);

    EXPECT_EQ(osAccountManagerService_->QueryOsAccountConstraintSourceTypes(MAIN_ACCOUNT_ID, STRING_EMPTY,
        constraintSourceTypeInfos), ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    EXPECT_EQ(osAccountManagerService_->QueryOsAccountConstraintSourceTypes(MAIN_ACCOUNT_ID,
        STRING_CONSTRAINT_OUT_OF_RANGE, constraintSourceTypeInfos),
        ERR_ACCOUNT_COMMON_INVALID_PARAMETER);

    int localId = Constants::START_USER_ID - 1;
    EXPECT_EQ(osAccountManagerService_->QueryOsAccountConstraintSourceTypes(localId, CONSTANT_WIFI,
        constraintSourceTypeInfos), ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest071
 * @tc.desc: Test DumpState normal case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest071, TestSize.Level1)
{
    std::vector<std::string> state;
    // id is -1, refers to query all accounts info
    EXPECT_EQ(osAccountManagerService_->DumpState(-1, state), ERR_OK);
    EXPECT_NE(state.size(), 0);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest072
 * @tc.desc: Test DumpState with invalid local id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest072, TestSize.Level1)
{
    std::vector<std::string> state;

    EXPECT_NE(osAccountManagerService_->DumpState(INVALID_ACCOUNT_ID, state), ERR_OK);
}

#if defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
/**
 * @tc.name: OsAccountManagerServiceModuleTest073
 * @tc.desc: Test GetSerialNumberFromDatabase with invalid store id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest073, TestSize.Level1)
{
    int64_t serialNumber = -1;
    EXPECT_NE(osAccountManagerService_->GetSerialNumberFromDatabase(STORE_ID, serialNumber), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest074
 * @tc.desc: Test GetSerialNumberFromDatabase normal case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest074, TestSize.Level1)
{
    int64_t serialNumber = -1;
    EXPECT_EQ(osAccountManagerService_->GetSerialNumberFromDatabase(EMPTY_STORE_ID, serialNumber), ERR_OK);
    EXPECT_NE(serialNumber, -1);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest075
 * @tc.desc: Test GetMaxAllowCreateIdFromDatabase with invalid store id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest075, TestSize.Level1)
{
    int id = -1;
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
    EXPECT_NE(osAccountManagerService_->GetMaxAllowCreateIdFromDatabase(STORE_ID, id), ERR_OK);
#else
    EXPECT_EQ(osAccountManagerService_->GetMaxAllowCreateIdFromDatabase(STORE_ID, id), ERR_OK);
    EXPECT_NE(id, -1);
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest076
 * @tc.desc: Test GetMaxAllowCreateIdFromDatabase normal case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest076, TestSize.Level1)
{
    int id = 0;
    EXPECT_EQ(osAccountManagerService_->GetMaxAllowCreateIdFromDatabase(EMPTY_STORE_ID, id), ERR_OK);
    EXPECT_NE(id, 0);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest077
 * @tc.desc: Test GetOsAccountFromDatabase with invalid local id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest077, TestSize.Level1)
{
    int invalidLocalID = -1;
    OsAccountInfo osAccountInfo;
    EXPECT_NE(osAccountManagerService_->GetOsAccountFromDatabase(
        EMPTY_STORE_ID, invalidLocalID, osAccountInfo), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest078
 * @tc.desc: Test GetOsAccountFromDatabase with invalid store id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest078, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    EXPECT_NE(osAccountManagerService_->GetOsAccountFromDatabase(STORE_ID, MAIN_ACCOUNT_ID, osAccountInfo), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest079
 * @tc.desc: Test GetOsAccountFromDatabase normal case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest079, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountFromDatabase(
        EMPTY_STORE_ID, MAIN_ACCOUNT_ID, osAccountInfo), ERR_OK);
    EXPECT_EQ(osAccountInfo.GetLocalId(), MAIN_ACCOUNT_ID);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest080
 * @tc.desc: Test GetOsAccountListFromDatabase normal case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest080, TestSize.Level1)
{
    std::vector<OsAccountInfo> osAccountList;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountListFromDatabase(EMPTY_STORE_ID, osAccountList), ERR_OK);
    EXPECT_NE(osAccountList.size(), 0);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest081
 * @tc.desc: Test GetOsAccountListFromDatabase with invalid store id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest081, TestSize.Level1)
{
    std::vector<OsAccountInfo> osAccountList;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountListFromDatabase(STORE_ID, osAccountList), ERR_OK);
    EXPECT_EQ(osAccountList.size(), 0);
}
#endif // defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)

/**
 * @tc.name: OsAccountManagerServiceModuleTest082
 * @tc.desc: Test SetGlobalOsAccountConstraints normal case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest082, TestSize.Level1)
{
    bool isConstraintEnable = true;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountConstraintEnable(
        MAIN_ACCOUNT_ID, CONSTANT_PRINT, isConstraintEnable), ERR_OK);
    EXPECT_EQ(isConstraintEnable, false);
    EXPECT_EQ(osAccountManagerService_->SetGlobalOsAccountConstraints(
        CONSTANTS_VECTOR, true, MAIN_ACCOUNT_ID, true), ERR_OK);
    bool isConstraintEnable1 = false;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountConstraintEnable(
        MAIN_ACCOUNT_ID, CONSTANT_PRINT, isConstraintEnable1), ERR_OK);
    EXPECT_EQ(isConstraintEnable1, true);
    EXPECT_EQ(osAccountManagerService_->SetGlobalOsAccountConstraints(
        CONSTANTS_VECTOR, false, MAIN_ACCOUNT_ID, true), ERR_OK);
    bool isConstraintEnable2 = true;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountConstraintEnable(
        MAIN_ACCOUNT_ID, CONSTANT_PRINT, isConstraintEnable2), ERR_OK);
    EXPECT_EQ(isConstraintEnable2, false);

    int localId = Constants::START_USER_ID - 1;
    EXPECT_EQ(osAccountManagerService_->SetGlobalOsAccountConstraints(
        CONSTANTS_VECTOR, false, localId, true), ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest083
 * @tc.desc: Test SetGlobalOsAccountConstraints exception case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest083, TestSize.Level1)
{
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
 * @tc.name: OsAccountManagerServiceModuleTest084
 * @tc.desc: Test SetSpecificOsAccountConstraints normal case.
 * @tc.type: FUNC
 * @tc.require:
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest084, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountManagerService_->CreateOsAccount("Test084", INT_TEST_TYPE, osAccountInfo);
    EXPECT_EQ(errCode, ERR_OK);
    bool isConstraintEnable = true;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountConstraintEnable(
        MAIN_ACCOUNT_ID, CONSTANT_PRINT, isConstraintEnable), ERR_OK);
    EXPECT_EQ(isConstraintEnable, false);
    EXPECT_EQ(osAccountManagerService_->SetSpecificOsAccountConstraints(
        CONSTANTS_VECTOR, true, osAccountInfo.GetLocalId(), MAIN_ACCOUNT_ID, false), ERR_OK);
    isConstraintEnable = false;
    EXPECT_EQ(osAccountManagerService_->IsOsAccountConstraintEnable(
        osAccountInfo.GetLocalId(), CONSTANT_PRINT, isConstraintEnable), ERR_OK);
    EXPECT_EQ(isConstraintEnable, true);
    isConstraintEnable = true;
    EXPECT_EQ(osAccountManagerService_->SetSpecificOsAccountConstraints(
        CONSTANTS_VECTOR, false, osAccountInfo.GetLocalId(), MAIN_ACCOUNT_ID, false), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->IsOsAccountConstraintEnable(
        MAIN_ACCOUNT_ID, CONSTANT_PRINT, isConstraintEnable), ERR_OK);
    EXPECT_EQ(isConstraintEnable, false);

    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfo.GetLocalId()), ERR_OK);

    int localId = Constants::START_USER_ID - 1;
    EXPECT_EQ(osAccountManagerService_->SetSpecificOsAccountConstraints(
        CONSTANTS_VECTOR, false, localId, MAIN_ACCOUNT_ID, false), ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR);
    EXPECT_EQ(osAccountManagerService_->SetSpecificOsAccountConstraints(
        CONSTANTS_VECTOR, false, MAIN_ACCOUNT_ID, localId, false), ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest085
 * @tc.desc: Test SetSpecificOsAccountConstraints exception case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest085, TestSize.Level1)
{
    // test invalid target id
    EXPECT_NE(osAccountManagerService_->SetSpecificOsAccountConstraints(
        CONSTANTS_VECTOR, true, INVALID_ACCOUNT_ID, MAIN_ACCOUNT_ID, false), ERR_OK);
    // test invalid enforcer id
    EXPECT_NE(osAccountManagerService_->SetSpecificOsAccountConstraints(
        CONSTANTS_VECTOR, true, MAIN_ACCOUNT_ID, INVALID_ACCOUNT_ID, false), ERR_OK);
    // set exit constraints
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountManagerService_->CreateOsAccount("Test085", INT_TEST_TYPE, osAccountInfo);
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

/**
 * @tc.name: OsAccountManagerServiceModuleTest086
 * @tc.desc: Test SetGlobalOsAccountConstraints and SetSpecificOsAccountConstraints with MANAGE_EDM_POLICY.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest086, TestSize.Level1)
{
    OsAccountInfo info;
    EXPECT_EQ(osAccountManagerService_->CreateOsAccount("Test085", INT_TEST_TYPE, info), ERR_OK);

    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission({"ohos.permission.MANAGE_LOCAL_ACCOUNTS"}, tokenID));
    setuid(TEST_UID);
    EXPECT_EQ(osAccountManagerService_->SetGlobalOsAccountConstraints(
        CONSTANTS_VECTOR, true, MAIN_ACCOUNT_ID, true), ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    EXPECT_EQ(osAccountManagerService_->SetSpecificOsAccountConstraints(
        CONSTANTS_VECTOR, true, info.GetLocalId(), MAIN_ACCOUNT_ID, false), ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    setuid(ROOT_UID);
    ASSERT_TRUE(RecoveryPermission(tokenID, selfTokenId));

    ASSERT_TRUE(MockTokenId("edm"));
    setuid(TEST_UID);
    EXPECT_EQ(osAccountManagerService_->SetGlobalOsAccountConstraints(
        CONSTANTS_VECTOR, true, MAIN_ACCOUNT_ID, true), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->SetSpecificOsAccountConstraints(
        CONSTANTS_VECTOR, true, info.GetLocalId(), MAIN_ACCOUNT_ID, false), ERR_OK);
    setuid(ROOT_UID);
    ASSERT_TRUE(SetSelfTokenID(selfTokenId) == 0);

    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(info.GetLocalId()), ERR_OK);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: OsAccountManagerServiceModuleTest117
 * @tc.desc: test SetOsAccountProfilePhoto
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest117, TestSize.Level1)
{
    std::string photo = "";
    EXPECT_EQ(osAccountManagerService_->SetOsAccountProfilePhoto(Constants::START_USER_ID + 1, photo),
        ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest118
 * @tc.desc: test SetOsAccountProfilePhoto
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest118, TestSize.Level1)
{
    EXPECT_EQ(osAccountManagerService_->SetDefaultActivatedOsAccount(Constants::MAX_USER_ID + 1),
        ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest124
 * @tc.desc: test SetOsAccountProfilePhoto invalid paramter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest124, TestSize.Level1)
{
    EXPECT_EQ(
        osAccountManagerService_->SetOsAccountProfilePhoto(MAIN_ACCOUNT_ID, ""), ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
/**
 * @tc.name: OsAccountManagerServiceModuleTest125
 * @tc.desc: test CreateOsAccount permission with EDM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest125, TestSize.Level1)
{
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission({}, tokenID));
    setuid(TEST_UID);
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(ERR_ACCOUNT_COMMON_PERMISSION_DENIED,
        osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, INT_TEST_TYPE, osAccountInfo));

    setuid(ROOT_UID);
    ASSERT_TRUE(RecoveryPermission(tokenID, selfTokenId));
    setuid(3057);
    EXPECT_EQ(ERR_OK,
        osAccountManagerService_->CreateOsAccount("Test125", INT_TEST_TYPE, osAccountInfo));
    setuid(ROOT_UID);
    EXPECT_EQ(ERR_OK, osAccountManagerService_->RemoveOsAccount(osAccountInfo.GetLocalId()));
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest126
 * @tc.desc: Test DeactivateOsAccount success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest126, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount("Test126", INT_TEST_TYPE, osAccountInfo), ERR_OK);
    ASSERT_TRUE(osAccountInfo.GetLocalId() > Constants::START_USER_ID);
    EXPECT_EQ(osAccountManagerService_->ActivateOsAccount(osAccountInfo.GetLocalId()), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->DeactivateOsAccount(osAccountInfo.GetLocalId()), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfo.GetLocalId()), ERR_OK);
}

#ifdef SUPPORT_LOCK_OS_ACCOUNT
/**
 * @tc.name: OsAccountManagerServiceModuleTest127
 * @tc.desc: Test PublishOsAccountLockEvent failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest127, TestSize.Level1)
{
    EXPECT_EQ(osAccountManagerService_->PublishOsAccountLockEvent(-1, true),
        ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
    EXPECT_EQ(osAccountManagerService_->PublishOsAccountLockEvent(50, true),
        ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR);
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest128
 * @tc.desc: Test LockOsAccount failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, OsAccountManagerServiceModuleTest128, TestSize.Level1)
{
    EXPECT_EQ(osAccountManagerService_->LockOsAccount(-1),
        ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
    EXPECT_EQ(osAccountManagerService_->LockOsAccount(50),
        ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR);
}
#endif

/**
 * @tc.name: DeactivateAllOsAccountsModuleTest001
 * @tc.desc: Test DeactivateAllOsAccounts success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, DeactivateAllOsAccountsModuleTest001, TestSize.Level1)
{
    std::string privateName = "DeactivateAllOsAccounts001";
    OsAccountInfo osAccountInfo;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount(privateName, INT_TEST_TYPE, osAccountInfo), ERR_OK);
    ASSERT_TRUE(osAccountInfo.GetLocalId() > Constants::START_USER_ID);
    EXPECT_EQ(osAccountManagerService_->ActivateOsAccount(osAccountInfo.GetLocalId()), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->DeactivateAllOsAccounts(), ERR_OK);

    std::vector<int32_t> ids;
    EXPECT_EQ(osAccountManagerService_->QueryActiveOsAccountIds(ids), ERR_OK);
    EXPECT_EQ(ids.empty(), true);

    EXPECT_EQ(osAccountManagerService_->ActivateOsAccount(MAIN_ACCOUNT_ID), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfo.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: GetOsAccountType001
 * @tc.desc: Test GetOsAccountType.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, GetOsAccountType001, TestSize.Level1)
{
    OsAccountInfo osAccountInfoA;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount("GetTypeName001", OsAccountType::NORMAL, osAccountInfoA),
        ERR_OK);
    int32_t type = 0;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountType(osAccountInfoA.GetLocalId(), type), ERR_OK);
    EXPECT_EQ(type, static_cast<int32_t>(OsAccountType::NORMAL));
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoA.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: PrivateTypeTest001
 * @tc.desc: Test PRIVATE type os account.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, PrivateTypeTest001, TestSize.Level1)
{
    std::string privateTestName = "PrivateTestName001";
    std::string privateTestNameTwo = "PrivateTestName002";
    // test create private os account with normal account duplicate name
    OsAccountInfo osAccountInfoA;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount(privateTestName,
        OsAccountType::NORMAL, osAccountInfoA), ERR_OK);
    OsAccountInfo osAccountInfoB;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount(privateTestName,
        OsAccountType::PRIVATE, osAccountInfoB), ERR_OK);
    OsAccountInfo osAccountInfoC;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount(privateTestNameTwo,
        OsAccountType::PRIVATE, osAccountInfoC), ERR_OSACCOUNT_SERVICE_CONTROL_MAX_CAN_CREATE_ERROR);

    auto &innerMgr = osAccountManagerService_->innerManager_;
    ASSERT_NE(innerMgr.osAccountControl_, nullptr);
    osAccountInfoB.SetIsCreateCompleted(false);
    innerMgr.osAccountControl_->UpdateOsAccount(osAccountInfoB);
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount(privateTestNameTwo,
        OsAccountType::PRIVATE, osAccountInfoC), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoC.GetLocalId()), ERR_OK);

    // test get os account type by id
    int32_t type;
    EXPECT_EQ(osAccountManagerService_->GetOsAccountType(osAccountInfoB.GetLocalId(), type), ERR_OK);
    EXPECT_EQ(type, static_cast<int32_t>(OsAccountType::PRIVATE));
    EXPECT_EQ(osAccountManagerService_->GetOsAccountType(osAccountInfoA.GetLocalId(), type), ERR_OK);
    EXPECT_EQ(type, static_cast<int32_t>(OsAccountType::NORMAL));

    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoB.GetLocalId()), ERR_OK);

    // test delete private os account
    OsAccountInfo osAccountInfoD;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount(privateTestName,
        OsAccountType::PRIVATE, osAccountInfoD), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoD.GetLocalId()), ERR_OK);

    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoA.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: PrivateTypeTest002
 * @tc.desc: Test PRIVATE type os account.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, PrivateTypeTest002, TestSize.Level1)
{
    std::string privateTestName = "PrivateTestName001";
    // test create normal os account with private account duplicate name
    OsAccountInfo osAccountInfoA;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount(privateTestName,
        OsAccountType::PRIVATE, osAccountInfoA), ERR_OK);
    OsAccountInfo osAccountInfoB;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount(privateTestName,
        OsAccountType::NORMAL, osAccountInfoB), ERR_OK);

    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoA.GetLocalId()), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoB.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: PrivateTypeTest003
 * @tc.desc: Test PRIVATE type os account.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, PrivateTypeTest003, TestSize.Level1)
{
    std::string privateTestName = "PrivateTestName001";
    std::string privateTestNameTwo = "PrivateTestName002";
    std::string privateTestNameThree = "PrivateTestName003";
    // test set name with private account duplicate name
    OsAccountInfo osAccountInfoA;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount(privateTestName,
        OsAccountType::PRIVATE, osAccountInfoA), ERR_OK);
    OsAccountInfo osAccountInfoB;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount(privateTestNameTwo,
        OsAccountType::NORMAL, osAccountInfoB), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->SetOsAccountName(osAccountInfoB.GetLocalId(), privateTestName), ERR_OK);
    OsAccountInfo osAccountInfoC;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount(privateTestNameTwo, OsAccountType::NORMAL, osAccountInfoC),
        ERR_OK);
    EXPECT_EQ(osAccountManagerService_->SetOsAccountName(osAccountInfoA.GetLocalId(), privateTestNameTwo), ERR_OK);

    EXPECT_EQ(osAccountManagerService_->SetOsAccountName(osAccountInfoA.GetLocalId(), privateTestNameThree), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->SetOsAccountName(osAccountInfoC.GetLocalId(), privateTestNameThree), ERR_OK);

    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoA.GetLocalId()), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoB.GetLocalId()), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoC.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: MaxNumTest001
 * @tc.desc: test maxOsAccount and maxLoggedInOsAccount is valid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, MaxNumTest001, TestSize.Level1)
{
    AccountFileOperator osAccountFileOperator;
    osAccountFileOperator.InputFileByPathAndContent(CONFIG_PATH, CONFIG_JSON_NORMAL);
    auto &innerMgr = osAccountManagerService_->innerManager_;
    ASSERT_NE(innerMgr.osAccountControl_, nullptr);
    innerMgr.osAccountControl_->GetOsAccountConfig(innerMgr.config_);
    uint32_t maxOsAccountNum = 0;
    EXPECT_EQ(osAccountManagerService_->QueryMaxOsAccountNumber(maxOsAccountNum), ERR_OK);
    ASSERT_EQ(maxOsAccountNum, MAX_OS_ACCOUNT_NUM);
    uint32_t maxLoggedInOsAccountNum = 0;
    EXPECT_EQ(osAccountManagerService_->QueryMaxLoggedInOsAccountNumber(maxLoggedInOsAccountNum), ERR_OK);
    ASSERT_EQ(maxLoggedInOsAccountNum, MAX_LOGGED_IN_OS_ACCOUNT_NUM);
    std::vector<int32_t> createdOsAccounts;
    ErrCode ret = ERR_OK;
    OsAccountInfo osAccountInfo;
    for (uint32_t i = 1; i < maxOsAccountNum; ++i) {
        ret = osAccountManagerService_->CreateOsAccount(
            "InnerOsAccountManager004" + std::to_string(i), OsAccountType::NORMAL, osAccountInfo);
        EXPECT_EQ(ret, ERR_OK);
        createdOsAccounts.emplace_back(osAccountInfo.GetLocalId());
    }
    ret = osAccountManagerService_->CreateOsAccount(
            "InnerOsAccountManager004" + std::to_string(maxOsAccountNum), OsAccountType::NORMAL, osAccountInfo);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_CONTROL_MAX_CAN_CREATE_ERROR);
    for (uint32_t i = 0; i < maxLoggedInOsAccountNum - 1; ++i) {
        ret = osAccountManagerService_->ActivateOsAccount(createdOsAccounts[i]);
        EXPECT_EQ(ret, ERR_OK);
    }
#ifndef ENABLE_MULTIPLE_ACTIVE_ACCOUNTS
    if (maxLoggedInOsAccountNum < maxOsAccountNum && createdOsAccounts.size() > 0) {
        ret = osAccountManagerService_->ActivateOsAccount(createdOsAccounts[createdOsAccounts.size() - 1]);
        EXPECT_EQ(ret, ERR_OK);
    }
#endif
    for (uint32_t i = 0; i < maxOsAccountNum; ++i) {
        osAccountManagerService_->RemoveOsAccount(createdOsAccounts[i]);
    }
    osAccountFileOperator.DeleteDirOrFile(CONFIG_PATH);
}

/**
 * @tc.name: MaxNumTest002
 * @tc.desc: test the maxLoggedInOsAccountNum is larger then the maxOsAccountNum
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, MaxNumTest002, TestSize.Level1)
{
    AccountFileOperator osAccountFileOperator;
    osAccountFileOperator.InputFileByPathAndContent(CONFIG_PATH, CONFIG_JSON_LAGER_LOGGED_IN_NUM);
    auto &innerMgr = osAccountManagerService_->innerManager_;
    ASSERT_NE(innerMgr.osAccountControl_, nullptr);
    innerMgr.osAccountControl_->GetOsAccountConfig(innerMgr.config_);
    uint32_t maxOsAccountNum = 0;
    EXPECT_EQ(osAccountManagerService_->QueryMaxOsAccountNumber(maxOsAccountNum), ERR_OK);
    ASSERT_EQ(maxOsAccountNum, MAX_OS_ACCOUNT_NUM);
    uint32_t maxLoggedInOsAccountNum = 0;
    EXPECT_EQ(osAccountManagerService_->QueryMaxLoggedInOsAccountNumber(maxLoggedInOsAccountNum), ERR_OK);
    ASSERT_EQ(maxLoggedInOsAccountNum, MAX_OS_ACCOUNT_NUM);
    osAccountFileOperator.DeleteDirOrFile(CONFIG_PATH);
}

/**
 * @tc.name: MaxNumTest003
 * @tc.desc: test config json is invalid format.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, MaxNumTest003, TestSize.Level1)
{
    AccountFileOperator osAccountFileOperator;
    osAccountFileOperator.InputFileByPathAndContent(CONFIG_PATH, CONFIG_JSON_INVALID_FORMAT);
    auto &innerMgr = osAccountManagerService_->innerManager_;
    innerMgr.config_.maxOsAccountNum = DEFAULT_MAX_OS_ACCOUNT_NUM;
    innerMgr.config_.maxLoggedInOsAccountNum = DEFAULT_MAX_LOGGED_IN_OS_ACCOUNT_NUM;
    ASSERT_NE(innerMgr.osAccountControl_, nullptr);
    innerMgr.osAccountControl_->GetOsAccountConfig(innerMgr.config_);
    uint32_t maxOsAccountNum = 0;
    EXPECT_EQ(osAccountManagerService_->QueryMaxOsAccountNumber(maxOsAccountNum), ERR_OK);
    ASSERT_EQ(maxOsAccountNum, DEFAULT_MAX_OS_ACCOUNT_NUM);
    uint32_t maxLoggedInOsAccountNum = 0;
    EXPECT_EQ(osAccountManagerService_->QueryMaxLoggedInOsAccountNumber(maxLoggedInOsAccountNum), ERR_OK);
    ASSERT_EQ(maxLoggedInOsAccountNum, DEFAULT_MAX_LOGGED_IN_OS_ACCOUNT_NUM);
    osAccountFileOperator.DeleteDirOrFile(CONFIG_PATH);
}

/**
 * @tc.name: MaxNumTest004
 * @tc.desc: test key not found, or value is negative.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, MaxNumTest004, TestSize.Level1)
{
    AccountFileOperator osAccountFileOperator;
    osAccountFileOperator.InputFileByPathAndContent(CONFIG_PATH, CONFIG_JSON_INVALID_KEY_OR_VALUE);
    auto &innerMgr = osAccountManagerService_->innerManager_;
    innerMgr.config_.maxOsAccountNum = DEFAULT_MAX_OS_ACCOUNT_NUM;
    innerMgr.config_.maxLoggedInOsAccountNum = DEFAULT_MAX_LOGGED_IN_OS_ACCOUNT_NUM;
    ASSERT_NE(innerMgr.osAccountControl_, nullptr);
    innerMgr.osAccountControl_->GetOsAccountConfig(innerMgr.config_);
    uint32_t maxOsAccountNum = 0;
    EXPECT_EQ(osAccountManagerService_->QueryMaxOsAccountNumber(maxOsAccountNum), ERR_OK);
    ASSERT_EQ(maxOsAccountNum, DEFAULT_MAX_OS_ACCOUNT_NUM);
    uint32_t maxLoggedInOsAccountNum = 0;
    EXPECT_EQ(osAccountManagerService_->QueryMaxLoggedInOsAccountNumber(maxLoggedInOsAccountNum), ERR_OK);
    ASSERT_EQ(maxLoggedInOsAccountNum, DEFAULT_MAX_LOGGED_IN_OS_ACCOUNT_NUM);
    osAccountFileOperator.DeleteDirOrFile(CONFIG_PATH);
}

/**
 * @tc.name: MaxNumTest005
 * @tc.desc: test activateOsAccount failed when the number of the logged in accounts reaches upper limit.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, MaxNumTest005, TestSize.Level1)
{
    auto &innerMgr = osAccountManagerService_->innerManager_;
    innerMgr.config_.maxLoggedInOsAccountNum = 1;
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(osAccountManagerService_->CreateOsAccount("MaxNumTest005", OsAccountType::NORMAL, osAccountInfo),
        ERR_OK);
    EXPECT_EQ(osAccountManagerService_->ActivateOsAccount(osAccountInfo.GetLocalId()),
        ERR_OSACCOUNT_SERVICE_LOGGED_IN_ACCOUNTS_OVERSIZE);
}

/**
 * @tc.name: MaxNumTest006
 * @tc.desc: test create account failed in accounts reaches upper limit. and success in after clean garbages.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, MaxNumTest006, TestSize.Level1)
{
    AccountFileOperator osAccountFileOperator;
    osAccountFileOperator.InputFileByPathAndContent(CONFIG_PATH, CONFIG_JSON_NORMAL);
    auto &innerMgr = osAccountManagerService_->innerManager_;
    ASSERT_NE(innerMgr.osAccountControl_, nullptr);
    innerMgr.osAccountControl_->GetOsAccountConfig(innerMgr.config_);

    uint32_t maxOsAccountNum = 0;
    EXPECT_EQ(osAccountManagerService_->QueryMaxOsAccountNumber(maxOsAccountNum), ERR_OK);
    ASSERT_EQ(maxOsAccountNum, MAX_OS_ACCOUNT_NUM);

    uint32_t maxLoggedInOsAccountNum = 0;
    EXPECT_EQ(osAccountManagerService_->QueryMaxLoggedInOsAccountNumber(maxLoggedInOsAccountNum), ERR_OK);
    ASSERT_EQ(maxLoggedInOsAccountNum, MAX_LOGGED_IN_OS_ACCOUNT_NUM);

    std::vector<OsAccountInfo> osAccountInfos;
    EXPECT_EQ(osAccountManagerService_->QueryAllCreatedOsAccounts(osAccountInfos), ERR_OK);
    for (const auto &osAccountInfo : osAccountInfos) {
        if (osAccountInfo.GetLocalId() == START_USER_ID) {
            continue;
        }
        osAccountManagerService_->RemoveOsAccount(osAccountInfo.GetLocalId());
    }

    innerMgr.CleanGarbageOsAccounts();

    std::vector<int32_t> createdOsAccounts;
    OsAccountInfo osAccountInfo;
    for (uint32_t i = 1; i < maxOsAccountNum; ++i) {
        EXPECT_EQ(osAccountManagerService_->CreateOsAccount(
            "MaxNumTest006" + std::to_string(i), OsAccountType::NORMAL, osAccountInfo), ERR_OK);
        createdOsAccounts.emplace_back(osAccountInfo.GetLocalId());
    }

    EXPECT_EQ(osAccountManagerService_->CreateOsAccount(
            "MaxNumTest006" + std::to_string(maxOsAccountNum), OsAccountType::NORMAL, osAccountInfo),
            ERR_OSACCOUNT_SERVICE_CONTROL_MAX_CAN_CREATE_ERROR);

    int32_t lastAccountId = createdOsAccounts.back();
    EXPECT_EQ(osAccountManagerService_->SetOsAccountToBeRemoved(lastAccountId, true), ERR_OK);

    EXPECT_EQ(osAccountManagerService_->CreateOsAccount(
            "MaxNumTest006_New", OsAccountType::NORMAL, osAccountInfo), ERR_OK);
    createdOsAccounts.emplace_back(osAccountInfo.GetLocalId());


    for (const auto &id : createdOsAccounts) {
        osAccountManagerService_->RemoveOsAccount(id);
    }
    osAccountFileOperator.DeleteDirOrFile(CONFIG_PATH);
}

/**
 * @tc.name: MaxNumTest007
 * @tc.desc: test create account failed in accounts reaches upper limit, and not limited by sa call
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, MaxNumTest007, TestSize.Level1)
{
    AccountFileOperator osAccountFileOperator;
    osAccountFileOperator.InputFileByPathAndContent(CONFIG_PATH, CONFIG_JSON_NORMAL);
    auto &innerMgr = osAccountManagerService_->innerManager_;
    ASSERT_NE(innerMgr.osAccountControl_, nullptr);
    innerMgr.osAccountControl_->GetOsAccountConfig(innerMgr.config_);

    uint32_t maxOsAccountNum = 0;
    EXPECT_EQ(osAccountManagerService_->QueryMaxOsAccountNumber(maxOsAccountNum), ERR_OK);
    ASSERT_EQ(maxOsAccountNum, MAX_OS_ACCOUNT_NUM);

    std::vector<OsAccountInfo> osAccountInfos;
    EXPECT_EQ(osAccountManagerService_->QueryAllCreatedOsAccounts(osAccountInfos), ERR_OK);
    for (const auto &osAccountInfo : osAccountInfos) {
        if (osAccountInfo.GetLocalId() == START_USER_ID) {
            continue;
        }
        osAccountManagerService_->RemoveOsAccount(osAccountInfo.GetLocalId());
    }

    innerMgr.CleanGarbageOsAccounts();

    std::vector<int32_t> createdOsAccounts;
    OsAccountInfo osAccountInfo;
    for (uint32_t i = 1; i < maxOsAccountNum; ++i) {
        EXPECT_EQ(osAccountManagerService_->CreateOsAccount(
            "MaxNumTest007" + std::to_string(i), OsAccountType::NORMAL, osAccountInfo), ERR_OK);
        createdOsAccounts.emplace_back(osAccountInfo.GetLocalId());
    }

    EXPECT_EQ(osAccountManagerService_->CreateOsAccount(
            "MaxNumTest007" + std::to_string(maxOsAccountNum), OsAccountType::NORMAL, osAccountInfo),
            ERR_OSACCOUNT_SERVICE_CONTROL_MAX_CAN_CREATE_ERROR);

    AccessTokenID selfTokenId = IPCSkeleton::GetSelfTokenID();
    AccessTokenID tokenId = GetTokenIdFromProcess("accountmgr");
    EXPECT_EQ(ERR_OK, SetSelfTokenID(tokenId));
    EXPECT_EQ(osAccountManagerService_->CreateOsAccount(
            "MaxNumTest007_SaCreated", OsAccountType::NORMAL, osAccountInfo), ERR_OK);
    EXPECT_EQ(NATIVE_TOKEN, osAccountInfo.GetCreatorType());
    createdOsAccounts.emplace_back(osAccountInfo.GetLocalId());
    EXPECT_EQ(ERR_OK, SetSelfTokenID(selfTokenId));

    for (const auto &id : createdOsAccounts) {
        osAccountManagerService_->RemoveOsAccount(id);
    }
    osAccountFileOperator.DeleteDirOrFile(CONFIG_PATH);
}

/**
 * @tc.name: MaxNumTest008
 * @tc.desc: test sa created account does not affect upper limit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, MaxNumTest008, TestSize.Level1)
{
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission({}, tokenID));

    AccountFileOperator osAccountFileOperator;
    osAccountFileOperator.InputFileByPathAndContent(CONFIG_PATH, CONFIG_JSON_NORMAL);
    auto &innerMgr = osAccountManagerService_->innerManager_;
    ASSERT_NE(innerMgr.osAccountControl_, nullptr);
    innerMgr.osAccountControl_->GetOsAccountConfig(innerMgr.config_);

    uint32_t maxOsAccountNum = 0;
    EXPECT_EQ(osAccountManagerService_->QueryMaxOsAccountNumber(maxOsAccountNum), ERR_OK);
    ASSERT_EQ(maxOsAccountNum, MAX_OS_ACCOUNT_NUM);

    std::vector<OsAccountInfo> osAccountInfos;
    EXPECT_EQ(osAccountManagerService_->QueryAllCreatedOsAccounts(osAccountInfos), ERR_OK);
    for (const auto &osAccountInfo : osAccountInfos) {
        if (osAccountInfo.GetLocalId() == START_USER_ID) {
            continue;
        }
        osAccountManagerService_->RemoveOsAccount(osAccountInfo.GetLocalId());
    }

    innerMgr.CleanGarbageOsAccounts();

    std::vector<int32_t> createdOsAccounts;
    OsAccountInfo osAccountInfo;
    AccessTokenID selfTokenId = IPCSkeleton::GetSelfTokenID();
    AccessTokenID tokenId = GetTokenIdFromProcess("accountmgr");
    EXPECT_EQ(ERR_OK, SetSelfTokenID(tokenId));
    for (uint32_t i = 1; i < maxOsAccountNum; ++i) {
        EXPECT_EQ(osAccountManagerService_->CreateOsAccount(
            "MaxNumTest008_sa_" + std::to_string(i), OsAccountType::NORMAL, osAccountInfo), ERR_OK);
        createdOsAccounts.emplace_back(osAccountInfo.GetLocalId());
    }
    EXPECT_EQ(ERR_OK, SetSelfTokenID(selfTokenId));

    EXPECT_EQ(osAccountManagerService_->CreateOsAccount(
            "MaxNumTest008" + std::to_string(maxOsAccountNum), OsAccountType::NORMAL, osAccountInfo), ERR_OK);

    for (const auto &id : createdOsAccounts) {
        osAccountManagerService_->RemoveOsAccount(id);
    }
    osAccountFileOperator.DeleteDirOrFile(CONFIG_PATH);
}

/**
 * @tc.name: SetOsAccountIsLoggedInTest001
 * @tc.desc: coverage SetOsAccountIsLoggedIn
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, SetOsAccountIsLoggedInTest001, TestSize.Level1)
{
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission({"ohos.permission.MANAGE_LOCAL_ACCOUNTS"}, tokenID));
    OsAccountInfo osAccountInfo;
    ErrCode ret = osAccountManagerService_->CreateOsAccount(
        "SetOsAccountIsLoggedInTest001", OsAccountType::NORMAL, osAccountInfo);
    ASSERT_EQ(ret, ERR_OK);
    int localId = osAccountInfo.GetLocalId();
    // account not found, login fail
    EXPECT_EQ(osAccountManagerService_->innerManager_.SetOsAccountIsLoggedIn(localId + 1, true),
        ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
    // to be removed, login fail
    ASSERT_EQ(osAccountManagerService_->SetOsAccountToBeRemoved(localId, true), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->innerManager_.SetOsAccountIsLoggedIn(localId, true),
        ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_TO_BE_REMOVED_ERROR);
    // unset toBeRemoved
    ASSERT_EQ(osAccountManagerService_->SetOsAccountToBeRemoved(localId, false), ERR_OK);
    EXPECT_FALSE(osAccountInfo.GetIsLoggedIn());
    EXPECT_FALSE(osAccountInfo.GetLastLoginTime() > 0);
    // login
    EXPECT_EQ(osAccountManagerService_->innerManager_.SetOsAccountIsLoggedIn(localId, true), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->QueryOsAccountById(localId, osAccountInfo), ERR_OK);
    EXPECT_TRUE(osAccountInfo.GetIsLoggedIn());
    EXPECT_TRUE(osAccountInfo.GetLastLoginTime() > 0);
    bool val = true;
    EXPECT_TRUE(osAccountManagerService_->innerManager_.loggedInAccounts_.Find(localId, val));
    // logout
    EXPECT_EQ(osAccountManagerService_->innerManager_.SetOsAccountIsLoggedIn(localId, false), ERR_OK);
    EXPECT_FALSE(osAccountManagerService_->innerManager_.loggedInAccounts_.Find(localId, val));
    osAccountManagerService_->RemoveOsAccount(osAccountInfo.GetLocalId());
}

/**
 * @tc.name: MaintenanceTypeTest001
 * @tc.desc: Test MAINTENANCE type os account.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, MaintenanceTypeTest001, TestSize.Level1)
{
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    ASSERT_TRUE(MockTokenId("accountmgr"));
    std::string maintenanceTestName = "MaintenanceTypeTest001";
    // test create maintenance os account
    OsAccountInfo osAccountInfoA;
    ASSERT_EQ(osAccountManagerService_->CreateOsAccount(maintenanceTestName,
        OsAccountType::MAINTENANCE, osAccountInfoA), ERR_OK);
    OsAccountInfo osAccountInfoB;
    EXPECT_EQ(osAccountManagerService_->CreateOsAccount("MaintenanceTypeTest001B",
        OsAccountType::MAINTENANCE, osAccountInfoB), ERR_OSACCOUNT_SERVICE_CONTROL_MAX_CAN_CREATE_ERROR);
    EXPECT_EQ(osAccountManagerService_->CreateOsAccount(maintenanceTestName,
        OsAccountType::NORMAL, osAccountInfoB), ERR_ACCOUNT_COMMON_NAME_HAD_EXISTED);

    // test maintenance os account id
    EXPECT_EQ(osAccountInfoA.GetLocalId(), Constants::MAINTENANCE_USER_ID);

    // test remove maintenance os account
    ASSERT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoA.GetLocalId()), ERR_OK);

    // test create maintenance os account after remove
    OsAccountInfo osAccountInfoC;
    EXPECT_EQ(osAccountManagerService_->CreateOsAccount(maintenanceTestName,
        OsAccountType::MAINTENANCE, osAccountInfoC), ERR_OK);
    EXPECT_EQ(osAccountInfoC.GetLocalId(), Constants::MAINTENANCE_USER_ID);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoC.GetLocalId()), ERR_OK);

    osAccountInfoA.SetType(OsAccountType::NORMAL);
    EXPECT_EQ(osAccountManagerService_->CreateOsAccountWithFullInfo(osAccountInfoA), ERR_OK);
    EXPECT_EQ(osAccountManagerService_->CreateOsAccount("MaintenanceTypeTest001B",
        OsAccountType::MAINTENANCE, osAccountInfoC), ERR_OSACCOUNT_SERVICE_CONTROL_INSERT_FILE_EXISTS_ERROR);
    EXPECT_EQ(osAccountManagerService_->RemoveOsAccount(osAccountInfoA.GetLocalId()), ERR_OK);
    SetSelfTokenID(selfTokenId);
}
#endif //ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: U1Checkout001
 * @tc.desc: Test the operation is allow u1 or not
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, U1Checkout001, TestSize.Level1)
{
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission({"ohos.permission.MANAGE_LOCAL_ACCOUNTS"}, tokenID));
    bool isU1Exist = false;
    EXPECT_EQ(ERR_OK, osAccountManagerService_->IsOsAccountExists(1, isU1Exist));
    ErrCode targetCode = 0;
    if (isU1Exist) {
        targetCode = ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    } else {
        targetCode = ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    ASSERT_EQ(osAccountManagerService_->RemoveOsAccount(1), targetCode);
    ASSERT_EQ(osAccountManagerService_->SetOsAccountName(1, STRING_NAME), targetCode);
    std::vector<std::string> constraints;
    ASSERT_EQ(osAccountManagerService_->SetOsAccountConstraints(1, constraints, true), targetCode);
    ASSERT_EQ(osAccountManagerService_->SetOsAccountProfilePhoto(1, STRING_NAME), targetCode);
    ASSERT_EQ(osAccountManagerService_->ActivateOsAccount(1), targetCode);
    ASSERT_EQ(osAccountManagerService_->DeactivateOsAccount(1), targetCode);
    ASSERT_EQ(osAccountManagerService_->SetCurrentOsAccountIsVerified(1), ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR);
    ASSERT_EQ(osAccountManagerService_->SetOsAccountIsVerified(1, true), targetCode);
    ASSERT_EQ(osAccountManagerService_->SetDefaultActivatedOsAccount(1), ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR);
    ASSERT_EQ(osAccountManagerService_->SetOsAccountToBeRemoved(1, true), targetCode);
}

/**
 * @tc.name: SubscribeConstraints_Invalid_Param001
 * @tc.desc: Test SubscribeOsAccountConstraints eventListener is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, SubscribeConstraints_Invalid_Param001, TestSize.Level1)
{
    std::set<std::string> constraints;
    OsAccountConstraintSubscribeInfo info(constraints);
    ASSERT_EQ(osAccountManagerService_->SubscribeOsAccountConstraints(info, nullptr),
        ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    ASSERT_EQ(osAccountManagerService_->UnsubscribeOsAccountConstraints(info, nullptr),
        ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: CheckLocalIdRestricted_001
 * @tc.desc: Test CheckLocalIdRestricted with diff input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, CheckLocalIdRestricted_001, TestSize.Level1)
{
    ErrCode ret = osAccountManagerService_->CheckLocalIdRestricted(Constants::ADMIN_LOCAL_ID);
    ASSERT_EQ(ret, ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR);
    ret = osAccountManagerService_->CheckLocalIdRestricted(Constants::START_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    bool isExists = false;
    osAccountManagerService_->IsOsAccountExists(Constants::U1_ID, isExists);
    ret = osAccountManagerService_->CheckLocalIdRestricted(Constants::U1_ID);
    if (isExists) {
        ASSERT_EQ(ret, ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR);
    } else {
        ASSERT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
    }

    int32_t unusedLocalId = 99; // 99 is currently unused
    ret = osAccountManagerService_->CheckLocalIdRestricted(unusedLocalId);
    ASSERT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: CreateOsAccount_001
 * @tc.desc: Test CreateOsAccount with valid data.
 * @tc.type: FUNC
 * @tc.require:
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(OsAccountManagerServiceModuleTest, CreateOsAccount_001, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    StringRawData rawdata;
    ErrCode errCode = osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, STRING_TEST_NAME, TEST_UID, rawdata);
    EXPECT_EQ(errCode, ERR_OK);
}
#endif

/**
 * @tc.name: CheckOsAccountConstraint01
 * @tc.desc: Test CheckOsAccountConstraint.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceModuleTest, CheckOsAccountConstraint01, TestSize.Level3)
{
    bool isConstraintEnable = false;
    std::string constraint = "";
    EXPECT_EQ(osAccountManagerService_->IsOsAccountConstraintEnable(
        INVALID_ACCOUNT_ID, constraint, isConstraintEnable), ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}
}  // namespace AccountSA
}  // namespace OHOS