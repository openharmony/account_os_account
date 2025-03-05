/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS
#ifdef DOMAIN_ACCOUNT_TEST_CASE
const uid_t ACCOUNT_UID = 3058;
#endif // DOMAIN_ACCOUNT_TEST_CASE
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
#ifdef ENABLE_FILE_WATCHER
const std::shared_ptr<AccountFileOperator> g_accountFileOperator =
    AccountFileWatcherMgr::GetInstance().accountFileOperator_;
#else
const std::shared_ptr<AccountFileOperator> g_accountFileOperator = std::make_shared<AccountFileOperator>();
#endif // ENABLE_FILE_WATCHER
}  // namespace

class OsAccountManagerServiceNoPermissionModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::shared_ptr<OsAccountManagerService>
        osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
};

void OsAccountManagerServiceNoPermissionModuleTest::SetUpTestCase(void)
{
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission({}, tokenID));
#ifdef ACCOUNT_TEST
    AccountFileOperator osAccountFileOperator;
    osAccountFileOperator.DeleteDirOrFile(USER_INFO_BASE);
    GTEST_LOG_(INFO) << "delete account test path " << USER_INFO_BASE;
#endif  // ACCOUNT_TEST
    ASSERT_NE(g_accountFileOperator, nullptr);
    IInnerOsAccountManager::GetInstance().Init();
    IInnerOsAccountManager::GetInstance().ActivateDefaultOsAccount();
}

void OsAccountManagerServiceNoPermissionModuleTest::TearDownTestCase(void)
{
#ifdef ACCOUNT_TEST
    AccountFileOperator osAccountFileOperator;
    osAccountFileOperator.DeleteDirOrFile(USER_INFO_BASE);
    GTEST_LOG_(INFO) << "delete account test path " << USER_INFO_BASE;
#endif  // ACCOUNT_TEST
}

void OsAccountManagerServiceNoPermissionModuleTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());

    setuid(ROOT_UID);
}

void OsAccountManagerServiceNoPermissionModuleTest::TearDown(void)
{
    setuid(ROOT_UID);
}

#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
/**
 * @tc.name: OsAccountManagerServiceModuleTest086
 * @tc.desc: Test CreateOsAccount PermissionCheck failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceNoPermissionModuleTest, OsAccountManagerServiceModuleTest086, TestSize.Level1)
{
    setuid(TEST_UID);
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(ERR_ACCOUNT_COMMON_PERMISSION_DENIED,
        osAccountManagerService_->CreateOsAccount("Test086", INT_TEST_TYPE, osAccountInfo));
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: OsAccountManagerServiceModuleTest087
 * @tc.desc: Test CreateOsAccountForDomain PermissionCheck failed.
 * @tc.type: FUNC
 * @tc.require:
 */
#ifdef DOMAIN_ACCOUNT_TEST_CASE
HWTEST_F(OsAccountManagerServiceNoPermissionModuleTest, OsAccountManagerServiceModuleTest087, TestSize.Level1)
{
    setuid(TEST_UID);
    OsAccountType type = NORMAL;
    DomainAccountInfo domainInfo(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(ERR_ACCOUNT_COMMON_PERMISSION_DENIED,
        osAccountManagerService_->CreateOsAccountForDomain(type, domainInfo, osAccountInfo));
}
#endif // DOMAIN_ACCOUNT_TEST_CASE

/**
 * @tc.name: OsAccountManagerServiceModuleTest088
 * @tc.desc: Test RemoveOsAccount PermissionCheck failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceNoPermissionModuleTest, OsAccountManagerServiceModuleTest088, TestSize.Level1)
{
    setuid(TEST_UID);
    int id = MAIN_ACCOUNT_ID + 1;
    EXPECT_EQ(ERR_ACCOUNT_COMMON_PERMISSION_DENIED,
        osAccountManagerService_->RemoveOsAccount(id));
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest089
 * @tc.desc: Test IsOsAccountActived PermissionCheck failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceNoPermissionModuleTest, OsAccountManagerServiceModuleTest089, TestSize.Level1)
{
    setuid(TEST_UID);
    bool isOsAccountActived;
    EXPECT_EQ(ERR_ACCOUNT_COMMON_PERMISSION_DENIED,
        osAccountManagerService_->IsOsAccountActived(MAIN_ACCOUNT_ID, isOsAccountActived));
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest090
 * @tc.desc: Test IsOsAccountConstraintEnable PermissionCheck failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceNoPermissionModuleTest, OsAccountManagerServiceModuleTest090, TestSize.Level1)
{
    setuid(TEST_UID);
    bool isOsAccountActived;
    EXPECT_EQ(ERR_ACCOUNT_COMMON_PERMISSION_DENIED,
        osAccountManagerService_->IsOsAccountConstraintEnable(MAIN_ACCOUNT_ID, CONSTANT_PRINT, isOsAccountActived));
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest091
 * @tc.desc: Test IsOsAccountVerified PermissionCheck failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceNoPermissionModuleTest, OsAccountManagerServiceModuleTest091, TestSize.Level1)
{
    setuid(TEST_UID);
    bool isVerified;
    EXPECT_EQ(ERR_ACCOUNT_COMMON_PERMISSION_DENIED,
        osAccountManagerService_->IsOsAccountVerified(MAIN_ACCOUNT_ID, isVerified));
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest092
 * @tc.desc: Test GetCreatedOsAccountsCount PermissionCheck failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceNoPermissionModuleTest, OsAccountManagerServiceModuleTest092, TestSize.Level1)
{
    setuid(TEST_UID);
    unsigned int osAccountsCount;
    EXPECT_EQ(ERR_ACCOUNT_COMMON_PERMISSION_DENIED,
        osAccountManagerService_->GetCreatedOsAccountsCount(osAccountsCount));
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest093
 * @tc.desc: Test IsMainOsAccount PermissionCheck failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceNoPermissionModuleTest, OsAccountManagerServiceModuleTest093, TestSize.Level1)
{
    setuid(TEST_UID);
    bool isMainOsAccount;
    EXPECT_EQ(ERR_ACCOUNT_COMMON_PERMISSION_DENIED,
        osAccountManagerService_->IsMainOsAccount(isMainOsAccount));
}

#ifdef DOMAIN_ACCOUNT_TEST_CASE
/**
 * @tc.name: OsAccountManagerServiceModuleTest094
 * @tc.desc: Test GetOsAccountLocalIdFromDomain PermissionCheck failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceNoPermissionModuleTest, OsAccountManagerServiceModuleTest094, TestSize.Level1)
{
    setuid(TEST_UID);
    DomainAccountInfo domainInfo(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    int id;
    EXPECT_EQ(ERR_ACCOUNT_COMMON_PERMISSION_DENIED,
        osAccountManagerService_->GetOsAccountLocalIdFromDomain(domainInfo, id));
}
#endif // DOMAIN_ACCOUNT_TEST_CASE

/**
 * @tc.name: OsAccountManagerServiceModuleTest095
 * @tc.desc: Test GetOsAccountAllConstraints PermissionCheck failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceNoPermissionModuleTest, OsAccountManagerServiceModuleTest095, TestSize.Level1)
{
    setuid(TEST_UID);
    std::vector<std::string> constraints;
    EXPECT_EQ(ERR_ACCOUNT_COMMON_PERMISSION_DENIED,
        osAccountManagerService_->GetOsAccountAllConstraints(MAIN_ACCOUNT_ID, constraints));
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest096
 * @tc.desc: Test QueryAllCreatedOsAccounts PermissionCheck failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceNoPermissionModuleTest, OsAccountManagerServiceModuleTest096, TestSize.Level1)
{
    setuid(TEST_UID);
    std::vector<OsAccountInfo> osAccountInfos;
    EXPECT_EQ(ERR_ACCOUNT_COMMON_PERMISSION_DENIED,
        osAccountManagerService_->QueryAllCreatedOsAccounts(osAccountInfos));
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest097
 * @tc.desc: Test QueryCurrentOsAccount PermissionCheck failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceNoPermissionModuleTest, OsAccountManagerServiceModuleTest097, TestSize.Level1)
{
    setuid(TEST_UID);
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(ERR_ACCOUNT_COMMON_PERMISSION_DENIED,
        osAccountManagerService_->QueryCurrentOsAccount(osAccountInfo));
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest098
 * @tc.desc: Test QueryOsAccountById PermissionCheck failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceNoPermissionModuleTest, OsAccountManagerServiceModuleTest098, TestSize.Level1)
{
    setuid(TEST_UID);
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(ERR_ACCOUNT_COMMON_PERMISSION_DENIED,
        osAccountManagerService_->QueryOsAccountById(MAIN_ACCOUNT_ID, osAccountInfo));
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest099
 * @tc.desc: Test GetOsAccountProfilePhoto PermissionCheck failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceNoPermissionModuleTest, OsAccountManagerServiceModuleTest099, TestSize.Level1)
{
    setuid(TEST_UID);
    std::string photo;
    EXPECT_EQ(ERR_ACCOUNT_COMMON_PERMISSION_DENIED,
        osAccountManagerService_->GetOsAccountProfilePhoto(MAIN_ACCOUNT_ID, photo));
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest100
 * @tc.desc: Test SetOsAccountName PermissionCheck failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceNoPermissionModuleTest, OsAccountManagerServiceModuleTest100, TestSize.Level1)
{
    setuid(TEST_UID);
    EXPECT_EQ(ERR_ACCOUNT_COMMON_PERMISSION_DENIED,
        osAccountManagerService_->SetOsAccountName(MAIN_ACCOUNT_ID, STRING_NAME));
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest101
 * @tc.desc: Test SetOsAccountConstraints PermissionCheck failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceNoPermissionModuleTest, OsAccountManagerServiceModuleTest101, TestSize.Level1)
{
    setuid(TEST_UID);
    EXPECT_EQ(ERR_ACCOUNT_COMMON_PERMISSION_DENIED,
        osAccountManagerService_->SetOsAccountConstraints(MAIN_ACCOUNT_ID, CONSTANTS_VECTOR, true));
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest102
 * @tc.desc: Test SetOsAccountProfilePhoto PermissionCheck failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceNoPermissionModuleTest, OsAccountManagerServiceModuleTest102, TestSize.Level1)
{
    setuid(TEST_UID);
    EXPECT_EQ(ERR_ACCOUNT_COMMON_PERMISSION_DENIED,
        osAccountManagerService_->SetOsAccountProfilePhoto(MAIN_ACCOUNT_ID, PHOTO_IMG));
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest103
 * @tc.desc: Test ActivateOsAccount PermissionCheck failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceNoPermissionModuleTest, OsAccountManagerServiceModuleTest103, TestSize.Level1)
{
    setuid(TEST_UID);
    EXPECT_EQ(ERR_ACCOUNT_COMMON_PERMISSION_DENIED,
        osAccountManagerService_->ActivateOsAccount(MAIN_ACCOUNT_ID));
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest104
 * @tc.desc: Test SubscribeOsAccount PermissionCheck failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceNoPermissionModuleTest, OsAccountManagerServiceModuleTest104, TestSize.Level1)
{
    setuid(TEST_UID);
    OsAccountSubscribeInfo subscribeInfo;
    sptr<IRemoteObject> eventListener = nullptr;
    EXPECT_EQ(ERR_ACCOUNT_COMMON_PERMISSION_DENIED,
        osAccountManagerService_->SubscribeOsAccount(subscribeInfo, eventListener));
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest105
 * @tc.desc: Test UnsubscribeOsAccount PermissionCheck failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceNoPermissionModuleTest, OsAccountManagerServiceModuleTest105, TestSize.Level1)
{
    setuid(TEST_UID);
    sptr<IRemoteObject> eventListener = nullptr;
    EXPECT_EQ(ERR_ACCOUNT_COMMON_PERMISSION_DENIED, osAccountManagerService_->UnsubscribeOsAccount(eventListener));
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest106
 * @tc.desc: Test SetCurrentOsAccountIsVerified PermissionCheck failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceNoPermissionModuleTest, OsAccountManagerServiceModuleTest106, TestSize.Level1)
{
    setuid(TEST_UID);
    EXPECT_EQ(ERR_ACCOUNT_COMMON_PERMISSION_DENIED,
        osAccountManagerService_->SetCurrentOsAccountIsVerified(true));
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest107
 * @tc.desc: Test SetOsAccountIsVerified PermissionCheck failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceNoPermissionModuleTest, OsAccountManagerServiceModuleTest107, TestSize.Level1)
{
    setuid(TEST_UID);
    EXPECT_EQ(ERR_ACCOUNT_COMMON_PERMISSION_DENIED,
        osAccountManagerService_->SetOsAccountIsVerified(MAIN_ACCOUNT_ID, true));
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest108
 * @tc.desc: Test DumpState PermissionCheck failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceNoPermissionModuleTest, OsAccountManagerServiceModuleTest108, TestSize.Level1)
{
    setuid(TEST_UID);
    int id = MAIN_ACCOUNT_ID;
    std::vector<std::string> state;
    EXPECT_EQ(ERR_ACCOUNT_COMMON_PERMISSION_DENIED,
        osAccountManagerService_->DumpState(id, state));
}

#if defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
/**
 * @tc.name: OsAccountManagerServiceModuleTest109
 * @tc.desc: Test GetCreatedOsAccountNumFromDatabase PermissionCheck failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceNoPermissionModuleTest, OsAccountManagerServiceModuleTest109, TestSize.Level1)
{
    setuid(TEST_UID);
    int createdOsAccountNum;
    EXPECT_EQ(ERR_ACCOUNT_COMMON_PERMISSION_DENIED,
        osAccountManagerService_->GetCreatedOsAccountNumFromDatabase(STORE_ID, createdOsAccountNum));
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest110
 * @tc.desc: Test GetOsAccountFromDatabase PermissionCheck failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceNoPermissionModuleTest, OsAccountManagerServiceModuleTest110, TestSize.Level1)
{
    setuid(TEST_UID);
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(ERR_ACCOUNT_COMMON_PERMISSION_DENIED,
        osAccountManagerService_->GetOsAccountFromDatabase(STORE_ID, MAIN_ACCOUNT_ID, osAccountInfo));
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest111
 * @tc.desc: Test GetOsAccountListFromDatabase PermissionCheck failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceNoPermissionModuleTest, OsAccountManagerServiceModuleTest111, TestSize.Level1)
{
    setuid(TEST_UID);
    std::vector<OsAccountInfo> osAccountList;
    EXPECT_EQ(ERR_ACCOUNT_COMMON_PERMISSION_DENIED,
        osAccountManagerService_->GetOsAccountListFromDatabase(STORE_ID, osAccountList));
}
#endif // defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)

/**
 * @tc.name: OsAccountManagerServiceModuleTest112
 * @tc.desc: Test QueryOsAccountConstraintSourceTypes PermissionCheck failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceNoPermissionModuleTest, OsAccountManagerServiceModuleTest112, TestSize.Level1)
{
    setuid(TEST_UID);
    std::vector<ConstraintSourceTypeInfo> constraintSourceTypeInfos;
    EXPECT_EQ(ERR_ACCOUNT_COMMON_PERMISSION_DENIED, osAccountManagerService_->QueryOsAccountConstraintSourceTypes(
            MAIN_ACCOUNT_ID, CONSTANT_WIFI, constraintSourceTypeInfos));
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest113
 * @tc.desc: Test SetGlobalOsAccountConstraints PermissionCheck failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceNoPermissionModuleTest, OsAccountManagerServiceModuleTest113, TestSize.Level1)
{
    setuid(TEST_UID);
    EXPECT_EQ(ERR_ACCOUNT_COMMON_PERMISSION_DENIED,
        osAccountManagerService_->SetGlobalOsAccountConstraints(CONSTANTS_VECTOR, true, MAIN_ACCOUNT_ID, true));
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest114
 * @tc.desc: Test SetSpecificOsAccountConstraints PermissionCheck failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceNoPermissionModuleTest, OsAccountManagerServiceModuleTest114, TestSize.Level1)
{
    setuid(TEST_UID);
    EXPECT_EQ(ERR_ACCOUNT_COMMON_PERMISSION_DENIED, osAccountManagerService_->SetSpecificOsAccountConstraints(
        CONSTANTS_VECTOR, false, MAIN_ACCOUNT_ID, MAIN_ACCOUNT_ID, false));
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest115
 * @tc.desc: Test SetDefaultActivatedOsAccount PermissionCheck failed.
 * @tc.type: FUNC
 * @tc.require: issueI6AQUQ
 */
HWTEST_F(OsAccountManagerServiceNoPermissionModuleTest, OsAccountManagerServiceModuleTest115, TestSize.Level1)
{
    setuid(TEST_UID);
    EXPECT_EQ(ERR_ACCOUNT_COMMON_PERMISSION_DENIED,
        osAccountManagerService_->SetDefaultActivatedOsAccount(MAIN_ACCOUNT_ID));
}

/**
 * @tc.name: OsAccountManagerServiceModuleTest116
 * @tc.desc: Test GetDefaultActivatedOsAccount PermissionCheck failed.
 * @tc.type: FUNC
 * @tc.require: issueI6AQUQ
 */
HWTEST_F(OsAccountManagerServiceNoPermissionModuleTest, OsAccountManagerServiceModuleTest116, TestSize.Level1)
{
    setuid(TEST_UID);
    int id;
    EXPECT_NE(ERR_ACCOUNT_COMMON_PERMISSION_DENIED,
        osAccountManagerService_->GetDefaultActivatedOsAccount(id));
    EXPECT_EQ(id, MAIN_ACCOUNT_ID);
}

#ifdef DOMAIN_ACCOUNT_TEST_CASE
/**
 * @tc.name: OsAccountManagerServiceModuleTest119
 * @tc.desc: test CreateOsAccountForDomain permission error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerServiceNoPermissionModuleTest, OsAccountManagerServiceModuleTest119, TestSize.Level1)
{
    setuid(ACCOUNT_UID);
    DomainAccountInfo domainInfo;
    EXPECT_EQ(osAccountManagerService_->CreateOsAccountForDomain(OsAccountType::NORMAL, domainInfo, nullptr),
        ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    setuid(ROOT_UID);
}
#endif // DOMAIN_ACCOUNT_TEST_CASE
}  // namespace AccountSA
}  // namespace OHOS