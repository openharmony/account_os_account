/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include <filesystem>
#include <gtest/gtest.h>
#include <gtest/hwext/gtest-multithread.h>
#include <map>
#include <string>

#include "account_error_no.h"
#include "errors.h"
#include "os_account_constants.h"
#include "os_account_manager.h"
#include "os_account_interface.h"
#include "os_account_info.h"
#include "account_log_wrapper.h"
#define private public
#include "account_file_watcher_manager.h"
#include "os_account_control_file_manager.h"
#undef private
#include "os_account_subscribe_manager.h"
#ifdef BUNDLE_ADAPTER_MOCK
#define private public
#include "os_account.h"
#include "os_account_manager_service.h"
#include "os_account_plugin_manager.h"
#include "os_account_proxy.h"
#undef private
#endif
#include "mock_os_account_control_file_manager.h"
#include "mock_os_account_dlfcn.h"
#include <sys/types.h>
#include <unistd.h>

namespace OHOS {
namespace AccountSA {
using namespace testing;
using namespace testing::ext;
using namespace testing::mt;
using namespace OHOS::AccountSA;
using namespace OHOS;
using namespace AccountSA;
using namespace OHOS::AccountSA::Constants;

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

const int TEST_USER_ID10 = 10;
const int TEST_USER_ID55 = 55;
const int TEST_USER_ID100 = 100;
const int TEST_USER_ID108 = 108;
const int THREAD_NUM = 10;
const std::int32_t MAIN_ACCOUNT_ID = 100;

OsAccountInfo osAccountInfo;
const std::string STRING_PHOTO_MAX(1024 * 1024, '1');  // length 1024*1024*10+1

const std::string STRING_TEST_NAME = "test_account_name";
const std::string STRING_DOMAIN_NAME_OUT_OF_RANGE(200, '1');  // length 200
const std::string STRING_DOMAIN_ACCOUNT_NAME_OUT_OF_RANGE(600, '1');  // length 600
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
const int ACCOUNT_UID = 3058;
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS
const std::string STRING_DOMAIN_VALID = "TestDomainMT";
const std::string STRING_DOMAIN_ACCOUNT_NAME_VALID = "TestDomainAccountNameMT";
OsAccountControlFileManager *g_controlManager = new (std::nothrow) OsAccountControlFileManager();

bool operator==(const ConstraintSourceTypeInfo &left, const ConstraintSourceTypeInfo &right)
{
    return left.localId == right.localId && left.typeInfo == right.typeInfo;
}

class OsAccountInnerAccmgrMockTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
public:
    IInnerOsAccountManager *innerMgrService_ = &IInnerOsAccountManager::GetInstance();
};

class MockDomainAccountCallback {
public:
    MOCK_METHOD2(OnResult, void(int32_t resultCode, Parcel &parcel));
};

class MockDomainAccountCallbackStub : public DomainAccountCallbackStub {
public:
    explicit MockDomainAccountCallbackStub(const std::shared_ptr<MockDomainAccountCallback> &callback);
    virtual ~MockDomainAccountCallbackStub();
    void OnResult(const int32_t errCode, Parcel &parcel) override;
    std::condition_variable cv;
    bool isReady = false;
    std::mutex mutex;

private:
    std::shared_ptr<MockDomainAccountCallback> innerCallback_;
};

void OsAccountInnerAccmgrMockTest::SetUpTestCase(void)
{
#ifdef ACCOUNT_TEST
    AccountFileOperator osAccountFileOperator;
    osAccountFileOperator.DeleteDirOrFile(USER_INFO_BASE);
    GTEST_LOG_(INFO) << "delete account test path " << USER_INFO_BASE;
#endif  // ACCOUNT_TEST
    IInnerOsAccountManager *innerMgrService = &IInnerOsAccountManager::GetInstance();
    std::shared_ptr<OsAccountControlFileManager> osAccountControl =
        std::static_pointer_cast<OsAccountControlFileManager>(innerMgrService->osAccountControl_);
    osAccountControl->eventCallbackFunc_ = nullptr;
    for (auto &fileNameMgr : osAccountControl->accountFileWatcherMgr_.fileNameMgrMap_) {
        fileNameMgr.second->eventCallbackFunc_ = nullptr;
    }
#ifdef BUNDLE_ADAPTER_MOCK
    auto osAccountService = new (std::nothrow) OsAccountManagerService();
    ASSERT_NE(osAccountService, nullptr);
    IInnerOsAccountManager::GetInstance().Init();
    IInnerOsAccountManager::GetInstance().ActivateDefaultOsAccount();
    OsAccount::GetInstance().proxy_ = new (std::nothrow) OsAccountProxy(osAccountService->AsObject());
    ASSERT_NE(OsAccount::GetInstance().proxy_, nullptr);
#endif
}

void OsAccountInnerAccmgrMockTest::TearDownTestCase(void)
{
#ifdef ACCOUNT_TEST
    AccountFileOperator osAccountFileOperator;
    osAccountFileOperator.DeleteDirOrFile(USER_INFO_BASE);
    GTEST_LOG_(INFO) << "delete account test path " << USER_INFO_BASE;
#endif  // ACCOUNT_TEST
}

void OsAccountInnerAccmgrMockTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void OsAccountInnerAccmgrMockTest::TearDown(void)
{}

/*
 * @tc.name: CreateOsAccount001
 * @tc.desc: Create os account without shortname successfully and save status to account_info.json
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, CreateOsAccount001, TestSize.Level1)
{
    OsAccountInfo createInfo;
    EXPECT_EQ(ERR_OK, innerMgrService_->CreateOsAccount("CreateOsAccount001", NORMAL, createInfo));
    EXPECT_TRUE(createInfo.GetLocalId() > START_USER_ID);

    // account info has been saved to account_info.json
    OsAccountInfo accountInfo;
    EXPECT_EQ(ERR_OK, innerMgrService_->GetOsAccountInfoById(createInfo.GetLocalId(), accountInfo));

    // some status
    EXPECT_EQ(accountInfo.ToString(), createInfo.ToString());
    EXPECT_EQ(accountInfo.GetLocalId(), createInfo.GetLocalId());
    EXPECT_EQ(accountInfo.GetLocalName(), "CreateOsAccount001");
    EXPECT_EQ(accountInfo.GetShortName(), "");
    EXPECT_EQ(accountInfo.GetType(), NORMAL);
    EXPECT_FALSE(accountInfo.GetIsVerified());
    EXPECT_TRUE(accountInfo.GetPhoto().empty());
    EXPECT_TRUE(accountInfo.GetCreateTime() > 0);
    EXPECT_EQ(accountInfo.GetLastLoginTime(), 0);
    EXPECT_TRUE(accountInfo.GetSerialNumber() > 0);
    EXPECT_FALSE(accountInfo.GetIsActived());
    EXPECT_TRUE(accountInfo.GetIsCreateCompleted());
    EXPECT_FALSE(accountInfo.GetToBeRemoved());
    EXPECT_EQ(accountInfo.GetCredentialId(), 0);
    EXPECT_EQ(accountInfo.GetDisplayId(), -1);
    EXPECT_FALSE(accountInfo.GetIsForeground());
    EXPECT_FALSE(accountInfo.GetIsLoggedIn());

    // constraints has been saved to base_os_account_constraints.json
    std::vector<std::string> constraintsByType;
    EXPECT_EQ(ERR_OK, innerMgrService_->osAccountControl_->GetConstraintsByType(NORMAL, constraintsByType));
    EXPECT_THAT(accountInfo.GetConstraints(), testing::ElementsAreArray(constraintsByType));
    Json constraintsFromFileJson;
    EXPECT_EQ(ERR_OK, g_controlManager->GetBaseOAConstraintsFromFile(constraintsFromFileJson));
    std::vector<std::string> constraintsFromFile;
    GetDataByType<std::vector<std::string>>(constraintsFromFileJson, constraintsFromFileJson.end(),
        std::to_string(accountInfo.GetLocalId()), constraintsFromFile, JsonType::ARRAY);
    EXPECT_THAT(accountInfo.GetConstraints(), testing::ElementsAreArray(constraintsFromFile));

    // account index has been saved to account_index_info.json
    Json accountIndexJson;
    EXPECT_EQ(ERR_OK, innerMgrService_->osAccountControl_->GetAccountIndexFromFile(accountIndexJson));
    auto iter = accountIndexJson.find(std::to_string(accountInfo.GetLocalId()));
    bool isExist = (iter != accountIndexJson.end());
    EXPECT_TRUE(isExist);
    if (isExist) {
        EXPECT_EQ(iter.value()[Constants::LOCAL_NAME].get<std::string>(), accountInfo.GetLocalName());
    }
    EXPECT_EQ(ERR_OK, innerMgrService_->RemoveOsAccount(accountInfo.GetLocalId()));
}

/*
 * @tc.name: CreateOsAccount002
 * @tc.desc: Create os account with shortname successfully and save status to account_info.json
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, CreateOsAccount002, TestSize.Level1)
{
    OsAccountInfo createInfo;
    EXPECT_EQ(ERR_OK, innerMgrService_->CreateOsAccount("CreateOsAccount001", "CreateOsAccount001ShortName", NORMAL,
                                                        createInfo));
    EXPECT_TRUE(createInfo.GetLocalId() > START_USER_ID);
    OsAccountInfo accountInfo;
    EXPECT_EQ(ERR_OK, innerMgrService_->GetOsAccountInfoById(createInfo.GetLocalId(), accountInfo));

    // some status
    EXPECT_EQ(accountInfo.ToString(), createInfo.ToString());
    EXPECT_EQ(accountInfo.GetLocalId(), createInfo.GetLocalId());
    EXPECT_EQ(accountInfo.GetLocalName(), "CreateOsAccount001");
    EXPECT_EQ(accountInfo.GetShortName(), "CreateOsAccount001ShortName");
    EXPECT_EQ(accountInfo.GetType(), NORMAL);
    EXPECT_FALSE(accountInfo.GetIsVerified());
    EXPECT_TRUE(accountInfo.GetPhoto().empty());
    EXPECT_TRUE(accountInfo.GetCreateTime() > 0);
    EXPECT_EQ(accountInfo.GetLastLoginTime(), 0);
    EXPECT_TRUE(accountInfo.GetSerialNumber() > 0);
    EXPECT_FALSE(accountInfo.GetIsActived());
    EXPECT_TRUE(accountInfo.GetIsCreateCompleted());
    EXPECT_FALSE(accountInfo.GetToBeRemoved());
    EXPECT_EQ(accountInfo.GetCredentialId(), 0);
    EXPECT_EQ(accountInfo.GetDisplayId(), -1);
    EXPECT_FALSE(accountInfo.GetIsForeground());
    EXPECT_FALSE(accountInfo.GetIsLoggedIn());

    // constraints has been saved to base_os_account_constraints.json
    std::vector<std::string> constraintsByType;
    EXPECT_EQ(ERR_OK, innerMgrService_->osAccountControl_->GetConstraintsByType(NORMAL, constraintsByType));
    EXPECT_THAT(accountInfo.GetConstraints(), testing::ElementsAreArray(constraintsByType));
    Json constraintsFromFileJson;
    EXPECT_EQ(ERR_OK, g_controlManager->GetBaseOAConstraintsFromFile(constraintsFromFileJson));
    std::vector<std::string> constraintsFromFile;
    GetDataByType<std::vector<std::string>>(constraintsFromFileJson, constraintsFromFileJson.end(),
        std::to_string(accountInfo.GetLocalId()), constraintsFromFile, JsonType::ARRAY);
    EXPECT_THAT(accountInfo.GetConstraints(), testing::ElementsAreArray(constraintsFromFile));

    // account index has been saved to account_index_info.json
    Json accountIndexJson;
    EXPECT_EQ(ERR_OK, innerMgrService_->osAccountControl_->GetAccountIndexFromFile(accountIndexJson));
    auto iter = accountIndexJson.find(std::to_string(accountInfo.GetLocalId()));
    bool isExist = (iter != accountIndexJson.end());
    EXPECT_TRUE(isExist);
    if (isExist) {
        EXPECT_EQ(iter.value()[Constants::LOCAL_NAME].get<std::string>(), accountInfo.GetLocalName());
    }
    EXPECT_EQ(ERR_OK, innerMgrService_->RemoveOsAccount(accountInfo.GetLocalId()));
}

/*
 * @tc.name: CreateOsAccountWithFullInfo001
 * @tc.desc: Create os account with full info successfully and save status to account_info.json
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, CreateOsAccountWithFullInfo001, TestSize.Level1)
{
    OsAccountInfo createInfo;
    createInfo.SetLocalName("CreateOsAccountWithFullInfo001");
    createInfo.SetShortName("CreateOsAccountWithFullInfo001ShortName");
    createInfo.SetType(NORMAL);
    createInfo.SetLocalId(999);
    createInfo.SetSerialNumber(1100); // this will not take effect
    createInfo.SetPhoto("test photo");
    createInfo.SetCreateTime(1695883215000);
    createInfo.SetConstraints({"test constraints"});
    EXPECT_EQ(ERR_OK, innerMgrService_->CreateOsAccountWithFullInfo(createInfo));
    OsAccountInfo accountInfo;
    EXPECT_EQ(ERR_OK, innerMgrService_->GetOsAccountInfoById(999, accountInfo));

    // some status
    EXPECT_EQ(accountInfo.ToString(), createInfo.ToString());
    EXPECT_EQ(accountInfo.GetLocalId(), 999);
    EXPECT_EQ(accountInfo.GetLocalName(), "CreateOsAccountWithFullInfo001");
    EXPECT_EQ(accountInfo.GetShortName(), "CreateOsAccountWithFullInfo001ShortName");
    EXPECT_EQ(accountInfo.GetType(), NORMAL);
    EXPECT_FALSE(accountInfo.GetIsVerified());
    EXPECT_EQ(accountInfo.GetPhoto(), "test photo");
    EXPECT_EQ(accountInfo.GetCreateTime(), 1695883215000);
    EXPECT_EQ(accountInfo.GetLastLoginTime(), 0);
    EXPECT_TRUE(accountInfo.GetSerialNumber() > 0);
    EXPECT_FALSE(accountInfo.GetIsActived());
    EXPECT_TRUE(accountInfo.GetIsCreateCompleted());
    EXPECT_FALSE(accountInfo.GetToBeRemoved());
    EXPECT_EQ(accountInfo.GetCredentialId(), 0);
    EXPECT_EQ(accountInfo.GetDisplayId(), -1);
    EXPECT_FALSE(accountInfo.GetIsForeground());
    EXPECT_FALSE(accountInfo.GetIsLoggedIn());

    // constraints has been saved to base_os_account_constraints.json
    std::vector<std::string> constraintsByType;
    EXPECT_EQ(ERR_OK, innerMgrService_->osAccountControl_->GetConstraintsByType(NORMAL, constraintsByType));
    constraintsByType.emplace_back("test constraints");
    EXPECT_THAT(accountInfo.GetConstraints(), testing::ElementsAreArray(constraintsByType));
    Json constraintsFromFileJson;
    EXPECT_EQ(ERR_OK, g_controlManager->GetBaseOAConstraintsFromFile(constraintsFromFileJson));
    std::vector<std::string> constraintsFromFile;
    GetDataByType<std::vector<std::string>>(constraintsFromFileJson, constraintsFromFileJson.end(),
        std::to_string(accountInfo.GetLocalId()), constraintsFromFile, JsonType::ARRAY);
    EXPECT_THAT(accountInfo.GetConstraints(), testing::ElementsAreArray(constraintsFromFile));

    // account index has been saved to account_index_info.json
    Json accountIndexJson;
    EXPECT_EQ(ERR_OK, innerMgrService_->osAccountControl_->GetAccountIndexFromFile(accountIndexJson));
    auto iter = accountIndexJson.find(std::to_string(accountInfo.GetLocalId()));
    bool isExist = (iter != accountIndexJson.end());
    EXPECT_TRUE(isExist);
    if (isExist) {
        EXPECT_EQ(iter.value()[Constants::LOCAL_NAME].get<std::string>(), accountInfo.GetLocalName());
    }
    EXPECT_EQ(ERR_OK, innerMgrService_->RemoveOsAccount(accountInfo.GetLocalId()));
}

/*
 * @tc.name: UpdateOsAccountWithFullInfo001
 * @tc.desc: Update os account with full info successfully and save status to account_info.json
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, UpdateOsAccountWithFullInfo001, TestSize.Level1)
{
    OsAccountInfo createInfo;
    EXPECT_EQ(ERR_OK, innerMgrService_->CreateOsAccount("UpdateOsAccountWithFullInfo001",
                                                        "UpdateOsAccountWithFullInfo001ShortName", NORMAL, createInfo));
    EXPECT_TRUE(createInfo.GetLocalId() > START_USER_ID);

    OsAccountInfo updateInfo;
    updateInfo.SetLocalName("UpdateOsAccountWithFullInfo001Change");
    updateInfo.SetShortName("UpdateOsAccountWithFullInfo001ShortNameChange"); // short name is unchangeable
    updateInfo.SetType(GUEST);
    updateInfo.SetLocalId(createInfo.GetLocalId());
    updateInfo.SetPhoto("test photo");
    updateInfo.SetConstraints({"test constraints"});
    EXPECT_EQ(ERR_OK, innerMgrService_->UpdateOsAccountWithFullInfo(updateInfo));

    // account info has been saved to account_info.json
    OsAccountInfo accountInfo;
    EXPECT_EQ(ERR_OK, innerMgrService_->GetOsAccountInfoById(createInfo.GetLocalId(), accountInfo));

    // some status
    EXPECT_EQ(accountInfo.ToString(), updateInfo.ToString());
    EXPECT_EQ(accountInfo.GetLocalId(), createInfo.GetLocalId());
    EXPECT_EQ(accountInfo.GetLocalName(), "UpdateOsAccountWithFullInfo001Change");
    EXPECT_EQ(accountInfo.GetShortName(), "UpdateOsAccountWithFullInfo001ShortName");
    EXPECT_EQ(accountInfo.GetType(), GUEST);
    EXPECT_FALSE(accountInfo.GetIsVerified());
    EXPECT_EQ(accountInfo.GetPhoto(), "test photo");
    EXPECT_TRUE(accountInfo.GetCreateTime() > 0);
    EXPECT_EQ(accountInfo.GetLastLoginTime(), 0);
    EXPECT_TRUE(accountInfo.GetSerialNumber() > 0);
    EXPECT_FALSE(accountInfo.GetIsActived());
    EXPECT_TRUE(accountInfo.GetIsCreateCompleted());
    EXPECT_FALSE(accountInfo.GetToBeRemoved());
    EXPECT_EQ(accountInfo.GetCredentialId(), 0);
    EXPECT_EQ(accountInfo.GetDisplayId(), -1);
    EXPECT_FALSE(accountInfo.GetIsForeground());
    EXPECT_FALSE(accountInfo.GetIsLoggedIn());

    // constraints has been saved to base_os_account_constraints.json
    EXPECT_THAT(accountInfo.GetConstraints(), testing::ElementsAreArray({"test constraints"}));
    Json constraintsFromFileJson;
    EXPECT_EQ(ERR_OK, g_controlManager->GetBaseOAConstraintsFromFile(constraintsFromFileJson));
    std::vector<std::string> constraintsFromFile;
    GetDataByType<std::vector<std::string>>(constraintsFromFileJson, constraintsFromFileJson.end(),
        std::to_string(accountInfo.GetLocalId()), constraintsFromFile, JsonType::ARRAY);

    // account index has been saved to account_index_info.json
    Json accountIndexJson;
    EXPECT_EQ(ERR_OK, innerMgrService_->osAccountControl_->GetAccountIndexFromFile(accountIndexJson));
    auto iter = accountIndexJson.find(std::to_string(accountInfo.GetLocalId()));
    bool isExist = (iter != accountIndexJson.end());
    EXPECT_TRUE(isExist);
    if (isExist) {
        EXPECT_EQ(iter.value()[Constants::LOCAL_NAME].get<std::string>(), accountInfo.GetLocalName());
    }
    EXPECT_EQ(ERR_OK, innerMgrService_->RemoveOsAccount(accountInfo.GetLocalId()));
}

/*
 * @tc.name: RemoveOsAccount001
 * @tc.desc: Remove background os account successfully and update status in
 * account_info.json/base_os_account_constraints.json/account_index_info.json
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, RemoveOsAccount001, TestSize.Level1)
{
    OsAccountInfo createInfo;
    EXPECT_EQ(ERR_OK, innerMgrService_->CreateOsAccount("RemoveOsAccount001", NORMAL, createInfo));
    EXPECT_TRUE(createInfo.GetLocalId() > START_USER_ID);

    // account info has been saved to account_info.json
    OsAccountInfo accountInfo;
    EXPECT_EQ(ERR_OK, innerMgrService_->GetOsAccountInfoById(createInfo.GetLocalId(), accountInfo));

    // constraints has been saved to base_os_account_constraints.json
    std::vector<std::string> constraintsByType;
    EXPECT_EQ(ERR_OK, innerMgrService_->osAccountControl_->GetConstraintsByType(NORMAL, constraintsByType));
    EXPECT_THAT(accountInfo.GetConstraints(), testing::ElementsAreArray(constraintsByType));
    Json constraintsFromFileJson;
    EXPECT_EQ(ERR_OK, g_controlManager->GetBaseOAConstraintsFromFile(constraintsFromFileJson));
    std::vector<std::string> constraintsFromFile;
    GetDataByType<std::vector<std::string>>(constraintsFromFileJson, constraintsFromFileJson.end(),
        std::to_string(accountInfo.GetLocalId()), constraintsFromFile, JsonType::ARRAY);
    EXPECT_THAT(accountInfo.GetConstraints(), testing::ElementsAreArray(constraintsFromFile));

    // account index has been saved to account_index_info.json
    Json accountIndexJson;
    EXPECT_EQ(ERR_OK, innerMgrService_->osAccountControl_->GetAccountIndexFromFile(accountIndexJson));
    auto iter = accountIndexJson.find(std::to_string(accountInfo.GetLocalId()));
    bool isExist = (iter != accountIndexJson.end());
    EXPECT_TRUE(isExist);
    if (isExist) {
        EXPECT_EQ(iter.value()[Constants::LOCAL_NAME].get<std::string>(), accountInfo.GetLocalName());
    }

    EXPECT_EQ(ERR_OK, innerMgrService_->RemoveOsAccount(accountInfo.GetLocalId()));

    // account info in account_info.json has been erased
    EXPECT_EQ(ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR,
              innerMgrService_->GetOsAccountInfoById(accountInfo.GetLocalId(), createInfo));

    // constraints in base_os_account_constraints.json has been erased
    EXPECT_EQ(ERR_OK, g_controlManager->GetBaseOAConstraintsFromFile(constraintsFromFileJson));
    constraintsFromFile.clear();
    GetDataByType<std::vector<std::string>>(constraintsFromFileJson, constraintsFromFileJson.end(),
        std::to_string(accountInfo.GetLocalId()), constraintsFromFile, JsonType::ARRAY);
    EXPECT_TRUE(constraintsFromFile.empty());

    // account index in account_index_info.json has been erased
    EXPECT_EQ(ERR_OK, innerMgrService_->osAccountControl_->GetAccountIndexFromFile(accountIndexJson));
    iter = accountIndexJson.find(std::to_string(accountInfo.GetLocalId()));
    EXPECT_EQ(iter, accountIndexJson.end());
}

/*
 * @tc.name: RemoveOsAccount002
 * @tc.desc: Remove foreground os account successfully and update status in
 * account_info.json/base_os_account_constraints.json/account_index_info.json
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, RemoveOsAccount002, TestSize.Level1)
{
    OsAccountInfo createInfo;
    EXPECT_EQ(ERR_OK, innerMgrService_->CreateOsAccount("RemoveOsAccount002", NORMAL, createInfo));
    EXPECT_TRUE(createInfo.GetLocalId() > START_USER_ID);

    // account info has been saved to account_info.json
    OsAccountInfo accountInfo;
    EXPECT_EQ(ERR_OK, innerMgrService_->GetOsAccountInfoById(createInfo.GetLocalId(), accountInfo));

    // constraints has been saved to base_os_account_constraints.json
    std::vector<std::string> constraintsByType;
    EXPECT_EQ(ERR_OK, innerMgrService_->osAccountControl_->GetConstraintsByType(NORMAL, constraintsByType));
    EXPECT_THAT(accountInfo.GetConstraints(), testing::ElementsAreArray(constraintsByType));
    Json constraintsFromFileJson;
    EXPECT_EQ(ERR_OK, g_controlManager->GetBaseOAConstraintsFromFile(constraintsFromFileJson));
    std::vector<std::string> constraintsFromFile;
    GetDataByType<std::vector<std::string>>(constraintsFromFileJson, constraintsFromFileJson.end(),
        std::to_string(accountInfo.GetLocalId()), constraintsFromFile, JsonType::ARRAY);
    EXPECT_THAT(accountInfo.GetConstraints(), testing::ElementsAreArray(constraintsFromFile));

    // account index has been saved to account_index_info.json
    Json accountIndexJson;
    EXPECT_EQ(ERR_OK, innerMgrService_->osAccountControl_->GetAccountIndexFromFile(accountIndexJson));
    auto iter = accountIndexJson.find(std::to_string(accountInfo.GetLocalId()));
    bool isExist = (iter != accountIndexJson.end());
    EXPECT_TRUE(isExist);
    if (isExist) {
        EXPECT_EQ(iter.value()[Constants::LOCAL_NAME].get<std::string>(), accountInfo.GetLocalName());
    }

    EXPECT_EQ(ERR_OK, innerMgrService_->ActivateOsAccount(accountInfo.GetLocalId()));
    int id = 0;
    EXPECT_EQ(ERR_OK, innerMgrService_->GetForegroundOsAccountLocalId(0, id));
    EXPECT_EQ(accountInfo.GetLocalId(), id);
    EXPECT_EQ(ERR_OK, innerMgrService_->RemoveOsAccount(accountInfo.GetLocalId()));
    EXPECT_EQ(ERR_OK, innerMgrService_->GetForegroundOsAccountLocalId(0, id));
    EXPECT_EQ(START_USER_ID, id);

    // account info in account_info.json has been erased
    EXPECT_EQ(ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR,
              innerMgrService_->GetOsAccountInfoById(accountInfo.GetLocalId(), createInfo));

    // constraints in base_os_account_constraints.json has been erased
    EXPECT_EQ(ERR_OK, g_controlManager->GetBaseOAConstraintsFromFile(constraintsFromFileJson));
    constraintsFromFile.clear();
    GetDataByType<std::vector<std::string>>(constraintsFromFileJson, constraintsFromFileJson.end(),
        std::to_string(accountInfo.GetLocalId()), constraintsFromFile, JsonType::ARRAY);
    EXPECT_TRUE(constraintsFromFile.empty());

    // account index in account_index_info.json has been erased
    EXPECT_EQ(ERR_OK, innerMgrService_->osAccountControl_->GetAccountIndexFromFile(accountIndexJson));
    iter = accountIndexJson.find(std::to_string(accountInfo.GetLocalId()));
    EXPECT_EQ(iter, accountIndexJson.end());
}

/*
 * @tc.name: AccountStatusTest001
 * @tc.desc: Get os account status and info successfully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, AccountStatusTest001, TestSize.Level1)
{
    OsAccountInfo createInfo;
    createInfo.SetLocalName("AccountStatusTest001");
    createInfo.SetShortName("AccountStatusTest001ShortName");
    createInfo.SetType(NORMAL);
    createInfo.SetLocalId(999);
    createInfo.SetSerialNumber(1100); // this will not take effect
    createInfo.SetPhoto("test photo");
    createInfo.SetCreateTime(1695883215000);
    createInfo.SetConstraints({"test constraints"});
    EXPECT_EQ(ERR_OK, innerMgrService_->CreateOsAccountWithFullInfo(createInfo));

    OsAccountInfo accountInfo;
    int id = createInfo.GetLocalId();
    EXPECT_EQ(ERR_OK, innerMgrService_->QueryOsAccountById(id, accountInfo));

    bool status = false;
    EXPECT_EQ(ERR_OK, innerMgrService_->IsOsAccountExists(id, status));
    EXPECT_TRUE(status);
    EXPECT_EQ(ERR_OK, innerMgrService_->IsOsAccountActived(id, status));
    EXPECT_FALSE(status);
    EXPECT_EQ(ERR_OK, innerMgrService_->IsOsAccountCompleted(id, status));
    EXPECT_TRUE(status);
    EXPECT_EQ(ERR_OK, innerMgrService_->IsOsAccountConstraintEnable(id, "test constraints", status));
    EXPECT_TRUE(status);
    EXPECT_EQ(ERR_OK, innerMgrService_->IsOsAccountConstraintEnable(id, "no constraints", status));
    EXPECT_FALSE(status);
    EXPECT_EQ(ERR_OK, innerMgrService_->IsOsAccountVerified(id, status));
    EXPECT_FALSE(status);

    std::string resStr;
    EXPECT_EQ(ERR_OK, innerMgrService_->GetOsAccountShortName(id, resStr));
    EXPECT_EQ("AccountStatusTest001ShortName", resStr);
    EXPECT_EQ(ERR_OK, innerMgrService_->GetOsAccountName(id, resStr));
    EXPECT_EQ("AccountStatusTest001", resStr);
    EXPECT_EQ(ERR_OK, innerMgrService_->GetOsAccountProfilePhoto(id, resStr));
    EXPECT_EQ("test photo", resStr);

    OsAccountType type;
    EXPECT_EQ(ERR_OK, innerMgrService_->GetOsAccountType(id, type));
    EXPECT_EQ(NORMAL, type);
    int localId;
    EXPECT_EQ(ERR_OK, innerMgrService_->GetOsAccountLocalIdBySerialNumber(accountInfo.GetSerialNumber(), localId));
    EXPECT_EQ(accountInfo.GetLocalId(), localId);
    int64_t serialNumber;
    EXPECT_EQ(ERR_OK, innerMgrService_->GetSerialNumberByOsAccountLocalId(id, serialNumber));
    EXPECT_EQ(accountInfo.GetSerialNumber(), serialNumber);
    uint64_t credentialId;
    EXPECT_EQ(ERR_OK, innerMgrService_->GetOsAccountCredentialId(id, credentialId));
    EXPECT_EQ(0, credentialId);

    EXPECT_EQ(ERR_OK, innerMgrService_->RemoveOsAccount(id));
}

/*
 * @tc.name: AccountStatusTest002
 * @tc.desc: Get os account all constraints successfully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, AccountStatusTest002, TestSize.Level1)
{
    unsigned int countBefore = 0;
    EXPECT_EQ(ERR_OK, innerMgrService_->GetCreatedOsAccountsCount(countBefore));
    std::vector<OsAccountInfo> osAccountInfosBefore;
    EXPECT_EQ(ERR_OK, innerMgrService_->QueryAllCreatedOsAccounts(osAccountInfosBefore));

    OsAccountInfo createInfo;
    createInfo.SetLocalName("AccountStatusTest002");
    createInfo.SetType(NORMAL);
    createInfo.SetLocalId(999);
    createInfo.SetCreateTime(1695883215000);
    createInfo.SetConstraints({"test constraints"});
    EXPECT_EQ(ERR_OK, innerMgrService_->CreateOsAccountWithFullInfo(createInfo));

    OsAccountInfo accountInfo;
    int id = createInfo.GetLocalId();
    EXPECT_EQ(ERR_OK, innerMgrService_->QueryOsAccountById(id, accountInfo));

    unsigned int countAfter = 0;
    EXPECT_EQ(ERR_OK, innerMgrService_->GetCreatedOsAccountsCount(countAfter));
    EXPECT_EQ(countAfter, countBefore + 1);
    std::vector<OsAccountInfo> osAccountInfosAfter;
    EXPECT_EQ(ERR_OK, innerMgrService_->QueryAllCreatedOsAccounts(osAccountInfosAfter));
    EXPECT_EQ(osAccountInfosBefore.size() + 1, osAccountInfosAfter.size());
    std::vector<std::string> constraints;
    EXPECT_EQ(ERR_OK, innerMgrService_->GetOsAccountAllConstraints(id, constraints));
    EXPECT_THAT(accountInfo.GetConstraints(), testing::ElementsAreArray(constraints));

    EXPECT_EQ(ERR_OK, innerMgrService_->RemoveOsAccount(id));
}

/*
 * @tc.name: SetOsAccountName001
 * @tc.desc: Set os account name successfully and save to account_info.json/account_index_info.json
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, SetOsAccountName001, TestSize.Level1)
{
    OsAccountInfo createInfo;
    EXPECT_EQ(ERR_OK, innerMgrService_->CreateOsAccount("SetOsAccountName001", NORMAL, createInfo));
    EXPECT_TRUE(createInfo.GetLocalId() > START_USER_ID);

    EXPECT_EQ(ERR_OK, innerMgrService_->SetOsAccountName(createInfo.GetLocalId(), "SetOsAccountName001After"));

    // account info has been saved to account_info.json
    OsAccountInfo accountInfo;
    EXPECT_EQ(ERR_OK, innerMgrService_->GetOsAccountInfoById(createInfo.GetLocalId(), accountInfo));
    createInfo.SetLocalName("SetOsAccountName001After");
    EXPECT_EQ(accountInfo.ToString(), createInfo.ToString());

    // account index has been saved to account_index_info.json
    Json accountIndexJson;
    EXPECT_EQ(ERR_OK, innerMgrService_->osAccountControl_->GetAccountIndexFromFile(accountIndexJson));
    auto iter = accountIndexJson.find(std::to_string(accountInfo.GetLocalId()));
    bool isExist = (iter != accountIndexJson.end());
    EXPECT_TRUE(isExist);
    if (isExist) {
        EXPECT_EQ(iter.value()[Constants::LOCAL_NAME].get<std::string>(), accountInfo.GetLocalName());
    }

    EXPECT_EQ(ERR_OK, innerMgrService_->RemoveOsAccount(createInfo.GetLocalId()));
}

/*
 * @tc.name: SetOsAccountConstraints001
 * @tc.desc: SetOsAccountConstraints success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, SetOsAccountConstraints001, TestSize.Level1)
{
    OsAccountInfo accountInfo;
    EXPECT_EQ(ERR_OK, innerMgrService_->CreateOsAccount("SetOsAccountConstraints001", NORMAL, accountInfo));
    int32_t localId = accountInfo.GetLocalId();
    std::vector<std::string> testConstraints = {"constraint.fun"};

    EXPECT_EQ(ERR_OK, innerMgrService_->SetBaseOsAccountConstraints(localId, testConstraints, true));
    EXPECT_EQ(ERR_OK, innerMgrService_->SetGlobalOsAccountConstraints(testConstraints, true, localId, true));
    EXPECT_EQ(ERR_OK,
        innerMgrService_->SetSpecificOsAccountConstraints(testConstraints, true, localId, TEST_USER_ID100, false));

    std::vector<ConstraintSourceTypeInfo> infos, emptyConstraintInfos{
        {-1, ConstraintSourceType::CONSTRAINT_NOT_EXIST},
    }, constraintInfos{
        {-1, ConstraintSourceType::CONSTRAINT_TYPE_BASE},
        {localId, ConstraintSourceType::CONSTRAINT_TYPE_DEVICE_OWNER},
        {TEST_USER_ID100, ConstraintSourceType::CONSTRAINT_TYPE_PROFILE_OWNER},
    };
    EXPECT_EQ(ERR_OK, innerMgrService_->QueryOsAccountConstraintSourceTypes(localId, testConstraints[0], infos));
    EXPECT_EQ(infos, constraintInfos);

    EXPECT_EQ(ERR_OK, innerMgrService_->SetBaseOsAccountConstraints(localId, testConstraints, false));
    EXPECT_EQ(ERR_OK, innerMgrService_->SetGlobalOsAccountConstraints(testConstraints, false, localId, false));
    EXPECT_EQ(ERR_OK,
        innerMgrService_->SetSpecificOsAccountConstraints(testConstraints, false, localId, TEST_USER_ID100, false));

    infos.clear();
    EXPECT_EQ(ERR_OK, innerMgrService_->QueryOsAccountConstraintSourceTypes(localId, testConstraints[0], infos));
    EXPECT_EQ(infos, emptyConstraintInfos);

    EXPECT_EQ(ERR_OK, innerMgrService_->RemoveOsAccount(localId));
}

/*
 * @tc.name: SetOsAccountInfo001
 * @tc.desc: SetOsAccountInfo success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, SetOsAccountInfo001, TestSize.Level1)
{
    OsAccountInfo createInfo;
    EXPECT_EQ(ERR_OK, innerMgrService_->CreateOsAccount("SetOsAccountInfo001", NORMAL, createInfo));
    int32_t localId = createInfo.GetLocalId();

    DomainAccountInfo createDomainInfo("test", "SetOsAccountInfo001");
    EXPECT_EQ(ERR_OK, innerMgrService_->UpdateAccountInfoByDomainAccountInfo(localId, createDomainInfo));

    OsAccountInfo accountInfo;
    DomainAccountInfo domainInfo;
    EXPECT_EQ(ERR_OK, innerMgrService_->GetOsAccountInfoById(localId, accountInfo));
    accountInfo.GetDomainInfo(domainInfo);
    EXPECT_EQ(domainInfo.accountName_, "SetOsAccountInfo001");
    EXPECT_EQ(domainInfo.status_, DomainAccountStatus::LOG_END);

    EXPECT_EQ(ERR_OK, innerMgrService_->UpdateAccountStatusForDomain(localId, DomainAccountStatus::LOGIN));
    EXPECT_EQ(ERR_OK, innerMgrService_->GetOsAccountInfoById(localId, accountInfo));
    accountInfo.GetDomainInfo(domainInfo);
    EXPECT_EQ(domainInfo.status_, DomainAccountStatus::LOGIN);

    EXPECT_EQ(ERR_OK, innerMgrService_->RemoveOsAccount(localId));
}

/*
 * @tc.name: GetOsAccountInfo001
 * @tc.desc: GetOsAccountInfo success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, GetOsAccountInfo001, TestSize.Level1)
{
    bool isAllowed = false;
    EXPECT_EQ(ERR_OK, innerMgrService_->IsAllowedCreateAdmin(isAllowed));
    EXPECT_TRUE(isAllowed);

    std::vector<int32_t> ids;
    EXPECT_EQ(ERR_OK, innerMgrService_->QueryActiveOsAccountIds(ids));
    EXPECT_EQ(ids.size(), 1);

    int32_t typeNumber = 0;
    EXPECT_EQ(ERR_OK, innerMgrService_->GetTypeNumber(ADMIN, typeNumber));
    EXPECT_EQ(typeNumber, 1);
}

/*
 * @tc.name: SetOsAccountIsVerified001
 * @tc.desc: Set os account verify status successfully and save to account_info.json
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, SetOsAccountIsVerified001, TestSize.Level1)
{
    OsAccountInfo createInfo;
    createInfo.SetLocalName("SetOsAccountIsVerified001");
    createInfo.SetType(NORMAL);
    createInfo.SetLocalId(999);
    createInfo.SetSerialNumber(1100); // this will not take effect
    createInfo.SetPhoto("test photo");
    createInfo.SetCreateTime(1695883215000);
    createInfo.SetConstraints({"test constraints"});
    EXPECT_EQ(ERR_OK, innerMgrService_->CreateOsAccountWithFullInfo(createInfo));

    int id = createInfo.GetLocalId();
    OsAccountInfo accountInfo;
    EXPECT_EQ(ERR_OK, innerMgrService_->GetOsAccountInfoById(id, accountInfo));
    EXPECT_FALSE(accountInfo.GetIsVerified());

    EXPECT_EQ(ERR_OK, innerMgrService_->SetOsAccountIsVerified(id, true));

    OsAccountInfo accountInfoAfter;
    EXPECT_EQ(ERR_OK, innerMgrService_->GetOsAccountInfoById(id, accountInfoAfter));
    EXPECT_TRUE(accountInfoAfter.GetIsVerified());

    ErrCode ret = innerMgrService_->RemoveOsAccount(createInfo.GetLocalId());
    if (ret == ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_OPERATING_ERROR) {
        sleep(1);
        EXPECT_EQ(ERR_OK, innerMgrService_->RemoveOsAccount(createInfo.GetLocalId()));
    } else {
        EXPECT_EQ(ret, ERR_OK);
    }
}

/*
 * @tc.name: SetOsAccountIsLoggedIn001
 * @tc.desc: Set os account login status successfully and save to account_info.json
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, SetOsAccountIsLoggedIn001, TestSize.Level1)
{
    OsAccountInfo createInfo;
    createInfo.SetLocalName("SetOsAccountIsLoggedIn001");
    createInfo.SetType(NORMAL);
    createInfo.SetLocalId(999);
    createInfo.SetSerialNumber(1100); // this will not take effect
    createInfo.SetPhoto("test photo");
    createInfo.SetCreateTime(1695883215000);
    createInfo.SetConstraints({"test constraints"});
    EXPECT_EQ(ERR_OK, innerMgrService_->CreateOsAccountWithFullInfo(createInfo));

    int id = createInfo.GetLocalId();
    OsAccountInfo accountInfo;
    EXPECT_EQ(ERR_OK, innerMgrService_->GetOsAccountInfoById(id, accountInfo));
    EXPECT_FALSE(accountInfo.GetIsLoggedIn());

    EXPECT_EQ(ERR_OK, innerMgrService_->SetOsAccountIsLoggedIn(id, true));

    OsAccountInfo accountInfoAfter;
    EXPECT_EQ(ERR_OK, innerMgrService_->GetOsAccountInfoById(id, accountInfoAfter));
    EXPECT_TRUE(accountInfoAfter.GetIsLoggedIn());

    EXPECT_EQ(ERR_OK, innerMgrService_->RemoveOsAccount(createInfo.GetLocalId()));
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTest001
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTest001, TestSize.Level1)
{
    innerMgrService_->CreateBaseAdminAccount();

    std::shared_ptr<IOsAccountControl> osAccountControl = innerMgrService_->osAccountControl_;
    bool isExistsAccount = false;

    osAccountControl->IsOsAccountExists(Constants::ADMIN_LOCAL_ID, isExistsAccount);
    EXPECT_EQ(true, isExistsAccount);
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTest002
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTest002, TestSize.Level1)
{
    innerMgrService_->CreateBaseStandardAccount();

    std::shared_ptr<IOsAccountControl> osAccountControl = innerMgrService_->osAccountControl_;
    bool isExistsAccount = false;

    osAccountControl->IsOsAccountExists(Constants::START_USER_ID, isExistsAccount);
    EXPECT_EQ(true, isExistsAccount);
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTest005
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTest005, TestSize.Level1)
{
    bool ret = false;

    innerMgrService_->PushIdIntoActiveList(TEST_USER_ID10);
    ret = innerMgrService_->IsOsAccountIDInActiveList(TEST_USER_ID10);
    EXPECT_EQ(ret, true);

    innerMgrService_->EraseIdFromActiveList(TEST_USER_ID10);
    ret = innerMgrService_->IsOsAccountIDInActiveList(TEST_USER_ID10);
    EXPECT_EQ(ret, false);

    innerMgrService_->EraseIdFromActiveList(TEST_USER_ID55);
    ret = innerMgrService_->IsOsAccountIDInActiveList(TEST_USER_ID55);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTest007
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTest007, TestSize.Level1)
{
    bool ret = false;
    innerMgrService_->CheckAndAddLocalIdOperating(TEST_USER_ID10);
    ret = innerMgrService_->CheckAndAddLocalIdOperating(TEST_USER_ID10);
    EXPECT_EQ(ret, false);

    innerMgrService_->RemoveLocalIdToOperating(TEST_USER_ID10);
    ret = innerMgrService_->CheckAndAddLocalIdOperating(TEST_USER_ID10);
    EXPECT_EQ(ret, true);

    innerMgrService_->RemoveLocalIdToOperating(TEST_USER_ID10);
    ret = innerMgrService_->CheckAndAddLocalIdOperating(TEST_USER_ID10);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTest008
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTest008, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();

    EXPECT_CALL(*ptr, GetOsAccountIdList(::testing::_))
        .WillRepeatedly(testing::Return(-1));

    innerMgrService_->osAccountControl_ = ptr;
    unsigned int count;
    int ret = innerMgrService_->GetCreatedOsAccountsCount(count);
    EXPECT_EQ(ret, -1);
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTest009
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTest009, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    EXPECT_CALL(*ptr, GetSerialNumber(::testing::_))
        .WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*ptr, GetAllowCreateId(::testing::_))
        .WillRepeatedly(testing::Return(-1));
    innerMgrService_->osAccountControl_ = ptr;
    std::string name;
    OsAccountType type = OsAccountType::GUEST;
    DomainAccountInfo domainInfo1(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    DomainAccountInfo domainInfo2(STRING_DOMAIN_NAME_OUT_OF_RANGE, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    OsAccountInfo accountInfo;
    int ret = innerMgrService_->PrepareOsAccountInfo(name, type, domainInfo1, accountInfo);
    innerMgrService_->RemoveLocalIdToOperating(accountInfo.GetLocalId());
    EXPECT_EQ(ret, -1);
    EXPECT_CALL(*ptr, GetAllowCreateId(::testing::_))
        .WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*ptr, GetConstraintsByType(::testing::_, ::testing::_))
        .WillRepeatedly(testing::Return(-1));
    ret = innerMgrService_->PrepareOsAccountInfo(name, type, domainInfo1, accountInfo);
    innerMgrService_->RemoveLocalIdToOperating(accountInfo.GetLocalId());
    EXPECT_NE(ret, ERR_OK);
    EXPECT_CALL(*ptr, GetConstraintsByType(::testing::_, ::testing::_))
        .WillRepeatedly(testing::Return(0));
    ret = innerMgrService_->PrepareOsAccountInfo(name, type, domainInfo2, accountInfo);
    innerMgrService_->RemoveLocalIdToOperating(accountInfo.GetLocalId());
    EXPECT_EQ(ret, ERR_OSACCOUNT_KIT_CREATE_OS_ACCOUNT_FOR_DOMAIN_ERROR);
    EXPECT_CALL(*ptr, InsertOsAccount(::testing::_))
        .WillRepeatedly(testing::Return(-1));
    ret = innerMgrService_->PrepareOsAccountInfo(name, type, domainInfo1, accountInfo);
    innerMgrService_->RemoveLocalIdToOperating(accountInfo.GetLocalId());
    EXPECT_NE(ret, ERR_OK);
    EXPECT_CALL(*ptr, InsertOsAccount(::testing::_))
        .WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*ptr, UpdateBaseOAConstraints(::testing::_, ::testing::_, ::testing::_))
        .WillRepeatedly(testing::Return(-1));
    ret = innerMgrService_->PrepareOsAccountInfo(name, type, domainInfo1, accountInfo);
    EXPECT_NE(ret, ERR_OK);
    innerMgrService_->RemoveLocalIdToOperating(accountInfo.GetLocalId());
    EXPECT_CALL(*ptr, UpdateBaseOAConstraints(::testing::_, ::testing::_, ::testing::_))
        .WillRepeatedly(testing::Return(0));
    ret = innerMgrService_->PrepareOsAccountInfo(name, type, domainInfo1, accountInfo);
    innerMgrService_->RemoveLocalIdToOperating(accountInfo.GetLocalId());
    EXPECT_EQ(ret, ERR_OK);
    innerMgrService_->RemoveOsAccount(accountInfo.GetLocalId());
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTest010
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTest010, TestSize.Level1)
{
    int ret;
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_->osAccountControl_ = ptr;

    OsAccountInfo osAccountInfoOne;
#ifdef BUNDLE_ADAPTER_MOCK
    EXPECT_NE(OsAccountManager::CreateOsAccount(STRING_TEST_NAME, OsAccountType::GUEST, osAccountInfoOne), ERR_OK);
#else // BUNDLE_ADAPTER_MOCK
    EXPECT_EQ(OsAccountManager::CreateOsAccount(STRING_TEST_NAME, OsAccountType::GUEST, osAccountInfoOne), ERR_OK);
#endif
    EXPECT_CALL(*ptr, UpdateOsAccount(::testing::_))
        .WillRepeatedly(testing::Return(0));

    ret = innerMgrService_->SendMsgForAccountCreate(osAccountInfoOne);
    EXPECT_EQ(ret, 0);

    (void)setuid(ACCOUNT_UID);

    EXPECT_CALL(*ptr, UpdateOsAccount(::testing::_))
        .WillRepeatedly(testing::Return(-1));

    ret = innerMgrService_->SendMsgForAccountCreate(osAccountInfoOne);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR);

    ret = innerMgrService_->SendMsgForAccountActivate(osAccountInfoOne);
    EXPECT_EQ(ret, ERR_OK);

    EXPECT_CALL(*ptr, UpdateOsAccount(::testing::_))
        .WillRepeatedly(testing::Return(0));

    ret = innerMgrService_->SendMsgForAccountCreate(osAccountInfoOne);
    EXPECT_EQ(ret, 0);

    EXPECT_CALL(*ptr, DelOsAccount(::testing::_))
        .WillRepeatedly(testing::Return(-1));

    ret = innerMgrService_->SendMsgForAccountRemove(osAccountInfoOne);
    EXPECT_EQ(ret, -1);

    (void)setuid(0);
#ifdef BUNDLE_ADAPTER_MOCK
    EXPECT_NE(OsAccountManager::RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
#else // BUNDLE_ADAPTER_MOCK
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
#endif
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTest012
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
#ifdef DOMAIN_ACCOUNT_TEST_CASE
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTest012, TestSize.Level1)
{
    int ret;
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_->osAccountControl_ = ptr;

    OsAccountInfo osAccountInfoOne;

    const OsAccountType type = OsAccountType::GUEST;
    const DomainAccountInfo domainInfo;

    EXPECT_CALL(*ptr, GetOsAccountIdList(::testing::_))
        .WillRepeatedly(testing::Return(0));

    EXPECT_CALL(*ptr, GetSerialNumber(::testing::_))
        .WillRepeatedly(testing::Return(0));

    EXPECT_CALL(*ptr, GetAllowCreateId(::testing::_))
        .WillRepeatedly(testing::Return(0));

    EXPECT_CALL(*ptr, GetConstraintsByType(::testing::_, ::testing::_))
        .WillRepeatedly(testing::Return(0));

    EXPECT_CALL(*ptr, InsertOsAccount(::testing::_))
        .WillRepeatedly(testing::Return(0));

    EXPECT_CALL(*ptr, UpdateBaseOAConstraints(::testing::_, ::testing::_, ::testing::_))
        .WillRepeatedly(testing::Return(0));

    EXPECT_CALL(*ptr, UpdateOsAccount(::testing::_))
        .WillRepeatedly(testing::Return(0));

    ret = innerMgrService_->CreateOsAccountForDomain(type, domainInfo, osAccountInfoOne);
    EXPECT_EQ(ret, 0);

    EXPECT_CALL(*ptr, GetOsAccountIdList(::testing::_))
        .WillRepeatedly(testing::Return(-1));

    ret = innerMgrService_->CreateOsAccountForDomain(type, domainInfo, osAccountInfoOne);
    EXPECT_NE(ret, ERR_OK);
}
#endif // DOMAIN_ACCOUNT_TEST_CASE
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/*
 * @tc.name: OsAccountInnerAccmgrMockTest013
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTest013, TestSize.Level1)
{
    int ret;
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_->osAccountControl_ = ptr;

    EXPECT_CALL(*ptr, GetOsAccountList(::testing::_))
        .WillRepeatedly(testing::Return(0));

    EXPECT_CALL(*ptr, GetSerialNumber(::testing::_))
        .WillRepeatedly(testing::Return(0));

    EXPECT_CALL(*ptr, GetAllowCreateId(::testing::_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(TEST_USER_ID108), testing::Return(0)));

    EXPECT_CALL(*ptr, GetConstraintsByType(::testing::_, ::testing::_))
        .WillRepeatedly(testing::Return(0));

    EXPECT_CALL(*ptr, InsertOsAccount(::testing::_))
        .WillRepeatedly(testing::Return(0));

    EXPECT_CALL(*ptr, UpdateBaseOAConstraints(::testing::_, ::testing::_, ::testing::_))
        .WillRepeatedly(testing::Return(0));

    EXPECT_CALL(*ptr, RemoveOAConstraintsInfo(::testing::_))
        .WillRepeatedly(testing::Return(0));

    EXPECT_CALL(*ptr, DelOsAccount(::testing::_))
        .WillRepeatedly(testing::Return(0));

    int32_t id = 0;
    innerMgrService_->CheckAndAddLocalIdOperating(id);
    ret = innerMgrService_->RemoveOsAccount(id);
    innerMgrService_->RemoveLocalIdToOperating(id);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_OPERATING_ERROR);

    EXPECT_CALL(*ptr, GetOsAccountInfoById(::testing::_, ::testing::_))
        .WillRepeatedly(testing::Return(0));

    EXPECT_CALL(*ptr, UpdateOsAccount(::testing::_))
        .WillRepeatedly(testing::Return(0));

    EXPECT_CALL(*ptr, RemoveOAConstraintsInfo(::testing::_))
        .WillRepeatedly(testing::Return(-1));

    ret = innerMgrService_->RemoveOsAccount(id);
    EXPECT_EQ(ret, -1);

    EXPECT_CALL(*ptr, RemoveOAConstraintsInfo(::testing::_))
        .WillRepeatedly(testing::Return(0));

    ret = innerMgrService_->RemoveOsAccount(id);
    EXPECT_EQ(ret, 0);
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTest015
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTest015, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    (void)setuid(ACCOUNT_UID);
    EXPECT_EQ(innerMgrService_->CreateOsAccount(STRING_TEST_NAME, OsAccountType::GUEST, osAccountInfoOne), ERR_OK);
    (void)setuid(0);
    EXPECT_EQ(innerMgrService_->RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/*
 * @tc.name: OsAccountInnerAccmgrMockTest017
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTest017, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_->osAccountControl_ = ptr;

    int id = 0;
    std::vector<std::string> constraints;

    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(testing::Return(-1));

    ErrCode ret = innerMgrService_->GetOsAccountAllConstraints(id, constraints);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);

    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(testing::Return(0));

    EXPECT_CALL(*ptr, GetGlobalOAConstraintsList(_))
        .WillRepeatedly(testing::Return(-1));

    ret = innerMgrService_->GetOsAccountAllConstraints(id, constraints);
    EXPECT_EQ(ret, -1);

    EXPECT_CALL(*ptr, GetGlobalOAConstraintsList(_))
        .WillRepeatedly(testing::Return(0));

    EXPECT_CALL(*ptr, GetSpecificOAConstraintsList(_, _))
        .WillRepeatedly(testing::Return(-1));

    ret = innerMgrService_->GetOsAccountAllConstraints(id, constraints);
    EXPECT_EQ(ret, -1);
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTest018
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTest018, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_->osAccountControl_ = ptr;

    std::vector<OsAccountInfo> accounts;

    EXPECT_CALL(*ptr, GetOsAccountIdList(_))
        .WillRepeatedly(testing::Return(-1));

    innerMgrService_->CleanGarbageOsAccounts();

    ErrCode ret = innerMgrService_->QueryAllCreatedOsAccounts(accounts);
    EXPECT_NE(ret, ERR_OK);
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTest019
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTest019, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_->osAccountControl_ = ptr;

    int id = TEST_USER_ID100;
    OsAccountInfo osAccountInfo;

    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(testing::Return(-1));

    ErrCode ret = innerMgrService_->QueryOsAccountById(id, osAccountInfo);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);

    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(testing::Return(0));

    osAccountInfo.SetPhoto("abc");

    EXPECT_CALL(*ptr, GetPhotoById(_, _))
        .WillRepeatedly(testing::Return(-1));

    ret = innerMgrService_->QueryOsAccountById(id, osAccountInfo);
    EXPECT_EQ(ret, -1);
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTest020
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTest020, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_->osAccountControl_ = ptr;

    int id = TEST_USER_ID100;
    OsAccountType type = OsAccountType::GUEST;

    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(testing::Return(-1));

    ErrCode ret = innerMgrService_->GetOsAccountType(id, type);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTest021
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTest021, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_->osAccountControl_ = ptr;

    int id = TEST_USER_ID100;
    std::string photo = "";

    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(testing::Return(-1));

    ErrCode ret = innerMgrService_->GetOsAccountProfilePhoto(id, photo);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTest022
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTest022, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_->osAccountControl_ = ptr;

    bool isMultiOsAccountEnabled = false;

    EXPECT_CALL(*ptr, GetIsMultiOsAccountEnable(_))
        .WillRepeatedly(testing::Return(-1));

    ErrCode ret = innerMgrService_->IsMultiOsAccountEnable(isMultiOsAccountEnabled);
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
    EXPECT_EQ(ret, -1);
#else
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(isMultiOsAccountEnabled, false);
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTest023
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTest023, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_->osAccountControl_ = ptr;

    int id = TEST_USER_ID100;
    std::string name = "test";

    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(testing::Return(-1));

    ErrCode ret = innerMgrService_->SetOsAccountName(id, name);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);

    OsAccountInfo osAccountInfo;
    osAccountInfo.SetToBeRemoved(true);

    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(DoAll(::testing::SetArgReferee<1>(osAccountInfo), ::testing::Return(0)));

    ret = innerMgrService_->SetOsAccountName(id, name);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_TO_BE_REMOVED_ERROR);

    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(DoAll(::testing::Return(0)));

    EXPECT_CALL(*ptr, UpdateOsAccount(_))
        .WillRepeatedly(testing::Return(-1));

    ret = innerMgrService_->SetOsAccountName(id, name);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR);
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTest024
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTest024, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_->osAccountControl_ = ptr;

    int id = TEST_USER_ID100;
    std::string name = "";
    std::vector<std::string> constraints;
    bool enable = false;

    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(testing::Return(-1));

    ErrCode ret = innerMgrService_->SetOsAccountConstraints(id, constraints, enable);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);

    OsAccountInfo osAccountInfo;
    osAccountInfo.SetToBeRemoved(true);

    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(DoAll(::testing::SetArgReferee<1>(osAccountInfo), ::testing::Return(0)));

    ret = innerMgrService_->SetOsAccountConstraints(id, constraints, enable);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_TO_BE_REMOVED_ERROR);

    EXPECT_CALL(*ptr, CheckConstraintsList(_, _, _))
        .WillRepeatedly(DoAll(::testing::Return(-1)));

    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(testing::Return(0));

    ret = innerMgrService_->SetOsAccountConstraints(id, constraints, enable);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);

    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(DoAll(::testing::Return(0)));

    EXPECT_CALL(*ptr, CheckConstraintsList(_, _, _))
        .WillRepeatedly(DoAll(::testing::SetArgReferee<1>(1), ::testing::Return(0)));

    EXPECT_CALL(*ptr, UpdateOsAccount(_))
        .WillRepeatedly(testing::Return(-1));

    ret = innerMgrService_->SetOsAccountConstraints(id, constraints, enable);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR);

    ret = innerMgrService_->SetBaseOsAccountConstraints(id, constraints, enable);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR);

    EXPECT_CALL(*ptr, UpdateOsAccount(_))
        .WillRepeatedly(testing::Return(0));

    EXPECT_CALL(*ptr, UpdateBaseOAConstraints(_, _, _))
        .WillRepeatedly(testing::Return(-1));
    ret = innerMgrService_->SetBaseOsAccountConstraints(id, constraints, enable);
    EXPECT_EQ(ret, -1);
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTest025
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTest025, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_->osAccountControl_ = ptr;

    int id = TEST_USER_ID100;
    std::string photo = "";

    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(testing::Return(-1));

    EXPECT_CALL(*ptr, SetPhotoById(_, _))
        .WillRepeatedly(testing::Return(0));

    ErrCode ret = innerMgrService_->SetOsAccountProfilePhoto(id, photo);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);

    OsAccountInfo osAccountInfo;
    osAccountInfo.SetToBeRemoved(true);

    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(DoAll(::testing::SetArgReferee<1>(osAccountInfo), ::testing::Return(0)));

    ret = innerMgrService_->SetOsAccountProfilePhoto(id, photo);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_TO_BE_REMOVED_ERROR);

    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(DoAll(::testing::Return(0)));

    EXPECT_CALL(*ptr, UpdateOsAccount(_))
        .WillRepeatedly(testing::Return(-1));

    photo += "1";
    ret = innerMgrService_->SetOsAccountProfilePhoto(id, photo);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR);
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTest026
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTest026, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_->osAccountControl_ = ptr;

    int id = TEST_USER_ID100;
    std::string photo = "";

    innerMgrService_->CheckAndAddLocalIdOperating(id);
    ErrCode ret = innerMgrService_->ActivateOsAccount(id);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_OPERATING_ERROR);
    innerMgrService_->RemoveLocalIdToOperating(id);

    OsAccountInfo expectedAccountInfo;
    expectedAccountInfo.SetIsVerified(true);
    EXPECT_CALL(*ptr, GetOsAccountInfoById(id, _))
        .WillOnce(DoAll(SetArgReferee<1>(expectedAccountInfo), Return(ERR_OK)));
    innerMgrService_->PushIdIntoActiveList(id);
    ret = innerMgrService_->ActivateOsAccount(id);
    EXPECT_NE(ret, ERR_OK);

    innerMgrService_->EraseIdFromActiveList(id);

    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(testing::Return(-1));
    ret = innerMgrService_->ActivateOsAccount(id);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);

    OsAccountInfo osAccountInfo;
    osAccountInfo.SetIsCreateCompleted(0);
    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(DoAll(testing::SetArgReferee<1>(osAccountInfo), testing::Return(0)));
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTest027
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTest027, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_->osAccountControl_ = ptr;

    int64_t serialNumber = Constants::CARRY_NUM * Constants::SERIAL_NUMBER_NUM_START_FOR_ADMIN
        + Constants::ADMIN_LOCAL_ID;
    int id = TEST_USER_ID100;
    ErrCode ret = innerMgrService_->GetOsAccountLocalIdBySerialNumber(serialNumber, id);
    EXPECT_EQ(ret, 0);

    EXPECT_CALL(*ptr, GetOsAccountList(::testing::_))
        .WillRepeatedly(testing::Return(-1));

    serialNumber = 0;
    ret = innerMgrService_->GetOsAccountLocalIdBySerialNumber(serialNumber, id);
    EXPECT_NE(ret, ERR_OK);

    EXPECT_CALL(*ptr, GetOsAccountInfoById(::testing::_, ::testing::_))
        .WillRepeatedly(testing::Return(-1));

    ret = innerMgrService_->GetSerialNumberByOsAccountLocalId(id, serialNumber);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTest029
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTest029, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_->osAccountControl_ = ptr;

    int id = TEST_USER_ID100;
    bool isVerified = false;

    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(testing::Return(-1));
    ErrCode ret = innerMgrService_->SetOsAccountIsVerified(id, isVerified);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);

    OsAccountInfo osAccountInfo;
    osAccountInfo.SetToBeRemoved(true);
    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(DoAll(testing::SetArgReferee<1>(osAccountInfo), testing::Return(0)));

    ret = innerMgrService_->SetOsAccountIsVerified(id, isVerified);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_TO_BE_REMOVED_ERROR);

    osAccountInfo.SetToBeRemoved(false);
    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(DoAll(testing::SetArgReferee<1>(osAccountInfo), testing::Return(0)));

    EXPECT_CALL(*ptr, UpdateOsAccount(::testing::_))
        .WillRepeatedly(testing::Return(-1));

    ret = innerMgrService_->SetOsAccountCredentialId(id, 0);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR);
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTest030
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTest030, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_->osAccountControl_ = ptr;

    int id = TEST_USER_ID100;

    DomainAccountInfo domainAllTooLong(STRING_DOMAIN_NAME_OUT_OF_RANGE, STRING_DOMAIN_ACCOUNT_NAME_OUT_OF_RANGE);
    ErrCode ret = innerMgrService_->GetOsAccountLocalIdFromDomain(domainAllTooLong, id);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);

    DomainAccountInfo domainAllTooLong2(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_OUT_OF_RANGE);
    ret = innerMgrService_->GetOsAccountLocalIdFromDomain(domainAllTooLong2, id);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);

    DomainAccountInfo domainInfo1(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    EXPECT_CALL(*ptr, GetOsAccountList(_))
        .WillRepeatedly(testing::Return(-1));
    ret = innerMgrService_->GetOsAccountLocalIdFromDomain(domainInfo1, id);
    EXPECT_NE(ret, ERR_OK);
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTest031
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTest031, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_->osAccountControl_ = ptr;

    int id = TEST_USER_ID100;
    const std::string constraint;
    std::vector<ConstraintSourceTypeInfo> constraintSourceTypeInfos;

    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(testing::Return(-1));

    ErrCode ret = innerMgrService_->QueryOsAccountConstraintSourceTypes(id, constraint, constraintSourceTypeInfos);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTest032
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTest032, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_->osAccountControl_ = ptr;

    const std::string constraint;
    std::vector<ConstraintSourceTypeInfo> constraintSourceTypeInfos;

    std::vector<std::string> constraints;
    bool enable = false;
    int32_t targetId = 0;
    int32_t enforcerId = 0;
    innerMgrService_-> deviceOwnerId_ = 0;
    bool isDeviceOwner = 0;

    OsAccountInfo osAccountInfo;
    osAccountInfo.SetToBeRemoved(true);
    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(DoAll(testing::SetArgReferee<1>(osAccountInfo), testing::Return(0)));
    ErrCode ret = innerMgrService_->SetGlobalOsAccountConstraints(constraints, enable, enforcerId, isDeviceOwner);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_TO_BE_REMOVED_ERROR);

    ret = innerMgrService_->SetSpecificOsAccountConstraints(constraints, enable, targetId, enforcerId, isDeviceOwner);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_TO_BE_REMOVED_ERROR);

    osAccountInfo.SetToBeRemoved(false);
    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(DoAll(testing::SetArgReferee<1>(osAccountInfo), testing::Return(0)));

    bool isExists = true;
    EXPECT_CALL(*ptr, CheckConstraintsList(_, _, _))
        .WillRepeatedly(DoAll(testing::SetArgReferee<1>(isExists), testing::Return(0)));

    EXPECT_CALL(*ptr, UpdateGlobalOAConstraints(_, _, _))
        .WillRepeatedly(DoAll(testing::Return(0)));

    EXPECT_CALL(*ptr, UpdateDeviceOwnerId(_))
        .WillRepeatedly(DoAll(testing::Return(-1)));
    ret = innerMgrService_->SetGlobalOsAccountConstraints(constraints, enable, enforcerId, isDeviceOwner);
    EXPECT_EQ(ret, -1);

    enable = false;
    targetId = 0;
    enforcerId = 0;
    innerMgrService_-> deviceOwnerId_ = 0;
    isDeviceOwner = 0;

    ret = innerMgrService_->SetSpecificOsAccountConstraints(constraints, enable, targetId, enforcerId, isDeviceOwner);
    EXPECT_EQ(ret, -1);
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTest033
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTest033, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_->osAccountControl_ = ptr;

    OsAccountInfo osAccountInfo;
    osAccountInfo.SetIsCreateCompleted(false);
    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(DoAll(testing::SetArgReferee<1>(osAccountInfo), testing::Return(-1)));

    EXPECT_CALL(*ptr, GetOsAccountIdList(::testing::_))
        .WillRepeatedly(testing::Return(0));

    (void)setuid(ACCOUNT_UID);
    innerMgrService_->ActivateDefaultOsAccount();
    (void)setuid(0);
    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(DoAll(testing::SetArgReferee<1>(osAccountInfo), testing::Return(0)));
    innerMgrService_->ActivateDefaultOsAccount();
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/*
 * @tc.name: OsAccountInnerAccmgrMockTest034
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTest034, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_->osAccountControl_ = ptr;

    std::vector<int32_t> accountIds;

    EXPECT_CALL(*ptr, GetOsAccountIdList(_))
        .WillRepeatedly(testing::Return(-1));

    innerMgrService_->RestartActiveAccount();

    OsAccountInfo account1;
    account1.SetLocalId(TEST_USER_ID55);
    account1.SetIsActived(true);
    accountIds.push_back(TEST_USER_ID55);
    innerMgrService_->PushIdIntoActiveList(TEST_USER_ID55);

    EXPECT_CALL(*ptr, GetOsAccountIdList(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(accountIds), testing::Return(0)));
    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _)).WillRepeatedly(DoAll(SetArgReferee<1>(account1), testing::Return(0)));
    innerMgrService_->RestartActiveAccount();
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTest036
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTest036, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_->osAccountControl_ = ptr;

    std::vector<OsAccountInfo> accounts;
    OsAccountInfo account1;
    account1.SetLocalId(TEST_USER_ID55);
    account1.SetIsActived(true);
    accounts.push_back(account1);
    innerMgrService_->PushIdIntoActiveList(TEST_USER_ID55);

    EXPECT_CALL(*ptr, UpdateOsAccount(::testing::_))
        .WillRepeatedly(testing::Return(0));

    EXPECT_CALL(*ptr, GetOsAccountList(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(accounts), testing::Return(0)));

    innerMgrService_->ResetAccountStatus();
    EXPECT_EQ(account1.GetIsActived(), true); // this interface has nothing to judge.

    EXPECT_CALL(*ptr, GetOsAccountList(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(accounts), testing::Return(-1)));

    innerMgrService_->ResetAccountStatus();
    EXPECT_EQ(account1.GetIsActived(), true); // this interface has nothing to judge.
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTest037
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTest037, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_->osAccountControl_ = ptr;

    EXPECT_CALL(*ptr, GetAllowCreateId(::testing::_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(TEST_USER_ID55), testing::Return(0)));

    ErrCode ret = innerMgrService_->DeactivateOsAccountById(Constants::ADMIN_LOCAL_ID);
    EXPECT_EQ(ret, ERR_OK);

    EXPECT_CALL(*ptr, GetOsAccountInfoById(::testing::_, ::testing::_))
        .WillRepeatedly(testing::Return(-1));

    ret = innerMgrService_->DeactivateOsAccountById(TEST_USER_ID55);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);

    EXPECT_CALL(*ptr, GetOsAccountInfoById(::testing::_, ::testing::_))
        .WillRepeatedly(testing::Return(0));

    EXPECT_CALL(*ptr, UpdateOsAccount(::testing::_))
        .WillRepeatedly(testing::Return(-1));

    ret = innerMgrService_->DeactivateOsAccountById(TEST_USER_ID55);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR);

    EXPECT_CALL(*ptr, UpdateOsAccount(::testing::_))
        .WillRepeatedly(testing::Return(0));
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTest039
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTest039, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();

    OsAccountInfo osAccountInfoOne;
    (void)setuid(ACCOUNT_UID);
    ErrCode ret = innerMgrService_->CreateOsAccount("CoverageTest039", OsAccountType::GUEST, osAccountInfoOne);
    EXPECT_EQ(ret, 0);

    ret = innerMgrService_->RemoveOsAccount(osAccountInfoOne.GetLocalId());
    innerMgrService_->CleanGarbageOsAccounts();

    EXPECT_EQ(ret, 0);

    std::vector<OsAccountInfo> accounts;
    OsAccountInfo account1;
    account1.SetLocalId(TEST_USER_ID55);
    account1.SetIsActived(true);
    account1.SetToBeRemoved(true);
    accounts.push_back(account1);
    innerMgrService_->PushIdIntoActiveList(TEST_USER_ID55);

    innerMgrService_->osAccountControl_ = ptr;
    EXPECT_CALL(*ptr, GetOsAccountList(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(accounts), testing::Return(0)));
    EXPECT_CALL(*ptr, GetSerialNumber(::testing::_))
        .WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*ptr, GetAllowCreateId(::testing::_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(TEST_USER_ID55), testing::Return(0)));
    EXPECT_CALL(*ptr, GetConstraintsByType(::testing::_, ::testing::_))
        .WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*ptr, InsertOsAccount(::testing::_))
        .WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*ptr, UpdateBaseOAConstraints(::testing::_, ::testing::_, ::testing::_))
        .WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*ptr, UpdateOsAccount(::testing::_))
        .WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*ptr, GetOsAccountInfoById(::testing::_, ::testing::_))
        .WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*ptr, DelOsAccount(::testing::_))
        .WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*ptr, RemoveOAConstraintsInfo(::testing::_))
        .WillRepeatedly(testing::Return(0));

    ret = innerMgrService_->CreateOsAccount("CoverageTest039", OsAccountType::GUEST, osAccountInfoOne);
    EXPECT_EQ(ret, 0);
    ret = innerMgrService_->RemoveOsAccount(osAccountInfoOne.GetLocalId());
    EXPECT_EQ(ret, 0);
    innerMgrService_->CleanGarbageOsAccounts();

    (void)setuid(0);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/*
 * @tc.name: OsAccountInnerAccmgrMockTest040
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require: issueI6AQUQ
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTest040, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_->osAccountControl_ = ptr;

    OsAccountInfo account1;
    account1.SetLocalId(TEST_USER_ID108);
    account1.SetToBeRemoved(false);
    account1.SetIsCreateCompleted(true);

    EXPECT_CALL(*ptr, GetOsAccountInfoById(::testing::_, ::testing::_))
        .WillRepeatedly(DoAll(SetArgReferee<1>(account1), testing::Return(-1)));

    int ret = innerMgrService_->SetDefaultActivatedOsAccount(TEST_USER_ID108);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTest041
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require: issueI6AQUQ
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTest041, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_->osAccountControl_ = ptr;

    OsAccountInfo account1;
    account1.SetLocalId(TEST_USER_ID108);
    account1.SetToBeRemoved(false);
    account1.SetIsCreateCompleted(false);

    EXPECT_CALL(*ptr, GetOsAccountInfoById(::testing::_, ::testing::_))
        .WillRepeatedly(DoAll(SetArgReferee<1>(account1), testing::Return(0)));

    int ret = innerMgrService_->SetDefaultActivatedOsAccount(TEST_USER_ID108);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_IS_UNCOMPLETED_ERROR);
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTest042
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require: issueI6AQUQ
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTest042, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_->osAccountControl_ = ptr;

    OsAccountInfo account1;
    account1.SetLocalId(TEST_USER_ID108);
    account1.SetToBeRemoved(true);
    account1.SetIsCreateCompleted(true);

    EXPECT_CALL(*ptr, GetOsAccountInfoById(::testing::_, ::testing::_))
        .WillRepeatedly(DoAll(SetArgReferee<1>(account1), testing::Return(0)));

    int ret = innerMgrService_->SetDefaultActivatedOsAccount(TEST_USER_ID108);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_TO_BE_REMOVED_ERROR);
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTest043
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require: issueI6AQUQ
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTest043, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_->osAccountControl_ = ptr;

    OsAccountInfo account1;
    account1.SetLocalId(TEST_USER_ID108);
    account1.SetToBeRemoved(false);
    account1.SetIsCreateCompleted(true);

    EXPECT_CALL(*ptr, GetOsAccountInfoById(::testing::_, ::testing::_))
        .WillRepeatedly(DoAll(SetArgReferee<1>(account1), testing::Return(0)));
    EXPECT_CALL(*ptr, SetDefaultActivatedOsAccount(::testing::_))
        .WillRepeatedly(testing::Return(0));
    int ret = innerMgrService_->SetDefaultActivatedOsAccount(TEST_USER_ID108);
    EXPECT_EQ(ret, ERR_OK);
    ret = innerMgrService_->SetDefaultActivatedOsAccount(Constants::START_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTest044
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require: issueI6AQUQ
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTest044, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_->osAccountControl_ = ptr;

    OsAccountInfo account1;
    account1.SetLocalId(TEST_USER_ID108);
    account1.SetToBeRemoved(false);
    account1.SetIsCreateCompleted(true);

    EXPECT_CALL(*ptr, GetOsAccountInfoById(::testing::_, ::testing::_))
        .WillRepeatedly(DoAll(SetArgReferee<1>(account1), testing::Return(0)));
    EXPECT_CALL(*ptr, SetDefaultActivatedOsAccount(::testing::_))
        .WillRepeatedly(testing::Return(-1));
    int ret = innerMgrService_->SetDefaultActivatedOsAccount(TEST_USER_ID108);
    EXPECT_EQ(ret, -1);
    testing::Mock::AllowLeak(ptr.get());
}

/*
 * @tc.name: OsAccountPluginMockTest001
 * @tc.desc: os account LoaderLib test
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountPluginMockTest001, TestSize.Level1)
{
    innerMgrService_->pluginManager_.CloseLib();
    // load plugin success
    innerMgrService_->pluginManager_.LoaderLib("/rightPath/", "right.z.so");
    EXPECT_NE(innerMgrService_->pluginManager_.libHandle_, nullptr);
    // load plugin not nullptr
    innerMgrService_->pluginManager_.LoaderLib("/rightPath/", "right.z.so");
    EXPECT_NE(innerMgrService_->pluginManager_.libHandle_, nullptr);
    // close plugin
    innerMgrService_->pluginManager_.CloseLib();
    EXPECT_EQ(innerMgrService_->pluginManager_.libHandle_, nullptr);
    // close plugin failed
    innerMgrService_->pluginManager_.CloseLib();
    EXPECT_EQ(innerMgrService_->pluginManager_.libHandle_, nullptr);
    // wrong lib path
    innerMgrService_->pluginManager_.LoaderLib("/abc/", "right.z.so");
    EXPECT_EQ(innerMgrService_->pluginManager_.libHandle_, nullptr);
    // wrong lib name
    innerMgrService_->pluginManager_.LoaderLib("/rightPath/", "abc.z.so");
    EXPECT_EQ(innerMgrService_->pluginManager_.libHandle_, nullptr);

    innerMgrService_->pluginManager_.CloseLib();
}

/******
 * MultiThread test
 *************/

/*
 * @tc.name: OsAccountInnerAccmgrMockTestMultiThread001
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWMTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTestMultiThread001, TestSize.Level1, THREAD_NUM)
{
    bool ret = false;
    IInnerOsAccountManager::GetInstance().RemoveLocalIdToOperating(TEST_USER_ID10);
    ret = IInnerOsAccountManager::GetInstance().CheckAndAddLocalIdOperating(TEST_USER_ID10);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTestMultiThread002
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWMTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTestMultiThread002, TestSize.Level1, THREAD_NUM)
{
    bool ret = false;
    IInnerOsAccountManager::GetInstance().PushIdIntoActiveList(TEST_USER_ID10);
    ret = IInnerOsAccountManager::GetInstance().IsOsAccountIDInActiveList(TEST_USER_ID10);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTestMultiThread003
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWMTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTestMultiThread003, TestSize.Level1, THREAD_NUM)
{
    bool ret = false;
    IInnerOsAccountManager::GetInstance().EraseIdFromActiveList(TEST_USER_ID10);
    ret = IInnerOsAccountManager::GetInstance().IsOsAccountIDInActiveList(TEST_USER_ID10);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTestMultiThread004
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWMTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTestMultiThread004, TestSize.Level1, THREAD_NUM)
{
    std::vector<int32_t> activatedIds;
    IInnerOsAccountManager::GetInstance().CopyFromActiveList(activatedIds);
    EXPECT_EQ(activatedIds, IInnerOsAccountManager::GetInstance().activeAccountId_);
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTestMultiThread005
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTestMultiThread005, TestSize.Level1)
{
    std::string privateTestName = "PrivateTestName001";
    ASSERT_EQ(
        IInnerOsAccountManager::GetInstance().CreateOsAccount(privateTestName, OsAccountType::PRIVATE, osAccountInfo),
        ERR_OK);
    GTEST_RUN_TASK([]() {
        std::string privateTestName = "PrivateTestName001";
        EXPECT_EQ(IInnerOsAccountManager::GetInstance().SetOsAccountName(osAccountInfo.GetLocalId(), privateTestName),
                  ERR_OK);
    });

    EXPECT_EQ(IInnerOsAccountManager::GetInstance().RemoveOsAccount(osAccountInfo.GetLocalId()), ERR_OK);
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTestMultiThread006
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTestMultiThread006, TestSize.Level1)
{
    std::string privateTestName = "PrivateTestName001";
    ASSERT_EQ(
        IInnerOsAccountManager::GetInstance().CreateOsAccount(privateTestName, OsAccountType::GUEST, osAccountInfo),
        ERR_OK);
    GTEST_RUN_TASK([]() {
        EXPECT_EQ(IInnerOsAccountManager::GetInstance().SetOsAccountProfilePhoto(osAccountInfo.GetLocalId(),
                                                                                 STRING_PHOTO_MAX),
                  ERR_OK);
    });

    ASSERT_EQ(IInnerOsAccountManager::GetInstance().RemoveOsAccount(osAccountInfo.GetLocalId()), ERR_OK);
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTestMultiThread007
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTestMultiThread007, TestSize.Level1)
{
    ErrCode ret = IInnerOsAccountManager::GetInstance().CreateOsAccount("OsAccountInnerAccmgrMockTestMultiThread007",
                                                                        OsAccountType::NORMAL, osAccountInfo);
    ASSERT_EQ(ret, ERR_OK);
    GTEST_RUN_TASK([]() {
        // login
        int localId = osAccountInfo.GetLocalId();
        EXPECT_EQ(IInnerOsAccountManager::GetInstance().SetOsAccountIsLoggedIn(localId, true), ERR_OK);
    });

    IInnerOsAccountManager::GetInstance().RemoveOsAccount(osAccountInfo.GetLocalId());
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTestMultiThread008
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTestMultiThread008, TestSize.Level1)
{
    ErrCode ret = IInnerOsAccountManager::GetInstance().CreateOsAccount("OsAccountInnerAccmgrMockTestMultiThread008",
                                                                        OsAccountType::NORMAL, osAccountInfo);
    ASSERT_EQ(ret, ERR_OK);
    GTEST_RUN_TASK([]() {
        // login
        int localId = osAccountInfo.GetLocalId();
        EXPECT_EQ(IInnerOsAccountManager::GetInstance().SetOsAccountCredentialId(localId, true), ERR_OK);
    });

    IInnerOsAccountManager::GetInstance().RemoveOsAccount(osAccountInfo.GetLocalId());
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTestMultiThread009
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTestMultiThread009, TestSize.Level1)
{
    ErrCode ret = IInnerOsAccountManager::GetInstance().CreateOsAccount("OsAccountInnerAccmgrMockTestMultiThread009",
                                                                        OsAccountType::NORMAL, osAccountInfo);
    ASSERT_EQ(ret, ERR_OK);
    GTEST_RUN_TASK([]() {
        // login
        int localId = osAccountInfo.GetLocalId();
        EXPECT_EQ(ERR_OK, IInnerOsAccountManager::GetInstance().UpdateAccountToBackground(localId));
    });

    IInnerOsAccountManager::GetInstance().RemoveOsAccount(osAccountInfo.GetLocalId());
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTestMultiThread011
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTestMultiThread011, TestSize.Level1)
{
    GTEST_RUN_TASK([]() {
        ErrCode ret = IInnerOsAccountManager::GetInstance().DeactivateOsAccountById(Constants::ADMIN_LOCAL_ID);
        EXPECT_EQ(ret, ERR_OK);
    });
}

/*
 * @tc.name: OsAccountInnerAccmgrMockTestMultiThread012
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrMockTest, OsAccountInnerAccmgrMockTestMultiThread012, TestSize.Level1)
{
    GTEST_RUN_TASK([]() {
        int id;
        ErrCode ret = IInnerOsAccountManager::GetInstance().GetDefaultActivatedOsAccount(id);
        EXPECT_EQ(ret, ERR_OK);
        EXPECT_EQ(id, MAIN_ACCOUNT_ID);
    });
}
}  // namespace AccountSA
}  // namespace OHOS
