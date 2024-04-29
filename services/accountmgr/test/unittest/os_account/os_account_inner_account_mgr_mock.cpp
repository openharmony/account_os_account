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
#include <map>

#include "account_error_no.h"
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
using namespace testing::ext;
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

const std::string STRING_TEST_NAME = "test_account_name";
const std::string STRING_DOMAIN_NAME_OUT_OF_RANGE(200, '1');  // length 200
const std::string STRING_DOMAIN_ACCOUNT_NAME_OUT_OF_RANGE(600, '1');  // length 600
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
const int ACCOUNT_UID = 3058;
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS
const std::string STRING_DOMAIN_VALID = "TestDomainMT";
const std::string STRING_DOMAIN_ACCOUNT_NAME_VALID = "TestDomainAccountNameMT";

class OsAccountInnerAccmgrMockTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
public:
    IInnerOsAccountManager *innerMgrService_ = &IInnerOsAccountManager::GetInstance();
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

    innerMgrService_->SetOsAccountControl(ptr);
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
    innerMgrService_->SetOsAccountControl(ptr);
    std::string name;
    OsAccountType type = OsAccountType::GUEST;
    DomainAccountInfo domainInfo1(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    DomainAccountInfo domainInfo2(STRING_DOMAIN_NAME_OUT_OF_RANGE, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    OsAccountInfo accountInfo;
    int ret = innerMgrService_->PrepareOsAccountInfo(name, type, domainInfo1, accountInfo);
    EXPECT_EQ(ret, -1);
    EXPECT_CALL(*ptr, GetAllowCreateId(::testing::_))
        .WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*ptr, GetConstraintsByType(::testing::_, ::testing::_))
        .WillRepeatedly(testing::Return(-1));
    ret = innerMgrService_->PrepareOsAccountInfo(name, type, domainInfo1, accountInfo);
    EXPECT_NE(ret, ERR_OK);
    EXPECT_CALL(*ptr, GetConstraintsByType(::testing::_, ::testing::_))
        .WillRepeatedly(testing::Return(0));
    ret = innerMgrService_->PrepareOsAccountInfo(name, type, domainInfo2, accountInfo);
    EXPECT_EQ(ret, ERR_OSACCOUNT_KIT_CREATE_OS_ACCOUNT_FOR_DOMAIN_ERROR);
    EXPECT_CALL(*ptr, InsertOsAccount(::testing::_))
        .WillRepeatedly(testing::Return(-1));
    ret = innerMgrService_->PrepareOsAccountInfo(name, type, domainInfo1, accountInfo);
    EXPECT_NE(ret, ERR_OK);
    EXPECT_CALL(*ptr, InsertOsAccount(::testing::_))
        .WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*ptr, UpdateBaseOAConstraints(::testing::_, ::testing::_, ::testing::_))
        .WillRepeatedly(testing::Return(-1));
    ret = innerMgrService_->PrepareOsAccountInfo(name, type, domainInfo1, accountInfo);
    EXPECT_NE(ret, ERR_OK);
    EXPECT_CALL(*ptr, UpdateBaseOAConstraints(::testing::_, ::testing::_, ::testing::_))
        .WillRepeatedly(testing::Return(0));
    ret = innerMgrService_->PrepareOsAccountInfo(name, type, domainInfo1, accountInfo);
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
    innerMgrService_->SetOsAccountControl(ptr);

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
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR);

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
    innerMgrService_->SetOsAccountControl(ptr);

    OsAccountInfo osAccountInfoOne;

    const OsAccountType type = OsAccountType::GUEST;
    const DomainAccountInfo domainInfo;

    EXPECT_CALL(*ptr, GetOsAccountList(::testing::_))
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

    EXPECT_CALL(*ptr, GetOsAccountList(::testing::_))
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
    innerMgrService_->SetOsAccountControl(ptr);

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
    innerMgrService_->SetOsAccountControl(ptr);

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
    innerMgrService_->SetOsAccountControl(ptr);

    std::vector<OsAccountInfo> accounts;

    EXPECT_CALL(*ptr, GetOsAccountList(_))
        .WillRepeatedly(testing::Return(-1));

    innerMgrService_->CleanGarbageAccounts();

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
    innerMgrService_->SetOsAccountControl(ptr);

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
    innerMgrService_->SetOsAccountControl(ptr);

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
    innerMgrService_->SetOsAccountControl(ptr);

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
    innerMgrService_->SetOsAccountControl(ptr);

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
    innerMgrService_->SetOsAccountControl(ptr);

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
    innerMgrService_->SetOsAccountControl(ptr);

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
    innerMgrService_->SetOsAccountControl(ptr);

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
    innerMgrService_->SetOsAccountControl(ptr);

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
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_ALREADY_ACTIVE_ERROR);

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
    innerMgrService_->SetOsAccountControl(ptr);

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
    innerMgrService_->SetOsAccountControl(ptr);

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

    ret = innerMgrService_->SetOsAccountIsVerified(id, isVerified);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR);

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
    innerMgrService_->SetOsAccountControl(ptr);

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
    innerMgrService_->SetOsAccountControl(ptr);

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
    innerMgrService_->SetOsAccountControl(ptr);

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
    innerMgrService_->SetOsAccountControl(ptr);

    OsAccountInfo osAccountInfo;
    osAccountInfo.SetIsCreateCompleted(false);
    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(DoAll(testing::SetArgReferee<1>(osAccountInfo), testing::Return(-1)));

    EXPECT_CALL(*ptr, GetOsAccountList(::testing::_))
        .WillRepeatedly(testing::Return(0));

    (void)setuid(ACCOUNT_UID);
    innerMgrService_->StartAccount();
    (void)setuid(0);
    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(DoAll(testing::SetArgReferee<1>(osAccountInfo), testing::Return(0)));
    innerMgrService_->StartAccount();
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
    innerMgrService_->SetOsAccountControl(ptr);

    std::vector<OsAccountInfo> accounts;

    EXPECT_CALL(*ptr, GetOsAccountList(_))
        .WillRepeatedly(testing::Return(-1));

    innerMgrService_->RestartActiveAccount();

    OsAccountInfo account1;
    account1.SetLocalId(TEST_USER_ID55);
    account1.SetIsActived(true);
    accounts.push_back(account1);
    innerMgrService_->PushIdIntoActiveList(TEST_USER_ID55);

    EXPECT_CALL(*ptr, GetOsAccountList(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(accounts), testing::Return(0)));
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
    innerMgrService_->SetOsAccountControl(ptr);

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
    innerMgrService_->SetOsAccountControl(ptr);

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
    innerMgrService_->CleanGarbageAccounts();

    EXPECT_EQ(ret, 0);

    std::vector<OsAccountInfo> accounts;
    OsAccountInfo account1;
    account1.SetLocalId(TEST_USER_ID55);
    account1.SetIsActived(true);
    account1.SetToBeRemoved(true);
    accounts.push_back(account1);
    innerMgrService_->PushIdIntoActiveList(TEST_USER_ID55);

    innerMgrService_->SetOsAccountControl(ptr);
    EXPECT_CALL(*ptr, GetOsAccountList(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(accounts), testing::Return(0)));
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
    innerMgrService_->CleanGarbageAccounts();

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
    innerMgrService_->SetOsAccountControl(ptr);

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
    innerMgrService_->SetOsAccountControl(ptr);

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
    innerMgrService_->SetOsAccountControl(ptr);

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
    innerMgrService_->SetOsAccountControl(ptr);

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
    innerMgrService_->SetOsAccountControl(ptr);

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
}  // namespace AccountSA
}  // namespace OHOS
