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

#include <gtest/gtest.h>
#include <map>

#include "account_error_no.h"
#include "os_account_constants.h"
#include "os_account_manager.h"
#include "os_account_manager_service.h"
#include "os_account_interface.h"
#include "os_account_info.h"
#include "account_log_wrapper.h"
#define private public
#include "iinner_os_account_manager.h"
#undef private
#include "os_account_subscribe_manager.h"
#include "mock_os_account_control_file_manager.h"
#include <sys/types.h>
#include <unistd.h>


namespace OHOS {
namespace AccountSA {
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS;
using namespace AccountSA;

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
const int TEST_USER_ID555 = 555;

const std::string STRING_TEST_NAME = "test_account_name";
const int ACCOUNT_UID = 3058;
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
const std::string TEST_EXPECTED_UID = "4E7FA9CA2E8760692F2ADBA7AE59B37E02E650670E5FA5F3D01232DCD52D3893";

class OsAccountInnerAccmgrCoverageTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
public:
    std::shared_ptr<IInnerOsAccountManager> innerMgrService_;
    std::shared_ptr<IOsAccountSubscribe> subscribeManagerPtr_;
};

void OsAccountInnerAccmgrCoverageTest::SetUpTestCase(void)
{}

void OsAccountInnerAccmgrCoverageTest::TearDownTestCase(void)
{}

void OsAccountInnerAccmgrCoverageTest::SetUp(void)
{}

void OsAccountInnerAccmgrCoverageTest::TearDown(void)
{}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest001
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest001, TestSize.Level1)
{
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();

    innerMgrService_->CreateBaseAdminAccount();

    std::shared_ptr<IOsAccountControl> osAccountControl = innerMgrService_->osAccountControl_;
    bool isExistsAccount = false;

    osAccountControl->IsOsAccountExists(Constants::ADMIN_LOCAL_ID, isExistsAccount);
    EXPECT_EQ(true, isExistsAccount);

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest002
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest002, TestSize.Level1)
{
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();

    innerMgrService_->CreateBaseStandardAccount();

    std::shared_ptr<IOsAccountControl> osAccountControl = innerMgrService_->osAccountControl_;
    bool isExistsAccount = false;

    osAccountControl->IsOsAccountExists(Constants::START_USER_ID, isExistsAccount);
    EXPECT_EQ(true, isExistsAccount);

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest003
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest003, TestSize.Level1)
{
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
    bool ret;
    innerMgrService_->StartActivatedAccount(0);
    ret = innerMgrService_->IsOsAccountIDInActiveList(0);
    EXPECT_EQ(true, ret);

    innerMgrService_->StartActivatedAccount(TEST_USER_ID100);
    ret = innerMgrService_->IsOsAccountIDInActiveList(TEST_USER_ID100);
    EXPECT_EQ(true, ret);

    innerMgrService_->StartActivatedAccount(TEST_USER_ID555);
    ret = innerMgrService_->IsOsAccountIDInActiveList(TEST_USER_ID555);
    EXPECT_EQ(false, ret);

    innerMgrService_->RestartActiveAccount();
    ret = innerMgrService_->IsOsAccountIDInActiveList(0);
    EXPECT_EQ(false, ret);

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest004
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest004, TestSize.Level1)
{
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_->SetOsAccountControl(ptr);

    EXPECT_CALL(*ptr, UpdateOsAccount(::testing::_))
        .WillRepeatedly(testing::Return(0));
    
    innerMgrService_->CreateBaseStandardAccountSendToOther();
    EXPECT_EQ(innerMgrService_->isSendToStorageCreate_, true);

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest005
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest005, TestSize.Level1)
{
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
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

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest006
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest006, TestSize.Level1)
{
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();

    innerMgrService_->GetEventHandler();

    EXPECT_EQ(true, (innerMgrService_->handler_ != nullptr));

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest007
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest007, TestSize.Level1)
{
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
    bool ret = false;
    innerMgrService_->AddLocalIdToOperating(TEST_USER_ID10);
    ret = innerMgrService_->IsLocalIdInOperating(TEST_USER_ID10);
    EXPECT_EQ(ret, true);

    innerMgrService_->RemoveLocalIdToOperating(TEST_USER_ID10);
    ret = innerMgrService_->IsLocalIdInOperating(TEST_USER_ID10);
    EXPECT_EQ(ret, false);

    innerMgrService_->RemoveLocalIdToOperating(TEST_USER_ID10);
    ret = innerMgrService_->IsLocalIdInOperating(TEST_USER_ID10);
    EXPECT_EQ(ret, false);

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest008
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest008, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();

    EXPECT_CALL(*ptr, GetOsAccountList(::testing::_))
        .WillRepeatedly(testing::Return(-1));

    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
    innerMgrService_->SetOsAccountControl(ptr);
    unsigned int count;
    int ret = innerMgrService_->GetCreatedOsAccountsCount(count);
    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
    EXPECT_EQ(ret, -1);
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest009
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest009, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();

    EXPECT_CALL(*ptr, GetSerialNumber(::testing::_))
        .WillRepeatedly(testing::Return(0));

    EXPECT_CALL(*ptr, GetAllowCreateId(::testing::_))
        .WillRepeatedly(testing::Return(-1));

    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
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
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_GET_TYPE_CONSTRAINTS_ERROR);

    EXPECT_CALL(*ptr, GetConstraintsByType(::testing::_, ::testing::_))
        .WillRepeatedly(testing::Return(0));

    ret = innerMgrService_->PrepareOsAccountInfo(name, type, domainInfo2, accountInfo);
    EXPECT_EQ(ret, ERR_OSACCOUNT_KIT_CREATE_OS_ACCOUNT_FOR_DOMAIN_ERROR);

    EXPECT_CALL(*ptr, InsertOsAccount(::testing::_))
        .WillRepeatedly(testing::Return(-1));

    ret = innerMgrService_->PrepareOsAccountInfo(name, type, domainInfo1, accountInfo);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_CREATE_ACCOUNT_ERROR);

    EXPECT_CALL(*ptr, InsertOsAccount(::testing::_))
        .WillRepeatedly(testing::Return(0));

    EXPECT_CALL(*ptr, UpdateBaseOAConstraints(::testing::_, ::testing::_, ::testing::_))
        .WillRepeatedly(testing::Return(-1));

    ret = innerMgrService_->PrepareOsAccountInfo(name, type, domainInfo1, accountInfo);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_CREATE_ACCOUNT_ERROR);

    EXPECT_CALL(*ptr, UpdateBaseOAConstraints(::testing::_, ::testing::_, ::testing::_))
        .WillRepeatedly(testing::Return(0));

    ret = innerMgrService_->PrepareOsAccountInfo(name, type, domainInfo1, accountInfo);
    EXPECT_EQ(ret, 0);

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest010
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest010, TestSize.Level1)
{
    int ret;
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
    innerMgrService_->SetOsAccountControl(ptr);

    OsAccountInfo osAccountInfoOne;
    EXPECT_EQ(OsAccountManager::CreateOsAccount(STRING_TEST_NAME, OsAccountType::GUEST, osAccountInfoOne), ERR_OK);

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
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest011
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest011, TestSize.Level1)
{
    int ret;
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
    innerMgrService_->SetOsAccountControl(ptr);

    OsAccountInfo osAccountInfoOne;
    EXPECT_EQ(OsAccountManager::CreateOsAccount(STRING_TEST_NAME, OsAccountType::GUEST, osAccountInfoOne), ERR_OK);

    EXPECT_CALL(*ptr, UpdateOsAccount(::testing::_))
        .WillRepeatedly(testing::Return(0));

    ret = innerMgrService_->SendMsgForAccountCreate(osAccountInfoOne);
    EXPECT_EQ(ret, 0);

    (void)setuid(ACCOUNT_UID);

    EXPECT_CALL(*ptr, UpdateOsAccount(::testing::_))
        .WillRepeatedly(testing::Return(-1));

    ret = innerMgrService_->SendMsgForAccountCreate(osAccountInfoOne);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR);

    EXPECT_CALL(*ptr, UpdateOsAccount(::testing::_))
        .WillRepeatedly(testing::Return(0));

    ret = innerMgrService_->SendMsgForAccountCreate(osAccountInfoOne);
    EXPECT_EQ(ret, 0);

    (void)setuid(0);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest012
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest012, TestSize.Level1)
{
    int ret;
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
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
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_GET_ACCOUNT_LIST_ERROR);
    

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest013
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest013, TestSize.Level1)
{
    int ret;
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
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
    innerMgrService_->AddLocalIdToOperating(id);
    ret = innerMgrService_->RemoveOsAccount(id);
    innerMgrService_->RemoveLocalIdToOperating(id);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_OPERATING_ERROR);

    EXPECT_CALL(*ptr, GetOsAccountInfoById(::testing::_, ::testing::_))
        .WillRepeatedly(testing::Return(0));

    innerMgrService_->PushIdIntoActiveList(id);
    ret = innerMgrService_->RemoveOsAccount(id);
    innerMgrService_->EraseIdFromActiveList(id);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_REMOVE_ACCOUNT_ACTIVED_ERROR);

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

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest015
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest015, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();

    OsAccountInfo osAccountInfoOne;
    (void)setuid(ACCOUNT_UID);
    ErrCode ret = innerMgrService_->CreateOsAccount(STRING_TEST_NAME, OsAccountType::GUEST, osAccountInfoOne);

    ret = innerMgrService_->RemoveOsAccount(osAccountInfoOne.GetLocalId());
    EXPECT_EQ(ret, 0);

    (void)setuid(0);
    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest016
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest016, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
    innerMgrService_->SetOsAccountControl(ptr);

    int id = 0;
    bool flag;

    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(testing::Return(-1));

    ErrCode ret = innerMgrService_->IsOsAccountActived(id, flag);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR);

    EXPECT_CALL(*ptr, GetMaxCreatedOsAccountNum(_))
        .WillRepeatedly(testing::Return(-1));
    int num = 0;
    ret = innerMgrService_->QueryMaxOsAccountNumber(num);
    EXPECT_EQ(ret, -1);

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest017
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest017, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
    innerMgrService_->SetOsAccountControl(ptr);

    int id = 0;
    std::vector<std::string> constraints;

    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(testing::Return(-1));

    ErrCode ret = innerMgrService_->GetOsAccountAllConstraints(id, constraints);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR);

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

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest018
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest018, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
    innerMgrService_->SetOsAccountControl(ptr);

    std::vector<OsAccountInfo> accounts;

    EXPECT_CALL(*ptr, GetOsAccountList(_))
        .WillRepeatedly(testing::Return(-1));

    innerMgrService_->CleanGarbageAccounts();

    ErrCode ret = innerMgrService_->QueryAllCreatedOsAccounts(accounts);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_GET_ACCOUNT_LIST_ERROR);

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest019
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest019, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
    innerMgrService_->SetOsAccountControl(ptr);

    int id = TEST_USER_ID100;
    OsAccountInfo osAccountInfo;

    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(testing::Return(-1));

    ErrCode ret = innerMgrService_->QueryOsAccountById(id, osAccountInfo);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR);

    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(testing::Return(0));

    osAccountInfo.SetPhoto("abc");

    EXPECT_CALL(*ptr, GetPhotoById(_, _))
        .WillRepeatedly(testing::Return(-1));

    ret = innerMgrService_->QueryOsAccountById(id, osAccountInfo);
    EXPECT_EQ(ret, -1);

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest020
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest020, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
    innerMgrService_->SetOsAccountControl(ptr);

    int id = TEST_USER_ID100;
    OsAccountType type = OsAccountType::GUEST;

    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(testing::Return(-1));

    ErrCode ret = innerMgrService_->GetOsAccountType(id, type);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR);

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest021
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest021, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
    innerMgrService_->SetOsAccountControl(ptr);

    int id = TEST_USER_ID100;
    std::string photo = "";

    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(testing::Return(-1));

    ErrCode ret = innerMgrService_->GetOsAccountProfilePhoto(id, photo);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR);

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest022
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest022, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
    innerMgrService_->SetOsAccountControl(ptr);

    bool isMultiOsAccountEnabled = false; ///

    EXPECT_CALL(*ptr, GetIsMultiOsAccountEnable(_))
        .WillRepeatedly(testing::Return(-1));

    ErrCode ret = innerMgrService_->IsMultiOsAccountEnable(isMultiOsAccountEnabled);
    EXPECT_EQ(ret, -1);

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest023
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest023, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
    innerMgrService_->SetOsAccountControl(ptr);

    int id = TEST_USER_ID100;
    std::string name = "test";

    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(testing::Return(-1));

    ErrCode ret = innerMgrService_->SetOsAccountName(id, name);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR);

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

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest024
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest024, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
    innerMgrService_->SetOsAccountControl(ptr);

    int id = TEST_USER_ID100;
    std::string name = "";
    std::vector<std::string> constraints;
    bool enable = false;

    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(testing::Return(-1));

    ErrCode ret = innerMgrService_->SetOsAccountConstraints(id, constraints, enable);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR);

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
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_SER_CONSTRAINTS_ERROR);

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

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest025
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest025, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
    innerMgrService_->SetOsAccountControl(ptr);

    int id = TEST_USER_ID100;
    std::string photo = "";

    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(testing::Return(-1));

    EXPECT_CALL(*ptr, SetPhotoById(_, _))
        .WillRepeatedly(testing::Return(0));

    ErrCode ret = innerMgrService_->SetOsAccountProfilePhoto(id, photo);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR);

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

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest026
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest026, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
    innerMgrService_->SetOsAccountControl(ptr);

    int id = TEST_USER_ID100;
    std::string photo = "";

    innerMgrService_->AddLocalIdToOperating(id);
    ErrCode ret = innerMgrService_->ActivateOsAccount(id);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_OPERATING_ERROR);
    innerMgrService_->RemoveLocalIdToOperating(id);

    innerMgrService_->PushIdIntoActiveList(id);
    ret = innerMgrService_->ActivateOsAccount(id);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_ALREADY_ACTIVE_ERROR);

    innerMgrService_->EraseIdFromActiveList(id);

    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(testing::Return(-1));
    ret = innerMgrService_->ActivateOsAccount(id);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR);

    OsAccountInfo osAccountInfo;
    osAccountInfo.SetIsCreateCompleted(0);
    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(DoAll(testing::SetArgReferee<1>(osAccountInfo), testing::Return(0)));
    
    ret = innerMgrService_->ActivateOsAccount(id);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_IS_UNVERIFIED_ERROR);
    
    osAccountInfo.SetIsCreateCompleted(1);
    osAccountInfo.SetToBeRemoved(true);
    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(DoAll(testing::SetArgReferee<1>(osAccountInfo), testing::Return(0)));

    ret = innerMgrService_->ActivateOsAccount(id);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_TO_BE_REMOVED_ERROR);

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest027
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest027, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
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
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_GET_ACCOUNT_LIST_ERROR);

    EXPECT_CALL(*ptr, GetOsAccountInfoById(::testing::_, ::testing::_))
        .WillRepeatedly(testing::Return(-1));

    ret = innerMgrService_->GetSerialNumberByOsAccountLocalId(id, serialNumber);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR);

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest028
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest028, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
    innerMgrService_->SetOsAccountControl(ptr);

    OsAccountSubscribeInfo info;
    sptr <IRemoteObject> eventListener;
    auto tmp = innerMgrService_->subscribeManagerPtr_;
    innerMgrService_->subscribeManagerPtr_ = nullptr;
    ErrCode ret = innerMgrService_->SubscribeOsAccount(info, eventListener);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_SUBSCRIBE_MANAGER_PTR_IS_NULLPTR);

    ret = innerMgrService_->UnsubscribeOsAccount(eventListener);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_SUBSCRIBE_MANAGER_PTR_IS_NULLPTR);

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest029
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest029, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
    innerMgrService_->SetOsAccountControl(ptr);

    int id = TEST_USER_ID100;
    bool isVerified = false;

    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(testing::Return(-1));
    ErrCode ret = innerMgrService_->SetOsAccountIsVerified(id, isVerified);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR);

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

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest030
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest030, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
    innerMgrService_->SetOsAccountControl(ptr);

    int id = TEST_USER_ID100;

    DomainAccountInfo domainAllTooLong(STRING_DOMAIN_NAME_OUT_OF_RANGE, STRING_DOMAIN_ACCOUNT_NAME_OUT_OF_RANGE);
    ErrCode ret = innerMgrService_->GetOsAccountLocalIdFromDomain(domainAllTooLong, id);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_DOMAIN_NAME_LEN_ERROR);

    DomainAccountInfo domainAllTooLong2(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_OUT_OF_RANGE);
    ret = innerMgrService_->GetOsAccountLocalIdFromDomain(domainAllTooLong2, id);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_DOMAIN_ACCOUNT_NAME_LEN_ERROR);

    DomainAccountInfo domainInfo1(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    EXPECT_CALL(*ptr, GetOsAccountList(_))
        .WillRepeatedly(testing::Return(-1));
    ret = innerMgrService_->GetOsAccountLocalIdFromDomain(domainInfo1, id);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_GET_ACCOUNT_LIST_ERROR);

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest031
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest031, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
    innerMgrService_->SetOsAccountControl(ptr);

    int id = TEST_USER_ID100;
    const std::string constraint;
    std::vector<ConstraintSourceTypeInfo> constraintSourceTypeInfos;

    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(testing::Return(-1));
    
    ErrCode ret = innerMgrService_->QueryOsAccountConstraintSourceTypes(id, constraint, constraintSourceTypeInfos);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_SELECT_OSACCOUNT_BYID_ERROR);

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest032
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest032, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
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

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest033
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest033, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
    innerMgrService_->SetOsAccountControl(ptr);

    OsAccountInfo osAccountInfo;
    osAccountInfo.SetIsCreateCompleted(false);
    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(DoAll(testing::SetArgReferee<1>(osAccountInfo), testing::Return(-1)));

    EXPECT_CALL(*ptr, GetOsAccountList(::testing::_))
        .WillRepeatedly(testing::Return(0));

    innerMgrService_->StartAccount();
    EXPECT_EQ((innerMgrService_->handler_ != nullptr), 1);

    EXPECT_CALL(*ptr, GetOsAccountInfoById(_, _))
        .WillRepeatedly(DoAll(testing::SetArgReferee<1>(osAccountInfo), testing::Return(0)));
    innerMgrService_->StartAccount();
    EXPECT_EQ((innerMgrService_->handler_ != nullptr), 1);

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest034
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest034, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
    innerMgrService_->SetOsAccountControl(ptr);

    std::vector<OsAccountInfo> accounts;

    EXPECT_CALL(*ptr, GetOsAccountList(_))
        .WillRepeatedly(testing::Return(-1));

    innerMgrService_->RestartActiveAccount();
    EXPECT_EQ((innerMgrService_->handler_ != nullptr), 0);

    OsAccountInfo account1;
    account1.SetLocalId(TEST_USER_ID55);
    account1.SetIsActived(true);
    accounts.push_back(account1);
    innerMgrService_->PushIdIntoActiveList(TEST_USER_ID55);

    EXPECT_CALL(*ptr, GetOsAccountList(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(accounts), testing::Return(0)));
    innerMgrService_->RestartActiveAccount();
    EXPECT_EQ((innerMgrService_->handler_ != nullptr), 1);

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest035
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest035, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
    innerMgrService_->SetOsAccountControl(ptr);

    OsAccountInfo account1;
    account1.SetLocalId(TEST_USER_ID55);
    account1.SetIsCreateCompleted(false);

    EXPECT_CALL(*ptr, GetOsAccountInfoById(::testing::_, ::testing::_))
        .WillRepeatedly(DoAll(SetArgReferee<1>(account1), testing::Return(0)));

    innerMgrService_->StartBaseStandardAccount(account1);
    EXPECT_EQ((innerMgrService_->counterForStandard_ == 0), 1);

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest036
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest036, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
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

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest037
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest037, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
    innerMgrService_->SetOsAccountControl(ptr);

    ErrCode ret = innerMgrService_->DeActivateOsAccount(Constants::ADMIN_LOCAL_ID);
    EXPECT_EQ(ret, ERR_OK);

    EXPECT_CALL(*ptr, GetOsAccountInfoById(::testing::_, ::testing::_))
        .WillRepeatedly(testing::Return(-1));

    ret = innerMgrService_->DeActivateOsAccount(TEST_USER_ID55);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_CANNOT_FIND_OSACCOUNT_ERROR);

    EXPECT_CALL(*ptr, GetOsAccountInfoById(::testing::_, ::testing::_))
        .WillRepeatedly(testing::Return(0));

    EXPECT_CALL(*ptr, UpdateOsAccount(::testing::_))
        .WillRepeatedly(testing::Return(-1));

    ret = innerMgrService_->DeActivateOsAccount(TEST_USER_ID55);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR);

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest038
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest038, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
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

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest039
 * @tc.desc: coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest039, TestSize.Level1)
{
    auto ptr = std::make_shared<MockOsAccountControlFileManager>();
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();

    OsAccountInfo osAccountInfoOne;
    (void)setuid(ACCOUNT_UID);
    ErrCode ret = innerMgrService_->CreateOsAccount(STRING_TEST_NAME, OsAccountType::GUEST, osAccountInfoOne);
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

    ret = innerMgrService_->CreateOsAccount(STRING_TEST_NAME, OsAccountType::GUEST, osAccountInfoOne);
    EXPECT_EQ(ret, 0);
    ret = innerMgrService_->RemoveOsAccount(osAccountInfoOne.GetLocalId());
    EXPECT_EQ(ret, 0);
    innerMgrService_->CleanGarbageAccounts();

    (void)setuid(0);
    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}

}  // namespace AccountSA
}  // namespace OHOS
