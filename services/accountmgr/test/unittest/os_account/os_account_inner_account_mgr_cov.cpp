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

#include <gtest/gtest.h>
#include <map>

#include "account_error_no.h"
#include "os_account_constants.h"
#include "os_account_manager_service.h"
#include "os_account_interface.h"
#include "os_account_info.h"
#include "account_log_wrapper.h"
#define private public
#include "iinner_os_account_manager.h"
#undef private
#include "os_account_subscribe_manager.h"

namespace OHOS {
namespace AccountSA {
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS;
using namespace AccountSA;

const int TEST_USER_ID10 = 10;
const int TEST_USER_ID55 = 55;
const int TEST_USER_ID100 = 100;
const int TEST_USER_ID555 = 555;

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
 * @tc.desc: CreateBaseAdminAccount coverage test
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
 * @tc.desc: CreateBaseAdminAccount coverage test
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
 * @tc.desc: CreateBaseAdminAccount coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest003, TestSize.Level1)
{
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
    bool ret;
    innerMgrService_->StartActivatedAccount(0);
    ret = innerMgrService_->IsOsAccountIDInActiveList(0);
    EXPECT_EQ(false, ret);

    innerMgrService_->StartActivatedAccount(TEST_USER_ID100);
    ret = innerMgrService_->IsOsAccountIDInActiveList(TEST_USER_ID100);
    EXPECT_EQ(false, ret);

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
 * @tc.desc: CreateBaseAdminAccount coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest004, TestSize.Level1)
{
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();

    innerMgrService_->CreateBaseStandardAccountSendToOther();
    EXPECT_EQ(innerMgrService_->isSendToStorageCreate_, true);

    innerMgrService_->CreateBaseStandardAccountSendToOther();
    EXPECT_EQ(innerMgrService_->isSendToStorageCreate_, true);

    DelayedSingleton<IInnerOsAccountManager>::DestroyInstance();
}


/*
 * @tc.name: OsAccountInnerAccmgrCoverageTest005
 * @tc.desc: CreateBaseAdminAccount coverage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountInnerAccmgrCoverageTest, OsAccountInnerAccmgrCoverageTest005, TestSize.Level1)
{
    innerMgrService_ = DelayedSingleton<IInnerOsAccountManager>::GetInstance();
    bool ret = false;
    innerMgrService_->PushIdIntoActiveList(TEST_USER_ID10);
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
 * @tc.desc: CreateBaseAdminAccount coverage test
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
 * @tc.desc: CreateBaseAdminAccount coverage test
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

}  // namespace AccountSA
}  // namespace OHOS
