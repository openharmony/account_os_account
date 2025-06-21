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

#include <gtest/gtest.h>
#include <memory>
#include <thread>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_test_common.h"
#include "account_proxy.h"
#include "ipc_skeleton.h"
#include "iremote_object.h"
#include "iservice_registry.h"
#include "os_account_proxy.h"
#define private public
#include "os_account.h"
#include "os_account_constraint_subscriber_manager.h"
#undef private
#include "singleton.h"
#include "system_ability_definition.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string STRING_EMPTY = "";
const std::string STRING_NAME = "name";
const std::int32_t MAIN_ACCOUNT_ID = 100;
const std::int32_t WAIT_A_MOMENT = 3000;
const std::int32_t ILLEGAL_LOCAL_ID = -1;
const std::int32_t NOT_EXSIT_ID = 99999;
const std::string STRING_NAME_OUT_OF_RANGE(1200, '1'); // length 1200
const std::string STRING_PHOTO_OUT_OF_RANGE(1024 * 1024 + 1, '1'); // length 1024*1024+1
const std::string STRING_DOMAIN_NAME_OUT_OF_RANGE(200, '1'); // length 200
const std::string STRING_DOMAIN_ACCOUNT_NAME_OUT_OF_RANGE(600, '1'); // length 600
const std::string STRING_CONSTRAINT_OUT_OF_RANGE(200, '1'); // length 200
const std::vector<std::string> CONSTANTS_VECTOR {
    "constraint.print",
    "constraint.screen.timeout.set",
    "constraint.share.into.profile"
};
const std::string CONSTRAINT_WIFI = "constraint.wifi";
const std::string CONSTRAINT_TIME_OUT = "constraint.screen.timeout.set";
const std::string CONSTRAINT_SHARE =  "constraint.share.into.profile";
const std::string STRING_DOMAIN_VALID = "TestDomainUT";
const std::string STRING_DOMAIN_ACCOUNT_NAME_VALID = "TestDomainAccountNameUT";
std::shared_ptr<OsAccount> g_osAccount = nullptr;
sptr<IOsAccount> osAccountProxy_ = nullptr;
const std::uint32_t MAX_WAIT_FOR_READY_CNT = 10;
}  // namespace
class OsAccountTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void OsAccountTest::SetUpTestCase(void)
{
    ASSERT_TRUE(MockTokenId("accountmgr"));
    g_osAccount = std::make_shared<OsAccount>();
    GTEST_LOG_(INFO) << "SetUpTestCase enter";
    bool isOsAccountActived = false;
    ErrCode ret = g_osAccount->IsOsAccountActived(MAIN_ACCOUNT_ID, isOsAccountActived);
    std::uint32_t waitCnt = 0;
    while (ret != ERR_OK || !isOsAccountActived) {
        std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_A_MOMENT));
        waitCnt++;
        GTEST_LOG_(INFO) << "SetUpTestCase waitCnt " << waitCnt << " ret = " << ret;
        ret = g_osAccount->IsOsAccountActived(MAIN_ACCOUNT_ID, isOsAccountActived);
        if (waitCnt >= MAX_WAIT_FOR_READY_CNT) {
            GTEST_LOG_(INFO) << "SetUpTestCase waitCnt " << waitCnt;
            GTEST_LOG_(INFO) << "SetUpTestCase wait for ready failed!";
            break;
        }
    }

    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject =
        systemAbilityManager->GetSystemAbility(SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN);
    sptr<IAccount> accountProxy = iface_cast<AccountProxy>(remoteObject);
    EXPECT_NE(accountProxy, nullptr);
    auto osAccountRemoteObject = accountProxy->GetOsAccountService();
    osAccountProxy_ = iface_cast<IOsAccount>(osAccountRemoteObject);
    EXPECT_NE(osAccountProxy_, nullptr);
    GTEST_LOG_(INFO) << "SetUpTestCase finished, waitCnt " << waitCnt;
}

void OsAccountTest::TearDownTestCase(void)
{}

void OsAccountTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void OsAccountTest::TearDown(void)
{}

class MockOsAccountConstraintSubscriber : public OsAccountConstraintSubscriber {
public:
    explicit MockOsAccountConstraintSubscriber(const std::set<std::string> &constraintSet)
        : OsAccountConstraintSubscriber(constraintSet) {}

    ~MockOsAccountConstraintSubscriber() {}

    void OnConstraintChanged(const OsAccountConstraintStateData &constraintData) override
    {
        ACCOUNT_LOGI("Enter OnConstraintChanged, localId=%{public}d, constraints=%{public}s enable=%{public}d",
            constraintData.localId, constraintData.constraint.c_str(), constraintData.isEnabled);
        std::unique_lock<std::mutex> lock(mutex_);
        isReady_ = true;
        count_++;
        cv_.notify_one();
        return;
    }

    void WaitForCallBack()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait_for(
            lock, std::chrono::seconds(1), [this]() { return this->isReady_; });
        isReady_ = false;
        ACCOUNT_LOGI("End");
    }

    std::condition_variable cv_;
    bool isReady_ = false;
    std::mutex mutex_;
    int32_t count_ = 0;
};

class MockOsAccountConstraintEventListener : public OsAccountConstraintEventStub {
public:
    ErrCode OnConstraintChanged(int localId, const std::set<std::string> &constraints, bool enable)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        isReady_ = true;
        count_++;
        cv_.notify_one();
        return ERR_OK;
    }

    void WaitForCallBack()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait_for(
            lock, std::chrono::seconds(1), [this]() { return this->isReady_; });
        isReady_ = false;
        ACCOUNT_LOGI("End");
    }

    std::condition_variable cv_;
    bool isReady_ = false;
    std::mutex mutex_;
    int32_t count_ = 0;
};

/**
 * @tc.name: OsAccountTest001
 * @tc.desc: Test CreateOsAccount string name out of range
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountTest001, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = g_osAccount->CreateOsAccount(STRING_NAME_OUT_OF_RANGE, OsAccountType::GUEST, osAccountInfo);
    osAccountInfo.SetShortName("shortName");
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: OsAccountTest002
 * @tc.desc: Test CreateOsAccount string name is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountTest002, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = g_osAccount->CreateOsAccount(STRING_EMPTY, OsAccountType::GUEST, osAccountInfo);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: OsAccountTest003
 * @tc.desc: Test RemoveOsAccount Id error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountTest003, TestSize.Level1)
{
    ErrCode errCode = g_osAccount->RemoveOsAccount(0);
    EXPECT_EQ(errCode, ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR);
    errCode = g_osAccount->RemoveOsAccount(100);
    EXPECT_EQ(errCode, ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR);
    errCode = g_osAccount->RemoveOsAccount(1100);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: OsAccountTest004
 * @tc.desc: Test SetOsAccountName string name out of range
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountTest004, TestSize.Level1)
{
    ErrCode errCode = g_osAccount->SetOsAccountName(100, STRING_NAME_OUT_OF_RANGE);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: OsAccountTest005
 * @tc.desc: Test SetOsAccountName name is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountTest005, TestSize.Level1)
{
    ErrCode errCode = g_osAccount->SetOsAccountName(100, STRING_EMPTY);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: OsAccountTest006
 * @tc.desc: Test SetOsAccountProfilePhoto string photo out of range
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountTest006, TestSize.Level1)
{
    ErrCode errCode = g_osAccount->SetOsAccountProfilePhoto(100, STRING_PHOTO_OUT_OF_RANGE);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: OsAccountTest007
 * @tc.desc: Test SetDomainInfo with valid info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountTest007, TestSize.Level1)
{
    DomainAccountInfo domainInfo(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    bool checkValid = (domainInfo.accountName_ == STRING_DOMAIN_ACCOUNT_NAME_VALID);
    EXPECT_EQ(checkValid, true);
    checkValid = (domainInfo.domain_ == STRING_DOMAIN_VALID);
    EXPECT_EQ(checkValid, true);

    domainInfo.Clear();
    checkValid = (domainInfo.accountName_ == "");
    EXPECT_EQ(checkValid, true);
    checkValid = (domainInfo.domain_ == "");
    EXPECT_EQ(checkValid, true);
}

/**
 * @tc.name: OsAccountTest008
 * @tc.desc: Test SetDomainInfo with valid info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountTest008, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    DomainAccountInfo domainInfo(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    EXPECT_EQ(osAccountInfo.SetDomainInfo(domainInfo), true);

    DomainAccountInfo getDomainInfo;
    osAccountInfo.GetDomainInfo(getDomainInfo);

    bool checkValid = (getDomainInfo.accountName_ == domainInfo.accountName_);
    EXPECT_EQ(checkValid, true);
    checkValid = (getDomainInfo.domain_ == domainInfo.domain_);
    EXPECT_EQ(checkValid, true);
}

/**
 * @tc.name: OsAccountTest009
 * @tc.desc: Test SetDomainInfo with in valid info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountTest009, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    DomainAccountInfo domainInfoNameInvalid(STRING_DOMAIN_NAME_OUT_OF_RANGE, STRING_DOMAIN_ACCOUNT_NAME_VALID);
    EXPECT_EQ(osAccountInfo.SetDomainInfo(domainInfoNameInvalid), false);

    DomainAccountInfo domainInfoAccountInvalid(STRING_DOMAIN_VALID, STRING_DOMAIN_ACCOUNT_NAME_OUT_OF_RANGE);
    EXPECT_EQ(osAccountInfo.SetDomainInfo(domainInfoAccountInvalid), false);
}

/**
 * @tc.name: OsAccountTest011
 * @tc.desc: Test CreateOsAccount name is empty.
 * @tc.type: FUNC
 * @tc.require:
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(OsAccountTest, OsAccountTest011, TestSize.Level1)
{
    OsAccountType type = NORMAL;
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(ERR_ACCOUNT_COMMON_INVALID_PARAMETER,
        osAccountProxy_->CreateOsAccount(STRING_EMPTY, type, osAccountInfo));
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: OsAccountTest016
 * @tc.desc: Test IsOsAccountConstraintEnable/CheckOsAccountConstraintEnabled constraint is illegal.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountTest016, TestSize.Level1)
{
    bool isConstraintEnable;
    EXPECT_EQ(ERR_ACCOUNT_COMMON_INVALID_PARAMETER,
        osAccountProxy_->IsOsAccountConstraintEnable(MAIN_ACCOUNT_ID, STRING_EMPTY, isConstraintEnable));
    EXPECT_EQ(ERR_ACCOUNT_COMMON_INVALID_PARAMETER,
        osAccountProxy_->CheckOsAccountConstraintEnabled(MAIN_ACCOUNT_ID, STRING_EMPTY, isConstraintEnable));

    EXPECT_EQ(ERR_ACCOUNT_COMMON_INVALID_PARAMETER, osAccountProxy_->IsOsAccountConstraintEnable(
        MAIN_ACCOUNT_ID, STRING_CONSTRAINT_OUT_OF_RANGE, isConstraintEnable));
    EXPECT_EQ(ERR_ACCOUNT_COMMON_INVALID_PARAMETER, osAccountProxy_->CheckOsAccountConstraintEnabled(
        MAIN_ACCOUNT_ID, STRING_CONSTRAINT_OUT_OF_RANGE, isConstraintEnable));
}

/**
 * @tc.name: OsAccountTest017
 * @tc.desc: Test SetGlobalOsAccountConstraints local id is illegal.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountTest017, TestSize.Level1)
{
    EXPECT_EQ(ERR_OSACCOUNT_KIT_READ_IN_LOCAL_ID_ERROR,
        osAccountProxy_->SetGlobalOsAccountConstraints(CONSTANTS_VECTOR, false, ILLEGAL_LOCAL_ID, false));
}

/**
 * @tc.name: OsAccountTest018
 * @tc.desc: Test SetSpecificOsAccountConstraints local id is illegal.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountTest018, TestSize.Level1)
{
    EXPECT_EQ(ERR_OSACCOUNT_KIT_READ_IN_LOCAL_ID_ERROR, osAccountProxy_->SetSpecificOsAccountConstraints(
        CONSTANTS_VECTOR, false, ILLEGAL_LOCAL_ID, MAIN_ACCOUNT_ID, false));
    EXPECT_EQ(ERR_OSACCOUNT_KIT_READ_IN_LOCAL_ID_ERROR, osAccountProxy_->SetSpecificOsAccountConstraints(
        CONSTANTS_VECTOR, false, MAIN_ACCOUNT_ID, ILLEGAL_LOCAL_ID, false));
}

/**
 * @tc.name: OsAccountTest019
 * @tc.desc: test ResetOsAccountProxy normal branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountTest019, TestSize.Level1)
{
    EXPECT_EQ(g_osAccount->ResetOsAccountProxy(), ERR_OK);
}

/**
 * @tc.name: OsAccountTest020
 * @tc.desc: test SubscribeOsAccountConstraints normal branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountTest020, TestSize.Level1)
{
    std::set<std::string> constraints;
    auto failSubsriber = std::make_shared<MockOsAccountConstraintSubscriber>(constraints);
    EXPECT_EQ(g_osAccount->SubscribeOsAccountConstraints(nullptr), ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    EXPECT_EQ(g_osAccount->UnsubscribeOsAccountConstraints(nullptr), ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    EXPECT_EQ(g_osAccount->SubscribeOsAccountConstraints(failSubsriber), ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    constraints = {STRING_NAME};
    failSubsriber = std::make_shared<MockOsAccountConstraintSubscriber>(constraints);
    EXPECT_EQ(g_osAccount->UnsubscribeOsAccountConstraints(failSubsriber),
        ERR_ACCOUNT_COMMON_ACCOUNT_SUBSCRIBE_NOT_FOUND_ERROR);
    EXPECT_NE(g_osAccount->SubscribeOsAccountConstraints(failSubsriber), ERR_OK);
    constraints = {CONSTRAINT_WIFI};
    auto wifiSubscriber = std::make_shared<MockOsAccountConstraintSubscriber>(constraints);
    auto wifiSubscriber2 = std::make_shared<MockOsAccountConstraintSubscriber>(constraints);
    EXPECT_EQ(g_osAccount->SubscribeOsAccountConstraints(wifiSubscriber), ERR_OK);
    EXPECT_EQ(g_osAccount->SubscribeOsAccountConstraints(wifiSubscriber2), ERR_OK);
    EXPECT_EQ(g_osAccount->UnsubscribeOsAccountConstraints(wifiSubscriber2), ERR_OK);
    bool isEnabled = false;
    EXPECT_EQ(g_osAccount->IsOsAccountConstraintEnable(Constants::START_USER_ID, CONSTRAINT_WIFI, isEnabled), ERR_OK);
    std::vector<std::string> vec = {CONSTRAINT_WIFI};
    EXPECT_EQ(g_osAccount->SetOsAccountConstraints(Constants::START_USER_ID, vec, !isEnabled), ERR_OK);
    wifiSubscriber->WaitForCallBack();
    EXPECT_EQ(wifiSubscriber->count_, 1);
    constraints = {CONSTRAINT_TIME_OUT};
    auto timeoutSubscriber = std::make_shared<MockOsAccountConstraintSubscriber>(constraints);
    EXPECT_EQ(g_osAccount->SubscribeOsAccountConstraints(timeoutSubscriber), ERR_OK);
    EXPECT_EQ(g_osAccount->SubscribeOsAccountConstraints(wifiSubscriber),
        ERR_ACCOUNT_COMMON_ACCOUNT_AREADY_SUBSCRIBE_ERROR);
    std::set<std::shared_ptr<OsAccountConstraintSubscriber>> subscriberSet =
        g_osAccount->constraintSubscriberMgr_->subscriberSet_;
    std::set<std::string> constraintSet = g_osAccount->constraintSubscriberMgr_->constraintSet_;
    std::map<std::string, std::set<std::shared_ptr<OsAccountConstraintSubscriber>>> constraint2SubscriberMap =
        g_osAccount->constraintSubscriberMgr_->constraint2SubscriberMap_;
    g_osAccount->RestoreConstraintSubscriberRecords();
    EXPECT_EQ(g_osAccount->UnsubscribeOsAccountConstraints(wifiSubscriber), ERR_OK);
    EXPECT_EQ(g_osAccount->UnsubscribeOsAccountConstraints(timeoutSubscriber), ERR_OK);
    g_osAccount->RestoreConstraintSubscriberRecords();
    g_osAccount->constraintSubscriberMgr_->constraint2SubscriberMap_ = constraint2SubscriberMap;
    g_osAccount->constraintSubscriberMgr_->subscriberSet_ = subscriberSet;
    g_osAccount->constraintSubscriberMgr_->constraintSet_ = constraintSet;
    g_osAccount->RestoreConstraintSubscriberRecords();
    EXPECT_EQ(g_osAccount->UnsubscribeOsAccountConstraints(wifiSubscriber), ERR_OK);
    EXPECT_EQ(g_osAccount->UnsubscribeOsAccountConstraints(timeoutSubscriber), ERR_OK);
}

/**
 * @tc.name: OsAccountTest021
 * @tc.desc: test SubscribeOsAccountConstraints normal branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountTest021, TestSize.Level1)
{
    std::set<std::string> constraints;
    constraints = {CONSTRAINT_WIFI};
    auto wifiSubscriber = std::make_shared<MockOsAccountConstraintSubscriber>(constraints);
    auto wifiSubscriber2 = std::make_shared<MockOsAccountConstraintSubscriber>(constraints);
    std::set<std::string> constraints2;
    constraints2 = {CONSTRAINT_TIME_OUT};
    auto timeoutSubscriber = std::make_shared<MockOsAccountConstraintSubscriber>(constraints2);
    EXPECT_EQ(OsAccountConstraintSubscriberManager::GetInstance().SubscribeOsAccountConstraints(
        wifiSubscriber, g_osAccount->proxy_), ERR_OK);
    EXPECT_EQ(OsAccountConstraintSubscriberManager::GetInstance().SubscribeOsAccountConstraints(
        wifiSubscriber2, g_osAccount->proxy_), ERR_OK);
    EXPECT_EQ(OsAccountConstraintSubscriberManager::GetInstance().SubscribeOsAccountConstraints(
        timeoutSubscriber, g_osAccount->proxy_), ERR_OK);
    bool isEnabled = false;
    EXPECT_EQ(g_osAccount->IsOsAccountConstraintEnable(Constants::START_USER_ID, CONSTRAINT_WIFI, isEnabled), ERR_OK);
    std::vector<std::string> vec = {CONSTRAINT_WIFI};
    EXPECT_EQ(g_osAccount->SetOsAccountConstraints(Constants::START_USER_ID, vec, !isEnabled), ERR_OK);
    EXPECT_EQ(OsAccountConstraintSubscriberManager::GetInstance().UnsubscribeOsAccountConstraints(
        wifiSubscriber, g_osAccount->proxy_), ERR_OK);
    EXPECT_EQ(OsAccountConstraintSubscriberManager::GetInstance().UnsubscribeOsAccountConstraints(
        wifiSubscriber2, g_osAccount->proxy_), ERR_OK);
    EXPECT_EQ(OsAccountConstraintSubscriberManager::GetInstance().UnsubscribeOsAccountConstraints(
        timeoutSubscriber, g_osAccount->proxy_), ERR_OK);
}

/**
 * @tc.name: OsAccountTest022
 * @tc.desc: test SubscribeOsAccountConstraints callback time check.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountTest022, TestSize.Level1)
{
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    ASSERT_TRUE(MockTokenId("edm"));
    std::set<std::string> constraints;
    constraints = {CONSTRAINT_WIFI};
    OsAccountConstraintSubscribeInfo subscribeInfo(constraints);
    auto listener = new (std::nothrow) MockOsAccountConstraintEventListener();
    ErrCode errCode = g_osAccount->proxy_->SubscribeOsAccountConstraints(subscribeInfo, listener->AsObject());
    EXPECT_EQ(errCode, ERR_OK);
    errCode = g_osAccount->proxy_->SubscribeOsAccountConstraints(subscribeInfo, listener->AsObject());
    EXPECT_EQ(errCode, ERR_OK);
    std::set<std::string>  constraints2 = {CONSTRAINT_WIFI, CONSTRAINT_TIME_OUT};
    OsAccountConstraintSubscribeInfo subscribeInfo2(constraints2);
    errCode = g_osAccount->proxy_->SubscribeOsAccountConstraints(subscribeInfo2, listener->AsObject());
    EXPECT_EQ(errCode, ERR_OK);
    bool isEnabled = false;
    EXPECT_EQ(g_osAccount->IsOsAccountConstraintEnable(Constants::START_USER_ID, CONSTRAINT_WIFI, isEnabled), ERR_OK);
    std::vector<std::string> vec = {CONSTRAINT_WIFI};
    EXPECT_EQ(g_osAccount->SetOsAccountConstraints(Constants::START_USER_ID, vec, !isEnabled), ERR_OK);
    EXPECT_EQ(g_osAccount->SetOsAccountConstraints(NOT_EXSIT_ID, vec, !isEnabled),
        ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
    listener->WaitForCallBack();
    EXPECT_EQ(listener->count_, 1);
    vec = {CONSTRAINT_TIME_OUT};
    isEnabled = !isEnabled;
    EXPECT_EQ(g_osAccount->IsOsAccountConstraintEnable(
        Constants::START_USER_ID, CONSTRAINT_TIME_OUT, isEnabled), ERR_OK);
    EXPECT_EQ(g_osAccount->SetSpecificOsAccountConstraints(
        vec, !isEnabled, MAIN_ACCOUNT_ID, MAIN_ACCOUNT_ID, false), ERR_OK);
    EXPECT_EQ(g_osAccount->SetSpecificOsAccountConstraints(
        vec, !isEnabled, NOT_EXSIT_ID, NOT_EXSIT_ID, false), ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
    listener->WaitForCallBack();
    EXPECT_EQ(listener->count_, 2);
    vec = {CONSTRAINT_SHARE};
    EXPECT_EQ(g_osAccount->IsOsAccountConstraintEnable(Constants::START_USER_ID, CONSTRAINT_SHARE, isEnabled), ERR_OK);
    EXPECT_EQ(g_osAccount->SetGlobalOsAccountConstraints(vec, !isEnabled, MAIN_ACCOUNT_ID, false), ERR_OK);
    EXPECT_EQ(g_osAccount->SetGlobalOsAccountConstraints(vec, !isEnabled, NOT_EXSIT_ID, false),
        ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
    listener->WaitForCallBack();
    EXPECT_EQ(listener->count_, 2);
    ASSERT_TRUE(SetSelfTokenID(selfTokenId) == 0);
}

/**
 * @tc.name: InsertSubscriberRecord001
 * @tc.desc: Test OsAccountConstraintSubscriberManager InsertSubscriberRecord
 * @tc.type: FUNC
 * @tc.require: issueI6AQUQ
 */
HWTEST_F(OsAccountTest, InsertSubscriberRecord001, TestSize.Level1)
{
    auto listener = new (std::nothrow) OsAccountConstraintSubscriberManager();
    std::set<std::string> constraints = {STRING_NAME};
    auto subscriber = std::make_shared<MockOsAccountConstraintSubscriber>(constraints);
    EXPECT_EQ(listener->HasSubscribed(subscriber), false);
    listener->InsertSubscriberRecord(subscriber);
    EXPECT_EQ(listener->subscriberSet_.size(), 1);
    EXPECT_EQ(listener->HasSubscribed(subscriber), true);
    EXPECT_EQ(listener->HasSubscribed(subscriber), true);
    listener->InsertSubscriberRecord(subscriber);
    EXPECT_EQ(listener->subscriberSet_.size(), 1);
    auto subscriber2 = std::make_shared<MockOsAccountConstraintSubscriber>(constraints);
    EXPECT_EQ(listener->HasSubscribed(subscriber2), false);
    listener->InsertSubscriberRecord(subscriber2);
    EXPECT_EQ(listener->subscriberSet_.size(), 2);
    EXPECT_EQ(listener->constraint2SubscriberMap_.size(), 1);
    EXPECT_EQ(listener->OnConstraintChanged(1, constraints, true), ERR_OK);
    listener->RemoveSubscriberRecord(subscriber2);
    EXPECT_EQ(listener->constraint2SubscriberMap_.size(), 1);
    EXPECT_EQ(listener->subscriberSet_.size(), 1);
    listener->RemoveSubscriberRecord(subscriber);
    EXPECT_EQ(listener->constraint2SubscriberMap_.size(), 0);
    EXPECT_EQ(listener->subscriberSet_.size(), 0);
}

/**
 * @tc.name: InsertSubscriberRecord001
 * @tc.desc: Test OsAccountConstraintSubscriberManager constraints size too large
 * @tc.type: FUNC
 * @tc.require: issueI6AQUQ
 */
HWTEST_F(OsAccountTest, SubscribeConstraints001, TestSize.Level1)
{
    auto listener = new (std::nothrow) OsAccountConstraintSubscriberManager();
    std::set<std::string> constraints;
    for (int i = 0; i <= Constants::CONSTRAINT_MAX_SIZE; i++) {
        constraints.emplace(std::to_string(i));
    }
    auto subscriber = std::make_shared<MockOsAccountConstraintSubscriber>(constraints);
    EXPECT_EQ(listener->SubscribeOsAccountConstraints(subscriber, g_osAccount->proxy_),
        ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}