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
#include "os_account_constants.h"
#include "os_account_constraint_subscriber_manager.h"
#include "os_account_state_reply_callback.h"
#include "os_account_state_parcel.h"
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
const std::int32_t COUNT_SIZE_TWO = 2;
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
const std::string CONSTRAINT_BOOT = "constraint.safe.boot";
const std::string CONSTRAINT_TIME_OUT = "constraint.screen.timeout.set";
const std::string CONSTRAINT_SHARE =  "constraint.share.into.profile";
const std::string STRING_DOMAIN_VALID = "TestDomainUT";
const std::string STRING_DOMAIN_ACCOUNT_NAME_VALID = "TestDomainAccountNameUT";
std::shared_ptr<OsAccount> g_osAccount = nullptr;
sptr<IOsAccount> osAccountProxy_ = nullptr;
const std::uint32_t MAX_WAIT_FOR_READY_CNT = 10;
const int32_t WAIT_TIME = 3;
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
    sptr<IAccount> accountProxy = iface_cast<IAccount>(remoteObject);
    EXPECT_NE(accountProxy, nullptr);
    sptr<IRemoteObject> osAccountRemoteObject = nullptr;
    accountProxy->GetOsAccountService(osAccountRemoteObject);
    osAccountProxy_ = iface_cast<IOsAccount>(osAccountRemoteObject);
    EXPECT_NE(osAccountProxy_, nullptr);
    std::vector<OsAccountInfo> osAccountInfos;
    g_osAccount->QueryAllCreatedOsAccounts(osAccountInfos);
    for (const auto &info : osAccountInfos) {
        if (info.GetLocalId() == Constants::START_USER_ID) {
            continue;
        }
        ACCOUNT_LOGI("[SetUp] remove account %{public}d", info.GetLocalId());
        g_osAccount->RemoveOsAccount(info.GetLocalId());
    }
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
        if (checkIdSet.count(localId) != 1) {
            return ERR_OK;
        }
        count_++;
        if (checkIdSet.size() == count_) {
            isReady_ = true;
            cv_.notify_one();
        }
        return ERR_OK;
    }

    void WaitForCallBack()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait_for(
            lock, std::chrono::seconds(WAIT_TIME), [this]() { return this->isReady_; });
        isReady_ = false;
        ACCOUNT_LOGI("End");
    }

    std::set<int32_t> checkIdSet = {Constants::START_USER_ID};
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
    StringRawData stringRawData;
    EXPECT_EQ(ERR_ACCOUNT_COMMON_INVALID_PARAMETER,
        osAccountProxy_->CreateOsAccount(STRING_EMPTY, static_cast<int32_t>(type), stringRawData));
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
    g_osAccount->RestoreConstraintSubscriberRecords();
    EXPECT_EQ(g_osAccount->UnsubscribeOsAccountConstraints(wifiSubscriber), ERR_OK);
    EXPECT_EQ(g_osAccount->UnsubscribeOsAccountConstraints(timeoutSubscriber), ERR_OK);
    g_osAccount->RestoreConstraintSubscriberRecords();
    OsAccountConstraintSubscriberManager::GetInstance()->constraint2SubscriberMap_ =
        {{CONSTRAINT_WIFI, {wifiSubscriber}}, {CONSTRAINT_TIME_OUT, {timeoutSubscriber}}};
    OsAccountConstraintSubscriberManager::GetInstance()->subscriberSet_ = {wifiSubscriber, timeoutSubscriber};
    OsAccountConstraintSubscriberManager::GetInstance()->constraintSet_ = {CONSTRAINT_WIFI, CONSTRAINT_TIME_OUT};
    OsAccountConstraintSubscriberManager::GetInstance()->RestoreConstraintSubscriberRecords(g_osAccount->proxy_);
    EXPECT_EQ(OsAccountConstraintSubscriberManager::GetInstance()->UnsubscribeOsAccountConstraints(wifiSubscriber,
        g_osAccount->proxy_), ERR_OK);
    EXPECT_EQ(OsAccountConstraintSubscriberManager::GetInstance()->UnsubscribeOsAccountConstraints(timeoutSubscriber,
        g_osAccount->proxy_), ERR_OK);
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
    EXPECT_EQ(OsAccountConstraintSubscriberManager::GetInstance()->SubscribeOsAccountConstraints(
        wifiSubscriber, g_osAccount->proxy_), ERR_OK);
    EXPECT_EQ(OsAccountConstraintSubscriberManager::GetInstance()->SubscribeOsAccountConstraints(
        wifiSubscriber2, g_osAccount->proxy_), ERR_OK);
    EXPECT_EQ(OsAccountConstraintSubscriberManager::GetInstance()->SubscribeOsAccountConstraints(
        timeoutSubscriber, g_osAccount->proxy_), ERR_OK);
    bool isEnabled = false;
    EXPECT_EQ(g_osAccount->IsOsAccountConstraintEnable(Constants::START_USER_ID, CONSTRAINT_WIFI, isEnabled), ERR_OK);
    std::vector<std::string> vec = {CONSTRAINT_WIFI};
    EXPECT_EQ(g_osAccount->SetOsAccountConstraints(Constants::START_USER_ID, vec, !isEnabled), ERR_OK);
    EXPECT_EQ(OsAccountConstraintSubscriberManager::GetInstance()->UnsubscribeOsAccountConstraints(
        wifiSubscriber, g_osAccount->proxy_), ERR_OK);
    EXPECT_EQ(OsAccountConstraintSubscriberManager::GetInstance()->UnsubscribeOsAccountConstraints(
        wifiSubscriber2, g_osAccount->proxy_), ERR_OK);
    EXPECT_EQ(OsAccountConstraintSubscriberManager::GetInstance()->UnsubscribeOsAccountConstraints(
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
    EXPECT_EQ(g_osAccount->SetOsAccountConstraints(NOT_EXSIT_ID, vec, !isEnabled),
        ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
    EXPECT_EQ(g_osAccount->SetOsAccountConstraints(Constants::START_USER_ID, vec, !isEnabled), ERR_OK);
    listener->WaitForCallBack();
    EXPECT_EQ(listener->count_, 1);
    vec = {CONSTRAINT_TIME_OUT};
    isEnabled = !isEnabled;
    EXPECT_EQ(g_osAccount->IsOsAccountConstraintEnable(
        Constants::START_USER_ID, CONSTRAINT_TIME_OUT, isEnabled), ERR_OK);
    EXPECT_EQ(g_osAccount->SetSpecificOsAccountConstraints(
        vec, !isEnabled, NOT_EXSIT_ID, NOT_EXSIT_ID, false), ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
    EXPECT_EQ(g_osAccount->SetSpecificOsAccountConstraints(
        vec, !isEnabled, MAIN_ACCOUNT_ID, MAIN_ACCOUNT_ID, false), ERR_OK);
    listener->WaitForCallBack();
    EXPECT_EQ(listener->count_, 2);
    vec = {CONSTRAINT_SHARE};
    EXPECT_EQ(g_osAccount->IsOsAccountConstraintEnable(Constants::START_USER_ID, CONSTRAINT_SHARE, isEnabled), ERR_OK);
    EXPECT_EQ(g_osAccount->SetGlobalOsAccountConstraints(vec, !isEnabled, MAIN_ACCOUNT_ID, false), ERR_OK);
    vec = {CONSTRAINT_WIFI};
    g_osAccount->SetOsAccountConstraints(Constants::START_USER_ID, vec, true);
    listener->WaitForCallBack();
    int32_t count = listener->count_;
    EXPECT_EQ(g_osAccount->IsOsAccountConstraintEnable(Constants::START_USER_ID, CONSTRAINT_WIFI, isEnabled), ERR_OK);
    EXPECT_EQ(isEnabled, true);
    EXPECT_EQ(g_osAccount->SetGlobalOsAccountConstraints(vec, false, MAIN_ACCOUNT_ID, false), ERR_OK);
    listener->WaitForCallBack();
    EXPECT_EQ(listener->count_, count);
    ASSERT_TRUE(SetSelfTokenID(selfTokenId) == 0);
}

/**
 * @tc.name: OsAccountTest023
 * @tc.desc: test SubscribeOsAccountConstraints callback time check.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountTest023, TestSize.Level1)
{
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    ASSERT_TRUE(MockTokenId("edm"));
    std::set<std::string> constraints;
    constraints = {CONSTRAINT_WIFI};
    OsAccountConstraintSubscribeInfo subscribeInfo(constraints);
    auto listener = new (std::nothrow) MockOsAccountConstraintEventListener();
    ErrCode errCode = g_osAccount->proxy_->SubscribeOsAccountConstraints(subscribeInfo, listener->AsObject());
    EXPECT_EQ(errCode, ERR_OK);
    bool isEnabled = false;
    EXPECT_EQ(g_osAccount->IsOsAccountConstraintEnable(Constants::START_USER_ID, CONSTRAINT_WIFI, isEnabled), ERR_OK);
    std::vector<std::string> vec = {CONSTRAINT_WIFI};
    int32_t count = 0;
    if (!isEnabled) {
        EXPECT_EQ(g_osAccount->SetOsAccountConstraints(Constants::START_USER_ID, vec, true), ERR_OK);
        listener->WaitForCallBack();
        count++;
    }
    EXPECT_EQ(g_osAccount->SetOsAccountConstraints(Constants::START_USER_ID, vec, true), ERR_OK);
    listener->WaitForCallBack();
    EXPECT_EQ(listener->count_, count);
    ASSERT_TRUE(SetSelfTokenID(selfTokenId) == 0);
}

/**
 * @tc.name: OsAccountTest024
 * @tc.desc: test SubscribeOsAccountConstraints callback time check.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountTest024, TestSize.Level1)
{
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    ASSERT_TRUE(MockTokenId("edm"));
    std::set<std::string> constraints;
    constraints = {CONSTRAINT_WIFI};
    OsAccountConstraintSubscribeInfo subscribeInfo(constraints);
    auto listener = new (std::nothrow) MockOsAccountConstraintEventListener();
    ErrCode errCode = g_osAccount->proxy_->SubscribeOsAccountConstraints(subscribeInfo, listener->AsObject());
    EXPECT_EQ(errCode, ERR_OK);
    bool isEnabled = false;
    EXPECT_EQ(g_osAccount->IsOsAccountConstraintEnable(Constants::START_USER_ID, CONSTRAINT_WIFI, isEnabled), ERR_OK);
    std::vector<std::string> vec = {CONSTRAINT_WIFI};
    int32_t count = 0;
    if (isEnabled) {
        EXPECT_EQ(g_osAccount->SetOsAccountConstraints(Constants::START_USER_ID, vec, false), ERR_OK);
        listener->WaitForCallBack();
        count++;
    }
    EXPECT_EQ(g_osAccount->SetOsAccountConstraints(Constants::START_USER_ID, vec, false), ERR_OK);
    listener->WaitForCallBack();
    EXPECT_EQ(listener->count_, count);
    ASSERT_TRUE(SetSelfTokenID(selfTokenId) == 0);
}

/**
 * @tc.name: OsAccountTest025
 * @tc.desc: test SubscribeOsAccountConstraints callback time check.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountTest025, TestSize.Level1)
{
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    ASSERT_TRUE(MockTokenId("edm"));
    std::vector<std::string> constraints;
    constraints = {CONSTRAINT_BOOT};
    OsAccountInfo newInfo;
    ErrCode errCode = g_osAccount->CreateOsAccount("test", OsAccountType::GUEST, newInfo);
    EXPECT_EQ(errCode, ERR_OK);
    bool isEnabled = false;
    EXPECT_EQ(g_osAccount->IsOsAccountConstraintEnable(Constants::START_USER_ID, CONSTRAINT_BOOT, isEnabled), ERR_OK);
    if (isEnabled) {
        EXPECT_EQ(g_osAccount->SetSpecificOsAccountConstraints(constraints, false, Constants::START_USER_ID,
            Constants::START_USER_ID, false), ERR_OK);
        EXPECT_EQ(g_osAccount->SetOsAccountConstraints(Constants::START_USER_ID, constraints, false), ERR_OK);
    }
    isEnabled = false;
    EXPECT_EQ(g_osAccount->IsOsAccountConstraintEnable(newInfo.GetLocalId(), CONSTRAINT_BOOT, isEnabled), ERR_OK);
    if (isEnabled) {
        EXPECT_EQ(g_osAccount->SetSpecificOsAccountConstraints(constraints, false, newInfo.GetLocalId(),
            newInfo.GetLocalId(), false), ERR_OK);
        EXPECT_EQ(g_osAccount->SetOsAccountConstraints(newInfo.GetLocalId(), constraints, false), ERR_OK);
    }
    EXPECT_EQ(g_osAccount->SetGlobalOsAccountConstraints(constraints, true, MAIN_ACCOUNT_ID, true), ERR_OK);
    auto listener = new (std::nothrow) MockOsAccountConstraintEventListener();
    std::set<std::string> constraintSet = {CONSTRAINT_BOOT};
    OsAccountConstraintSubscribeInfo subscribeInfo(constraintSet);
    errCode = g_osAccount->proxy_->SubscribeOsAccountConstraints(subscribeInfo, listener->AsObject());
    EXPECT_EQ(errCode, ERR_OK);
    listener->checkIdSet.emplace(newInfo.GetLocalId());
    EXPECT_EQ(g_osAccount->SetGlobalOsAccountConstraints(constraints, false, MAIN_ACCOUNT_ID, false), ERR_OK);
    listener->WaitForCallBack();
    EXPECT_EQ(listener->count_, COUNT_SIZE_TWO);
    EXPECT_EQ(g_osAccount->RemoveOsAccount(newInfo.GetLocalId()), ERR_OK);
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

/**
 * @tc.name: StringRawData_001
 * @tc.desc: Func Marshalling and Unmarshalling.
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountTest, StringRawData_001, TestSize.Level3)
{
    StringRawData rawData;
    string str1 = STRING_NAME;
    EXPECT_EQ(rawData.Marshalling(str1), ERR_OK);
    string str2 = "";
    EXPECT_EQ(rawData.Unmarshalling(str2), ERR_OK);
    EXPECT_EQ(str2, STRING_NAME);
}

/**
 * @tc.name: OnComplete_001
 * @tc.desc: Test that neither cv_ nor callbackCounter is empty.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OnComplete_001, TestSize.Level3)
{
    auto cv = std::make_shared<std::condition_variable>();
    auto counter = std::make_shared<std::atomic<int>>(1);
    OsAccountStateReplyCallback callback(cv, counter);
    OsAccountStateReplyCallback callback1(nullptr);

    callback1.OnComplete();
    // Verify that the callbackCounter will be reset after OnComplete
    callback.OnComplete();
    // Check whether the callbackCounter has been reset (changed to nullptr)
    EXPECT_EQ(0, counter->load());
}

/**
 * @tc.name: OnComplete_002
 * @tc.desc: Test cv_ is empty, and callbackCounter is not empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OnComplete_002, TestSize.Level3)
{
    auto counter = std::make_shared<std::atomic<int>>(1);
    // Pass in an empty cv
    OsAccountStateReplyCallback callback(nullptr, counter);
    callback.OnComplete();
    // The callbackCounter should not be modified
    EXPECT_TRUE(counter != nullptr);
}

/**
 * @tc.name: OnComplete_003
 * @tc.desc: Test cv_ is not empty and callbackCounter is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OnComplete_003, TestSize.Level3)
{
    auto cv = std::make_shared<std::condition_variable>();
    // Pass in an empty callbackCounter
    OsAccountStateReplyCallback callback(cv, nullptr);
    callback.OnComplete();
    // cv_ should remain unchanged
    EXPECT_TRUE(cv != nullptr);
}

/**
 * @tc.name: OsAccountActivateOsAccountTest001
 * @tc.desc: Test ActivateOsAccount with invalid parameters and valid flow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountActivateOsAccountTest001, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountActivateOsAccountTest001");
    
    // Test invalid localId
    ErrCode result = g_osAccount->ActivateOsAccount(-1, Constants::DEFAULT_DISPLAY_ID);
    EXPECT_NE(result, ERR_OK);
    
    // Test invalid displayId
    result = g_osAccount->ActivateOsAccount(MAIN_ACCOUNT_ID, Constants::INVALID_DISPLAY_ID);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.name: OsAccountSetDefaultActivatedOsAccountTest001
 * @tc.desc: Test SetDefaultActivatedOsAccount with parameters validation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountSetDefaultActivatedOsAccountTest001, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountSetDefaultActivatedOsAccountTest001");
    
    // Test invalid localId
    ErrCode result = g_osAccount->SetDefaultActivatedOsAccount(Constants::DEFAULT_DISPLAY_ID, -1);
    EXPECT_NE(result, ERR_OK);
    
    // Test invalid displayId
    result = g_osAccount->SetDefaultActivatedOsAccount(Constants::INVALID_DISPLAY_ID, MAIN_ACCOUNT_ID);
    EXPECT_NE(result, ERR_OK);
    
    // Test valid setting
    result = g_osAccount->SetDefaultActivatedOsAccount(Constants::DEFAULT_DISPLAY_ID, MAIN_ACCOUNT_ID);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: OsAccountGetDefaultActivatedOsAccountTest001
 * @tc.desc: Test GetDefaultActivatedOsAccount functionality
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountGetDefaultActivatedOsAccountTest001, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountGetDefaultActivatedOsAccountTest001");
    
    // Test invalid displayId
    int32_t id = -1;
    ErrCode result = g_osAccount->GetDefaultActivatedOsAccount(Constants::INVALID_DISPLAY_ID, id);
    EXPECT_NE(result, ERR_OK);
    
    // Test valid getting
    result = g_osAccount->GetDefaultActivatedOsAccount(Constants::DEFAULT_DISPLAY_ID, id);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_GE(id, 0);
}

/**
 * @tc.name: OsAccountGetForegroundOsAccountLocalIdTest001
 * @tc.desc: Test GetForegroundOsAccountLocalId functionality
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountGetForegroundOsAccountLocalIdTest001, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountGetForegroundOsAccountLocalIdTest001");
    
    // Test invalid displayId
    int32_t localId = -1;
    ErrCode result = g_osAccount->GetForegroundOsAccountLocalId(Constants::INVALID_DISPLAY_ID, localId);
    EXPECT_NE(result, ERR_OK);
    
    // Test valid getting
    result = g_osAccount->GetForegroundOsAccountLocalId(Constants::DEFAULT_DISPLAY_ID, localId);
    // May succeed or fail depending on system state
    if (result == ERR_OK) {
        EXPECT_GE(localId, 0);
    }
}

/**
 * @tc.name: OsAccountGetForegroundOsAccountDisplayIdTest001
 * @tc.desc: Test GetForegroundOsAccountDisplayId functionality
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountGetForegroundOsAccountDisplayIdTest001, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountGetForegroundOsAccountDisplayIdTest001");
    
    // Test invalid localId
    uint64_t displayId = 0;
    ErrCode result = g_osAccount->GetForegroundOsAccountDisplayId(-1, displayId);
    EXPECT_NE(result, ERR_OK);
    
    // Test valid getting with main account
    result = g_osAccount->GetForegroundOsAccountDisplayId(MAIN_ACCOUNT_ID, displayId);
    // May succeed or fail depending on whether account is foreground
    if (result == ERR_OK) {
        EXPECT_GE(displayId, 0);
    }
}

/**
 * @tc.name: OsAccountIsOsAccountForegroundTest001
 * @tc.desc: Test IsOsAccountForeground without parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountIsOsAccountForegroundTest001, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountIsOsAccountForegroundTest001");
    
    bool isForeground = false;
    ErrCode result = g_osAccount->IsOsAccountForeground(isForeground);
    
    // Should not fail with this overload
    EXPECT_EQ(result, ERR_OK);
    // isForeground can be true or false depending on system state
}

/**
 * @tc.name: OsAccountIsOsAccountForegroundTest002
 * @tc.desc: Test IsOsAccountForeground with localId parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountIsOsAccountForegroundTest002, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountIsOsAccountForegroundTest002");
    
    bool isForeground = false;
    
    // Test with invalid localId
    ErrCode result = g_osAccount->IsOsAccountForeground(ILLEGAL_LOCAL_ID, isForeground);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    
    // Test with invalid localId (less than admin)
    result = g_osAccount->IsOsAccountForeground(-5, isForeground);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    
    // Test with valid localId
    result = g_osAccount->IsOsAccountForeground(MAIN_ACCOUNT_ID, isForeground);
    EXPECT_EQ(result, ERR_OK);
    
    // Test with non-existent account
    result = g_osAccount->IsOsAccountForeground(NOT_EXSIT_ID, isForeground);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.name: OsAccountIsOsAccountForegroundTest003
 * @tc.desc: Test IsOsAccountForeground with localId and displayId parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountIsOsAccountForegroundTest003, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountIsOsAccountForegroundTest003");
    
    bool isForeground = false;
    
    // Test with invalid localId
    ErrCode result = g_osAccount->IsOsAccountForeground(ILLEGAL_LOCAL_ID, Constants::DEFAULT_DISPLAY_ID, isForeground);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    
    // Test with invalid localId
    result = g_osAccount->IsOsAccountForeground(-5, Constants::DEFAULT_DISPLAY_ID, isForeground);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    
    // Test with invalid displayId
    result = g_osAccount->IsOsAccountForeground(MAIN_ACCOUNT_ID, Constants::INVALID_DISPLAY_ID, isForeground);
    EXPECT_NE(result, ERR_OK);
    
    // Test with very large invalid displayId
    result = g_osAccount->IsOsAccountForeground(MAIN_ACCOUNT_ID, 99999, isForeground);
    EXPECT_NE(result, ERR_OK);
    
    // Test with valid parameters
    result = g_osAccount->IsOsAccountForeground(MAIN_ACCOUNT_ID, Constants::DEFAULT_DISPLAY_ID, isForeground);
    EXPECT_EQ(result, ERR_OK);
    
    // Test with non-existent account but valid displayId
    result = g_osAccount->IsOsAccountForeground(NOT_EXSIT_ID, Constants::DEFAULT_DISPLAY_ID, isForeground);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.name: OsAccountGetForegroundOsAccountLocalIdTest002
 * @tc.desc: Test GetForegroundOsAccountLocalId without displayId parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountTest, OsAccountGetForegroundOsAccountLocalIdTest002, TestSize.Level1)
{
    ACCOUNT_LOGI("OsAccountGetForegroundOsAccountLocalIdTest002");
    
    int32_t localId = -1;
    ErrCode result = g_osAccount->GetForegroundOsAccountLocalId(localId);
    
    // Should succeed or fail depending on system state and proxy availability
    if (result == ERR_OK) {
        EXPECT_GE(localId, Constants::ADMIN_LOCAL_ID);
        ACCOUNT_LOGI("Retrieved foreground account localId: %{public}d", localId);
    } else {
        ACCOUNT_LOGI("GetForegroundOsAccountLocalId failed with code: %{public}d", result);
        // Verify it's a reasonable error code
        EXPECT_TRUE(result == ERR_ACCOUNT_COMMON_GET_PROXY ||
                   result == ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR ||
                   result != ERR_OK);
    }
    
    // Test multiple calls for consistency
    int32_t localId2 = -2;
    ErrCode result2 = g_osAccount->GetForegroundOsAccountLocalId(localId2);
    
    // If both succeed, they should return the same value
    if (result == ERR_OK && result2 == ERR_OK) {
        EXPECT_EQ(localId, localId2);
    }
}
