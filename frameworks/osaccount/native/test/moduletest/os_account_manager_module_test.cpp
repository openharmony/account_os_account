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

#include "os_account_manager_module_test.h"

#include "account_test_common.h"
#ifdef HAS_CES_PART
#include "common_event_manager.h"
#include "common_event_subscriber.h"
#include "common_event_support.h"
#include "common_event_subscribe_info.h"
#include "matching_skills.h"
#endif // HAS_CES_PART
#include "json_utils.h"
#define private public
#include "account_file_operator.h"
#include "os_account.h"
#include "ohos_account_kits_impl.h"
#undef private
#ifdef BUNDLE_ADAPTER_MOCK
#define private public
#include "os_account_manager_service.h"
#include "os_account_proxy.h"
#include "iinner_os_account_manager.h"
#undef private
#endif
#ifdef SUPPORT_LOCK_OS_ACCOUNT
#ifdef BUNDLE_ADAPTER_MOCK
#include "mock_os_account_control_file_manager.h"
#endif
#endif

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::AccountSA::Constants;
using namespace OHOS::EventFwk;

namespace {
static uint64_t g_selfTokenID;
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
OsAccountInfo commonOsAccountInfo;
OsAccountInfo commonOsAccountInfoBack;
const int32_t WAIT_TIME = 20;
#ifdef BUNDLE_ADAPTER_MOCK
const uid_t ACCOUNT_UID = 3058;
const gid_t ACCOUNT_GID = 3058;
#endif
const uid_t ROOT_UID = 0;
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS
std::shared_ptr<AccountFileOperator> g_accountFileOperator = std::make_shared<AccountFileOperator>();

static PermissionDef INFO_MANAGER_TEST_PERM_DEF1 = {
    .permissionName = "open the door",
    .bundleName = "osaccount_test",
    .grantMode = 1,
    .availableLevel = APL_NORMAL,
    .provisionEnable = false,
    .distributedSceneEnable = false,
    .label = "label",
    .labelId = 1,
    .description = "open the door",
    .descriptionId = 1
};

static PermissionDef INFO_MANAGER_TEST_PERM_DEF2 = {
    .permissionName = "break the door",
    .bundleName = "osaccount_test",
    .grantMode = 1,
    .availableLevel = APL_NORMAL,
    .provisionEnable = false,
    .distributedSceneEnable = false,
    .label = "label",
    .labelId = 1,
    .description = "break the door",
    .descriptionId = 1
};

static PermissionStateFull INFO_MANAGER_TEST_STATE1 = {
    .permissionName = "open the door",
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {1},
    .grantFlags = {1}
};

static PermissionStateFull INFO_MANAGER_TEST_STATE2 = {
    .permissionName = "break the door",
    .isGeneral = false,
    .resDeviceID = {"device 1", "device 2"},
    .grantStatus = {1, 3},
    .grantFlags = {1, 2}
};

static HapPolicyParams INFO_MANAGER_TEST_POLICY_PRAMS = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
    .permList = {INFO_MANAGER_TEST_PERM_DEF1, INFO_MANAGER_TEST_PERM_DEF2},
    .permStateList = {INFO_MANAGER_TEST_STATE1, INFO_MANAGER_TEST_STATE2}
};

HapInfoParams infoManagerTestNormalInfoParms = {
    .userID = 1,
    .bundleName = "osaccount_test",
    .instIndex = 0,
    .appIDDesc = "testtesttesttest",
    .apiVersion = DEFAULT_API_VERSION,
    .isSystemApp = false
};

HapInfoParams infoManagerTestSystemInfoParms = {
    .userID = 1,
    .bundleName = "osaccount_test",
    .instIndex = 0,
    .appIDDesc = "testtesttesttest",
    .apiVersion = DEFAULT_API_VERSION,
    .isSystemApp = true
};
}  // namespace

#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
static bool RecoveryPermission(uint64_t tokenID)
{
    if (!MockTokenId("foundation")) {
        return false;
    }
    if (!((ERR_OK == AccessTokenKit::DeleteToken(tokenID)) && (ERR_OK == SetSelfTokenID(g_selfTokenID)))) {
        return false;
    }
    return g_selfTokenID == IPCSkeleton::GetSelfTokenID();
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

class OsAccountManagerModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void OsAccountManagerModuleTest::SetUpTestCase(void)
{
    GTEST_LOG_(INFO) << "SetUpTestCase enter";
    ASSERT_NE(GetAllAccountPermission(), 0);
    g_selfTokenID = IPCSkeleton::GetSelfTokenID();
#ifdef ACCOUNT_TEST
    AccountFileOperator osAccountFileOperator;
    osAccountFileOperator.DeleteDirOrFile(USER_INFO_BASE);
    GTEST_LOG_(INFO) << "delete account test path " << USER_INFO_BASE;
#endif  // ACCOUNT_TEST
    bool isOsAccountActived = false;
    ErrCode ret = OsAccountManager::IsOsAccountActived(MAIN_ACCOUNT_ID, isOsAccountActived);
    std::uint32_t waitCnt = 0;
    while (ret != ERR_OK || !isOsAccountActived) {
        std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_A_MOMENT));
        waitCnt++;
        GTEST_LOG_(INFO) << "SetUpTestCase waitCnt " << waitCnt << " ret = " << ret;
        ret = OsAccountManager::IsOsAccountActived(MAIN_ACCOUNT_ID, isOsAccountActived);
        if (waitCnt >= MAX_WAIT_FOR_READY_CNT) {
            GTEST_LOG_(INFO) << "SetUpTestCase waitCnt " << waitCnt;
            GTEST_LOG_(INFO) << "SetUpTestCase wait for ready failed!";
            break;
        }
    }
    GTEST_LOG_(INFO) << "SetUpTestCase finished, waitCnt " << waitCnt;
#ifdef BUNDLE_ADAPTER_MOCK
    auto osAccountService = new (std::nothrow) OsAccountManagerService();
    ASSERT_NE(osAccountService, nullptr);
    IInnerOsAccountManager::GetInstance().Init();
    IInnerOsAccountManager::GetInstance().ActivateDefaultOsAccount();
    OsAccount::GetInstance().proxy_ = new (std::nothrow) OsAccountProxy(osAccountService->AsObject());
    ASSERT_NE(OsAccount::GetInstance().proxy_, nullptr);
#endif

#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
    OsAccountManager::CreateOsAccount("CommonAccount", OsAccountType::NORMAL, commonOsAccountInfo);
    OsAccountManager::QueryOsAccountById(commonOsAccountInfo.GetLocalId(), commonOsAccountInfoBack);
#endif
}

void OsAccountManagerModuleTest::TearDownTestCase(void)
{
    GTEST_LOG_(INFO) << "TearDownTestCase";
#ifdef ACCOUNT_TEST
    AccountFileOperator osAccountFileOperator;
    osAccountFileOperator.DeleteDirOrFile(USER_INFO_BASE);
    GTEST_LOG_(INFO) << "delete account test path " << USER_INFO_BASE;
#endif  // ACCOUNT_TEST
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
    OsAccountManager::RemoveOsAccount(commonOsAccountInfo.GetLocalId());
#endif
}

void OsAccountManagerModuleTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());

    std::vector<OsAccountInfo> osAccountInfos;
    EXPECT_EQ(OsAccountManager::QueryAllCreatedOsAccounts(osAccountInfos), ERR_OK);
    for (const auto &info : osAccountInfos) {
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
        if (info.GetLocalId() == commonOsAccountInfo.GetLocalId()) {
            if (info.GetIsActived()) {
                OsAccountManager::DeactivateOsAccount(commonOsAccountInfo.GetLocalId());
            }
            continue;
        }
#endif
        if (info.GetLocalId() == START_USER_ID) {
            if (!info.GetIsVerified() || !info.GetIsActived()) {
                OsAccountManager::ActivateOsAccount(MAIN_ACCOUNT_ID);
            }
            continue;
        }
        ACCOUNT_LOGI("[SetUp] remove account %{public}d", info.GetLocalId());
        OsAccountManager::RemoveOsAccount(info.GetLocalId());
    }

#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
    OsAccountManager::UpdateOsAccountWithFullInfo(commonOsAccountInfoBack);
    OsAccountManager::QueryOsAccountById(commonOsAccountInfoBack.GetLocalId(), commonOsAccountInfo);
#endif
}

void OsAccountManagerModuleTest::TearDown(void)
{}

class MockSubscriberListener {
public:
    MOCK_METHOD1(OnReceiveEvent, void(const std::string &action));
};

class AccountTestEventSubscriber final : public EventFwk::CommonEventSubscriber {
public:
    AccountTestEventSubscriber(const EventFwk::CommonEventSubscribeInfo &subscribeInfo,
        const std::shared_ptr<MockSubscriberListener> &listener)
        : CommonEventSubscriber(subscribeInfo), listener_(listener)
    {}

    void OnReceiveEvent(const EventFwk::CommonEventData &data)
    {
        if (listener_ == nullptr) {
            return;
        }
        auto want = data.GetWant();
        listener_->OnReceiveEvent(want.GetAction());
        std::unique_lock<std::mutex> lock(mutex);
        if (want.GetAction() == EventFwk::CommonEventSupport::COMMON_EVENT_USER_STOPPING) {
            stoppingEventReady = true;
        } else {
            stoppedEventReady = true;
        }
        if (want.GetAction() == EventFwk::CommonEventSupport::COMMON_EVENT_USER_BACKGROUND) {
            isReady = true;
        }
        cv.notify_one();
        return;
    }
    std::condition_variable cv;
    bool stoppingEventReady = false;
    bool stoppedEventReady = false;
    bool isReady = false;
    std::mutex mutex;

private:
    const std::shared_ptr<MockSubscriberListener> listener_;
};

#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
#ifndef BUNDLE_ADAPTER_MOCK
static void Wait(const std::shared_ptr<AccountTestEventSubscriber> &ptr)
{
    std::unique_lock<std::mutex> lock(ptr->mutex);
    ptr->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME),
        [lockPtr = ptr]() {
            return (lockPtr->stoppingEventReady && lockPtr->stoppedEventReady) || lockPtr->isReady;
        });
}
#endif
#endif

class MockOsAccountSubscriber {
public:
    MOCK_METHOD1(OnAccountsChanged, void(const int &id));
};

class DeactivateOsAccountSubscriber final : public OsAccountSubscriber {
public:
    explicit DeactivateOsAccountSubscriber(
        const OsAccountSubscribeInfo &subscribeInfo, const std::shared_ptr<MockOsAccountSubscriber> &callback)
        : OsAccountSubscriber(subscribeInfo), callback_(callback) {}

    void OnAccountsChanged(const int &id)
    {
        callback_->OnAccountsChanged(id);
        std::unique_lock<std::mutex> lock(mutex);
        isReady = true;
        cv.notify_one();
        return;
    }
    std::condition_variable cv;
    bool isReady = false;
    std::mutex mutex;

private:
    std::shared_ptr<MockOsAccountSubscriber> callback_;
};

#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
static void Wait(const std::shared_ptr<DeactivateOsAccountSubscriber> &ptr)
{
    std::unique_lock<std::mutex> lock(ptr->mutex);
    ptr->cv.wait_for(lock, std::chrono::seconds(WAIT_TIME),
        [lockPtr = ptr]() { return lockPtr->isReady; });
}
#endif

class ActiveOsAccountSubscriber final : public OsAccountSubscriber {
public:
    explicit ActiveOsAccountSubscriber(const OsAccountSubscribeInfo &subscribeInfo)
        : OsAccountSubscriber(subscribeInfo) {}

    MOCK_METHOD1(OnAccountsChanged, void(const int &id));
    MOCK_METHOD2(OnAccountsSwitch, void(const int &newId, const int &oldId));
};

#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
/**
 * @tc.name: CreateOsAccountWithFullInfo001
 * @tc.desc: Test next id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, CreateOsAccountWithFullInfo001, TestSize.Level1)
{
    std::string fileContext;
    int32_t nextLocalId = 0;
    EXPECT_EQ(ERR_OK, g_accountFileOperator->GetFileContentByPath(Constants::ACCOUNT_LIST_FILE_JSON_PATH, fileContext));
    auto accountListJson = CreateJsonFromString(fileContext);
    ASSERT_TRUE(accountListJson != nullptr && IsStructured(accountListJson));
    ASSERT_TRUE(IsNumber(GetItemFromJson(accountListJson, "NextLocalId")));
    GetIntFromJson(accountListJson.get(), "NextLocalId", nextLocalId);
    ASSERT_TRUE(nextLocalId > 100);
    OsAccountInfo osAccountInfo;
    osAccountInfo.SetLocalName("testNextID_001");
    int32_t expectUid = nextLocalId + 2; // test random uid, next account should start from nextLocalId + 2
    osAccountInfo.SetLocalId(expectUid);
    osAccountInfo.SetSerialNumber(2023023100000033); // test random input
    osAccountInfo.SetCreateTime(1695883215000); // test random input
    osAccountInfo.SetLastLoginTime(1695863215000); // test random input
    EXPECT_EQ(ERR_OK, OsAccountManager::CreateOsAccountWithFullInfo(osAccountInfo));
    EXPECT_EQ(osAccountInfo.GetLocalId(), expectUid);
    OsAccountManager::RemoveOsAccount(osAccountInfo.GetLocalId());

    EXPECT_EQ(ERR_OK, g_accountFileOperator->GetFileContentByPath(Constants::ACCOUNT_LIST_FILE_JSON_PATH, fileContext));
    accountListJson = CreateJsonFromString(fileContext);
    ASSERT_TRUE(accountListJson != nullptr && IsStructured(accountListJson));
    ASSERT_TRUE(IsNumber(GetItemFromJson(accountListJson, "NextLocalId")));
    GetIntFromJson(accountListJson.get(), "NextLocalId", nextLocalId);
    ASSERT_TRUE(nextLocalId > 100);
    EXPECT_EQ(nextLocalId, (expectUid + 1));
}

/**
 * @tc.name: CreateOsAccountWithFullInfo002
 * @tc.desc: CreateOsAccountWithFullInfo will return fail if account exists.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, CreateOsAccountWithFullInfo002, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    osAccountInfo.SetLocalName("CreateOsAccountWithFullInfo002");
    osAccountInfo.SetLocalId(commonOsAccountInfo.GetLocalId());
    osAccountInfo.SetSerialNumber(2023023100000033); // test random input
    osAccountInfo.SetCreateTime(1695883215000);      // test random input
    osAccountInfo.SetLastLoginTime(1695863215000);   // test random input
    EXPECT_EQ(ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_ALREADY_EXIST_ERROR,
              OsAccountManager::CreateOsAccountWithFullInfo(osAccountInfo));
}

/**
 * @tc.name: CreateOsAccountWithFullInfo003
 * @tc.desc: CreateOsAccountWithFullInfo will return success if account exists but toberemoved.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, CreateOsAccountWithFullInfo003, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    CreateOsAccountOptions options;
    options.allowedHapList = {};
    EXPECT_EQ(ERR_OK, OsAccountManager::CreateOsAccount("CreateOsAccountWithFullInfo003",
        "CreateOsAccountWithFullInfo003", OsAccountType::NORMAL, options, osAccountInfo));
    EXPECT_EQ(ERR_OK, OsAccountManager::SetOsAccountToBeRemoved(osAccountInfo.GetLocalId(), true));

    OsAccountInfo fullOsAccountInfo;
    fullOsAccountInfo.SetLocalName("CreateOsAccountWithFullInfo003");
    fullOsAccountInfo.SetLocalId(osAccountInfo.GetLocalId());
    fullOsAccountInfo.SetSerialNumber(2023023100000033); // test random input
    fullOsAccountInfo.SetCreateTime(1695883215000);      // test random input
    fullOsAccountInfo.SetLastLoginTime(1695863215000);   // test random input
    EXPECT_EQ(ERR_OK, OsAccountManager::CreateOsAccountWithFullInfo(fullOsAccountInfo));

    EXPECT_EQ(ERR_OK, OsAccountManager::RemoveOsAccount(osAccountInfo.GetLocalId()));
}

/**
 * @tc.name: OsAccountManagerModuleTest001
 * @tc.desc: Test create guest account.
 * @tc.type: FUNC
 * @tc.require: issueI4IU74
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest001, TestSize.Level0)
{
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(OsAccountManager::CreateOsAccount("ModuleTest001", OsAccountType::GUEST, osAccountInfoOne), ERR_OK);
    OsAccountInfo osAccountInfoTwo;
    EXPECT_EQ(OsAccountManager::QueryOsAccountById(osAccountInfoOne.GetLocalId(), osAccountInfoTwo), ERR_OK);
    DomainAccountInfo domainInfo;
    osAccountInfoTwo.GetDomainInfo(domainInfo);
    domainInfo.status_ = DomainAccountStatus::LOG_END;
    osAccountInfoTwo.SetDomainInfo(domainInfo);
    EXPECT_EQ(osAccountInfoOne.ToString(), osAccountInfoTwo.ToString());
    EXPECT_EQ(osAccountInfoOne.GetType(), OsAccountType::GUEST);
    ASSERT_EQ(OsAccountManager::RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest002
 * @tc.desc: Test CreateOsAccount with too long name.
 * @tc.type: FUNC
 * @tc.require: issueI4IU51
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest002, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    EXPECT_NE(OsAccountManager::CreateOsAccount(STRING_NAME_OUT_OF_RANGE, OsAccountType::GUEST, osAccountInfoOne),
        ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest003
 * @tc.desc: Test CreateOsAccount with empty name.
 * @tc.type: FUNC
 * @tc.require: issueI4IU51
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest003, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    EXPECT_NE(OsAccountManager::CreateOsAccount(STRING_EMPTY, OsAccountType::GUEST, osAccountInfoOne), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest004
 * @tc.desc: Test create admin account.
 * @tc.type: FUNC
 * @tc.require: issueI4IU51
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest004, TestSize.Level0)
{
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(OsAccountManager::CreateOsAccount("ModuleTest004", OsAccountType::ADMIN, osAccountInfoOne), ERR_OK);
    OsAccountInfo osAccountInfoTwo;
    EXPECT_EQ(OsAccountManager::QueryOsAccountById(osAccountInfoOne.GetLocalId(), osAccountInfoTwo), ERR_OK);
    DomainAccountInfo domainInfo;
    osAccountInfoTwo.GetDomainInfo(domainInfo);
    domainInfo.status_ = DomainAccountStatus::LOG_END;
    osAccountInfoTwo.SetDomainInfo(domainInfo);
    EXPECT_EQ(osAccountInfoOne.ToString(), osAccountInfoTwo.ToString());
    EXPECT_EQ(osAccountInfoOne.GetType(), OsAccountType::ADMIN);
    ASSERT_EQ(OsAccountManager::RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest005
 * @tc.desc: Test create normal account.
 * @tc.type: FUNC
 * @tc.require: issueI4IU51
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest005, TestSize.Level0)
{
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(OsAccountManager::CreateOsAccount("ModuleTest005", OsAccountType::NORMAL, osAccountInfoOne), ERR_OK);
    OsAccountInfo osAccountInfoTwo;
    EXPECT_EQ(OsAccountManager::QueryOsAccountById(osAccountInfoOne.GetLocalId(), osAccountInfoTwo), ERR_OK);
    DomainAccountInfo domainInfo;
    osAccountInfoTwo.GetDomainInfo(domainInfo);
    domainInfo.status_ = DomainAccountStatus::LOG_END;
    osAccountInfoTwo.SetDomainInfo(domainInfo);
    EXPECT_EQ(osAccountInfoOne.ToString(), osAccountInfoTwo.ToString());
    EXPECT_EQ(osAccountInfoOne.GetType(), OsAccountType::NORMAL);
    ASSERT_EQ(OsAccountManager::RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}

#ifdef BUNDLE_ADAPTER_MOCK
/**
 * @tc.name: OsAccountManagerModuleTest006
 * @tc.desc: Test CreateOsAccount when cannot find account_list.json.
 * @tc.type: FUNC
 * @tc.require: issueI4IU51
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest006, TestSize.Level1)
{
    // save file content to ram
    std::string fileContext;
    g_accountFileOperator->GetFileContentByPath(Constants::ACCOUNT_LIST_FILE_JSON_PATH, fileContext);

    // remove file
    ASSERT_EQ(g_accountFileOperator->DeleteDirOrFile(Constants::ACCOUNT_LIST_FILE_JSON_PATH), ERR_OK);

    // create account
    OsAccountInfo osAccountInfoOne;
    EXPECT_NE(OsAccountManager::CreateOsAccount("ModuleTest006", OsAccountType::GUEST, osAccountInfoOne), ERR_OK);

    // rewrite file content
    g_accountFileOperator->InputFileByPathAndContent(Constants::ACCOUNT_LIST_FILE_JSON_PATH, fileContext);

    // recover permission
    if (chmod(Constants::ACCOUNT_LIST_FILE_JSON_PATH.c_str(), S_IRUSR | S_IWUSR) != 0) {
        ACCOUNT_LOGE("OsAccountManagerModuleTest006, chmod failed! errno %{public}d.", errno);
    }
    if (chown(Constants::ACCOUNT_LIST_FILE_JSON_PATH.c_str(), ACCOUNT_UID, ACCOUNT_GID) != 0) {
        ACCOUNT_LOGE("OsAccountManagerModuleTest006, chown failed! errno %{public}d.", errno);
    }
}
#endif

/**
 * @tc.name: OsAccountManagerModuleTest007
 * @tc.desc: Test RemoveOsAccount with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI4IU74
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest007, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    EXPECT_NE(OsAccountManager::CreateOsAccount(STRING_EMPTY, OsAccountType::GUEST, osAccountInfoOne), ERR_OK);
    EXPECT_NE(OsAccountManager::RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    EXPECT_EQ(g_accountFileOperator->IsExistDir(
        Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + osAccountInfoOne.GetPrimeKey()), false);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: OsAccountManagerModuleTest008
 * @tc.desc: Test RemoveOsAccount with cannot remove id.
 * @tc.type: FUNC
 * @tc.require: issueI4IU74
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest008, TestSize.Level1)
{
    EXPECT_NE(OsAccountManager::RemoveOsAccount(Constants::START_USER_ID), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest009
 * @tc.desc: Test RemoveOsAccount with does not exists id.
 * @tc.type: FUNC
 * @tc.require: issueI4IU51
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest009, TestSize.Level1)
{
    EXPECT_NE(OsAccountManager::RemoveOsAccount(Constants::MAX_USER_ID + 1), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest010
 * @tc.desc: Test IsOsAccountExists with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI4IU51
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest010, TestSize.Level1)
{
    bool isOsAccountExists = false;
    EXPECT_EQ(OsAccountManager::IsOsAccountExists(Constants::START_USER_ID, isOsAccountExists), ERR_OK);
    EXPECT_EQ(isOsAccountExists, true);
}

/**
 * @tc.name: OsAccountManagerModuleTest011
 * @tc.desc: Test IsOsAccountExists with not exists data.
 * @tc.type: FUNC
 * @tc.require: issueI4IU51
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest011, TestSize.Level1)
{
    bool isOsAccountExists = true;
    EXPECT_EQ(OsAccountManager::IsOsAccountExists(Constants::MAX_USER_ID + 1, isOsAccountExists), ERR_OK);
    EXPECT_EQ(isOsAccountExists, false);
}

/**
 * @tc.name: OsAccountManagerModuleTest012
 * @tc.desc: Test IsOsAccountActived with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI4JBFF
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest012, TestSize.Level1)
{
    bool isOsAccountActived = false;
    EXPECT_EQ(OsAccountManager::IsOsAccountActived(Constants::ADMIN_LOCAL_ID, isOsAccountActived), ERR_OK);
    EXPECT_EQ(isOsAccountActived, true);
}

/**
 * @tc.name: OsAccountManagerModuleTest013
 * @tc.desc: Test IsOsAccountActived with not active account id.
 * @tc.type: FUNC
 * @tc.require: issueI4JBFF
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest013, TestSize.Level1)
{
    bool isOsAccountActived = true;
    EXPECT_EQ(OsAccountManager::IsOsAccountActived(commonOsAccountInfo.GetLocalId(), isOsAccountActived), ERR_OK);
    EXPECT_EQ(isOsAccountActived, false);
}

/**
 * @tc.name: OsAccountManagerModuleTest014
 * @tc.desc: Test SetOsAccountConstraints with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI4IU6A
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest014, TestSize.Level1)
{
    bool enable = false;
    EXPECT_EQ(OsAccountManager::SetOsAccountConstraints(commonOsAccountInfo.GetLocalId(), CONSTANTS_VECTOR, enable),
        ERR_OK);
    OsAccountInfo osAccountInfoTwo;
    EXPECT_EQ(OsAccountManager::QueryOsAccountById(commonOsAccountInfo.GetLocalId(), osAccountInfoTwo), ERR_OK);
    std::vector<std::string> constraints = osAccountInfoTwo.GetConstraints();
    EXPECT_TRUE(std::includes(constraints.begin(), constraints.end(), CONSTANTS_VECTOR.begin(), CONSTANTS_VECTOR.end(),
                              [](const std::string& s1, const std::string& s2) { return s1 == s2; }));
}

/**
 * @tc.name: OsAccountManagerModuleTest015
 * @tc.desc: Test SetOsAccountConstraints with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI4IU6A
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest015, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(OsAccountManager::CreateOsAccount("ModuleTest015", OsAccountType::GUEST, osAccountInfoOne), ERR_OK);
    bool enable = true;
    EXPECT_EQ(OsAccountManager::SetOsAccountConstraints(osAccountInfoOne.GetLocalId(), CONSTANTS_VECTOR, enable),
        ERR_OK);
    OsAccountInfo osAccountInfoTwo;
    EXPECT_EQ(OsAccountManager::QueryOsAccountById(osAccountInfoOne.GetLocalId(), osAccountInfoTwo), ERR_OK);
    std::vector<std::string> constraints = osAccountInfoTwo.GetConstraints();
    EXPECT_TRUE(std::includes(constraints.begin(), constraints.end(), CONSTANTS_VECTOR.begin(), CONSTANTS_VECTOR.end(),
                              [](const std::string& s1, const std::string& s2) { return s1 == s2; }));
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest016
 * @tc.desc: Test IsOsAccountConstraintEnable with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI4IU6A issueI4RCGG
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest016, TestSize.Level1)
{
    bool enable = true;
    EXPECT_EQ(OsAccountManager::SetOsAccountConstraints(commonOsAccountInfo.GetLocalId(), CONSTANTS_VECTOR, enable),
        ERR_OK);
    bool isEnable = false;
    EXPECT_EQ(
        OsAccountManager::IsOsAccountConstraintEnable(commonOsAccountInfo.GetLocalId(), CONSTANT_PRINT, isEnable),
        ERR_OK);
    EXPECT_EQ(isEnable, true);
}

/**
 * @tc.name: OsAccountManagerModuleTest017
 * @tc.desc: Test IsOsAccountConstraintEnable with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI4IU6A issueI4RCGG
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest017, TestSize.Level1)
{
    bool isEnable = true;
    EXPECT_EQ(
        OsAccountManager::IsOsAccountConstraintEnable(commonOsAccountInfo.GetLocalId(), CONSTANT_PRINT, isEnable),
        ERR_OK);
    EXPECT_EQ(isEnable, false);
}

/**
 * @tc.name: OsAccountManagerModuleTest018
 * @tc.desc: Test IsMultiOsAccountEnable
 * @tc.type: FUNC
 * @tc.require: issueI4JBFF
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest018, TestSize.Level1)
{
    bool isMultiOsAccountEnable = false;
    EXPECT_EQ(OsAccountManager::IsMultiOsAccountEnable(isMultiOsAccountEnable), ERR_OK);
    EXPECT_EQ(isMultiOsAccountEnable, true);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: OsAccountManagerModuleTest019
 * @tc.desc: Test IsOsAccountVerified with not verified os account id.
 * @tc.type: FUNC
 * @tc.require: issueI4JBFF
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest019, TestSize.Level1)
{
    bool isVerified = false;
    EXPECT_EQ(OsAccountManager::IsOsAccountVerified(Constants::START_USER_ID, isVerified), ERR_OK);
    EXPECT_EQ(isVerified, true);
    isVerified = true;
    EXPECT_EQ(OsAccountManager::SetOsAccountIsVerified(Constants::START_USER_ID, false), ERR_OK);
    EXPECT_EQ(OsAccountManager::IsOsAccountVerified(Constants::START_USER_ID, isVerified), ERR_OK);
    EXPECT_EQ(isVerified, false);
    isVerified = false;
    EXPECT_EQ(OsAccountManager::SetOsAccountIsVerified(Constants::START_USER_ID, true), ERR_OK);
    EXPECT_EQ(OsAccountManager::IsOsAccountVerified(Constants::START_USER_ID, isVerified), ERR_OK);
    EXPECT_EQ(isVerified, true);
}

/**
 * @tc.name: OsAccountManagerModuleTest020
 * @tc.desc: Test IsOsAccountVerified with does not exists os account id.
 * @tc.type: FUNC
 * @tc.require: issueI4JBFF
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest020, TestSize.Level1)
{
    bool isVerified = true;
    EXPECT_NE(OsAccountManager::IsOsAccountVerified(Constants::MAX_USER_ID + 1, isVerified), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest021
 * @tc.desc: Test IsOsAccountVerified with does not exists os account id.
 * @tc.type: FUNC
 * @tc.require: issueI4JBFF
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest021, TestSize.Level1)
{
    bool isVerified = true;
    EXPECT_NE(OsAccountManager::IsOsAccountVerified(Constants::MAX_USER_ID + 1, isVerified), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest022
 * @tc.desc: Test GetCreatedOsAccountsCount.
 * @tc.type: FUNC
 * @tc.require: issueI4JBFF
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest022, TestSize.Level1)
{
    unsigned int osAccountsCount = 0;
    EXPECT_EQ(OsAccountManager::GetCreatedOsAccountsCount(osAccountsCount), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest023
 * @tc.desc: Test GetOsAccountLocalIdFromProcess.
 * @tc.type: FUNC
 * @tc.require: issueI4IU6N
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest023, TestSize.Level1)
{
    int id = -1;
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromProcess(id), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest024
 * @tc.desc: Test GetOsAccountLocalIdFromUid.
 * @tc.type: FUNC
 * @tc.require: issueI4IU6N
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest024, TestSize.Level1)
{
    int id = -1;
    int testUid = 1000000;   // uid for test
    int expectedUserID = 5;  // the expected result user ID
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromUid(testUid, id), ERR_OK);
    EXPECT_EQ(expectedUserID, id);
}

/**
 * @tc.name: OsAccountManagerModuleTest025
 * @tc.desc: Test QueryMaxOsAccountNumber.
 * @tc.type: FUNC
 * @tc.require: issueI4JBFF
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest025, TestSize.Level1)
{
    uint32_t maxOsAccountNumber = 0;
    EXPECT_EQ(OsAccountManager::QueryMaxOsAccountNumber(maxOsAccountNumber), ERR_OK);
}

/**
 * @tc.name: QueryMaxLoggedInOsAccountNumberModuleTest001
 * @tc.desc: Test QueryMaxLoggedInOsAccountNumber.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, QueryMaxLoggedInOsAccountNumberModuleTest001, TestSize.Level1)
{
    uint32_t maxNum = 0;
    EXPECT_EQ(OsAccountManager::QueryMaxLoggedInOsAccountNumber(maxNum), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest026
 * @tc.desc: Test GetOsAccountAllConstraints with exisit os account id.
 * @tc.type: FUNC
 * @tc.require: issueI4IU6A issueI4RCGG
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest026, TestSize.Level1)
{
    std::vector<std::string> constraints;
    EXPECT_EQ(OsAccountManager::GetOsAccountAllConstraints(Constants::START_USER_ID, constraints), ERR_OK);
    EXPECT_NE(0, constraints.size());
    constraints.clear();
    EXPECT_NE(OsAccountManager::GetOsAccountAllConstraints(199, constraints), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest027
 * @tc.desc: Test GetOsAccountAllConstraints with does not exisit os account id.
 * @tc.type: FUNC
 * @tc.require: issueI4IU6A issueI4RCGG
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest027, TestSize.Level1)
{
    std::vector<std::string> constraints;
    EXPECT_NE(OsAccountManager::GetOsAccountAllConstraints(Constants::MAX_USER_ID + 1, constraints), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest028
 * @tc.desc: Test QueryAllCreatedOsAccounts.
 * @tc.type: FUNC
 * @tc.require: issueI4RCGG
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest028, TestSize.Level1)
{
    std::vector<OsAccountInfo> osAccountInfos;
    EXPECT_EQ(OsAccountManager::QueryAllCreatedOsAccounts(osAccountInfos), ERR_OK);
    EXPECT_EQ(2, osAccountInfos.size());
    OsAccountInfo osAccountInfoOne;
    EXPECT_EQ(OsAccountManager::CreateOsAccount("ModuleTest028_1", OsAccountType::GUEST, osAccountInfoOne), ERR_OK);
    osAccountInfos.clear();
    EXPECT_EQ(OsAccountManager::QueryAllCreatedOsAccounts(osAccountInfos), ERR_OK);
    EXPECT_EQ(3, osAccountInfos.size());
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);

    OsAccountInfo osAccountInfoTwo;
    EXPECT_EQ(OsAccountManager::CreateOsAccount("ModuleTest028_2", OsAccountType::GUEST, osAccountInfoTwo), ERR_OK);
    EXPECT_EQ(OsAccountManager::SetOsAccountProfilePhoto(osAccountInfoTwo.GetLocalId(), PHOTO_IMG), ERR_OK);
    osAccountInfos.clear();
    EXPECT_EQ(OsAccountManager::QueryAllCreatedOsAccounts(osAccountInfos), ERR_OK);
    EXPECT_EQ(3, osAccountInfos.size());

    osAccountInfoTwo.SetPhoto(PHOTO_IMG);
    for (size_t i = 0;i < osAccountInfos.size();i++) {
        if (osAccountInfos[i].GetLocalId() == osAccountInfoTwo.GetLocalId()) {
            EXPECT_EQ(osAccountInfos[i].ToString(), osAccountInfoTwo.ToString());
        }
    }

    EXPECT_EQ(OsAccountManager::SetOsAccountToBeRemoved(osAccountInfoTwo.GetLocalId(), true), ERR_OK);
    osAccountInfos.clear();
    EXPECT_EQ(OsAccountManager::QueryAllCreatedOsAccounts(osAccountInfos), ERR_OK);
    EXPECT_EQ(2, osAccountInfos.size());

    EXPECT_EQ(OsAccountManager::RemoveOsAccount(osAccountInfoTwo.GetLocalId()), ERR_OK);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: OsAccountManagerModuleTest029
 * @tc.desc: Test QueryCurrentOsAccount.
 * @tc.type: FUNC
 * @tc.require: issueI4JBFF
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest029, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(OsAccountManager::QueryCurrentOsAccount(osAccountInfo), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest030
 * @tc.desc: Test QueryOsAccountById with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI4IU6N
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest030, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(OsAccountManager::QueryOsAccountById(Constants::START_USER_ID, osAccountInfo), ERR_OK);
    EXPECT_EQ(Constants::START_USER_ID, osAccountInfo.GetLocalId());
}

/**
 * @tc.name: OsAccountManagerModuleTest031
 * @tc.desc: Test QueryOsAccountById with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4IU6N
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest031, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    EXPECT_NE(OsAccountManager::QueryOsAccountById(Constants::MAX_USER_ID + 1, osAccountInfo), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest032
 * @tc.desc: Test GetOsAccountTypeFromProcess.
 * @tc.type: FUNC
 * @tc.require: issueI4JBFF
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest032, TestSize.Level1)
{
    OsAccountType type = OsAccountType::ADMIN;
    EXPECT_EQ(OsAccountManager::GetOsAccountTypeFromProcess(type), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest033
 * @tc.desc: Test SetOsAccountName with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI4IU6N
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest033, TestSize.Level1)
{
    EXPECT_EQ(OsAccountManager::SetOsAccountName(commonOsAccountInfo.GetLocalId(), STRING_NAME), ERR_OK);
    OsAccountInfo osAccountInfoTwo;
    EXPECT_EQ(OsAccountManager::QueryOsAccountById(commonOsAccountInfo.GetLocalId(), osAccountInfoTwo), ERR_OK);
    EXPECT_EQ(STRING_NAME, osAccountInfoTwo.GetLocalName());
}

/**
 * @tc.name: OsAccountManagerModuleTest034
 * @tc.desc: Test SetOsAccountName with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4IU6N
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest034, TestSize.Level1)
{
    EXPECT_NE(OsAccountManager::SetOsAccountName(commonOsAccountInfo.GetLocalId(), STRING_EMPTY), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest035
 * @tc.desc: Test SetOsAccountName with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4IU6N
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest035, TestSize.Level1)
{
    EXPECT_NE(OsAccountManager::SetOsAccountName(commonOsAccountInfo.GetLocalId(), STRING_NAME_OUT_OF_RANGE), ERR_OK);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: OsAccountManagerModuleTest036
 * @tc.desc: Test GetDistributedVirtualDeviceId.
 * @tc.type: FUNC
 * @tc.require: issueI4JBFF
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest036, TestSize.Level1)
{
    // before ohos account login
    std::string deviceId;
    ErrCode ret = OsAccountManager::GetDistributedVirtualDeviceId(deviceId);
    EXPECT_EQ(ret, ERR_OK);

    // ohos account login
    sptr<ISystemAbilityManager> systemMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(systemMgr, nullptr);
    sptr<IRemoteObject> accountObj = systemMgr->GetSystemAbility(SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN);
    ASSERT_NE(accountObj, nullptr);
    sptr<IAccount> ohosMgr = iface_cast<AccountProxy>(accountObj);
    EXPECT_NE(ohosMgr, nullptr);
    ohosMgr->UpdateOhosAccountInfo(TEST_ACCOUNT_NAME, TEST_ACCOUNT_UID, OHOS_ACCOUNT_EVENT_LOGIN);

    // after ohos account login
    ret = OsAccountManager::GetDistributedVirtualDeviceId(deviceId);
    EXPECT_EQ(ret, ERR_OK);

    // ohos account logout
    ohosMgr->UpdateOhosAccountInfo(TEST_ACCOUNT_NAME, TEST_ACCOUNT_UID, OHOS_ACCOUNT_EVENT_LOGOUT);

    // after ohos account logout
    ret = OsAccountManager::GetDistributedVirtualDeviceId(deviceId);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest037
 * @tc.desc: Test GetOsAccountLocalIdBySerialNumber with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI4IU6N
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest037, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(OsAccountManager::QueryOsAccountById(Constants::START_USER_ID, osAccountInfo), ERR_OK);
    int id = 0;
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdBySerialNumber(osAccountInfo.GetSerialNumber(), id), ERR_OK);
    EXPECT_EQ(id, Constants::START_USER_ID);
}

/**
 * @tc.name: OsAccountManagerModuleTest038
 * @tc.desc: Test GetOsAccountLocalIdBySerialNumber with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4IU6N
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest038, TestSize.Level1)
{
    int32_t id = 0;
    EXPECT_NE(OsAccountManager::GetOsAccountLocalIdBySerialNumber(INVALID_SERIAL_NUM, id), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest039
 * @tc.desc: Test GetSerialNumberByOsAccountLocalId with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI4IU6N
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest039, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(OsAccountManager::QueryOsAccountById(Constants::START_USER_ID, osAccountInfo), ERR_OK);
    int64_t serialNumber;
    EXPECT_EQ(OsAccountManager::GetSerialNumberByOsAccountLocalId(Constants::START_USER_ID, serialNumber), ERR_OK);
    EXPECT_EQ(serialNumber, osAccountInfo.GetSerialNumber());
}

/**
 * @tc.name: OsAccountManagerModuleTest040
 * @tc.desc: Test GetSerialNumberByOsAccountLocalId with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4IU6N
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest040, TestSize.Level1)
{
    int64_t serialNumber;
    EXPECT_NE(OsAccountManager::GetSerialNumberByOsAccountLocalId(Constants::MAX_USER_ID + 1, serialNumber), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest041
 * @tc.desc: Test SetOsAccountProfilePhoto with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI4IU33
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest041, TestSize.Level1)
{
    EXPECT_EQ(OsAccountManager::SetOsAccountProfilePhoto(commonOsAccountInfo.GetLocalId(), PHOTO_IMG), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest042
 * @tc.desc: Test SetOsAccountProfilePhoto with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4IU33
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest042, TestSize.Level1)
{
    EXPECT_NE(OsAccountManager::SetOsAccountProfilePhoto(
        commonOsAccountInfo.GetLocalId(), STRING_PHOTO_OUT_OF_RANGE), ERR_OK);
    EXPECT_EQ(
        OsAccountManager::SetOsAccountProfilePhoto(commonOsAccountInfo.GetLocalId(), STRING_PHOTO_MAX), ERR_OK);
    std::string photo;
    EXPECT_EQ(
        OsAccountManager::GetOsAccountProfilePhoto(commonOsAccountInfo.GetLocalId(), photo), ERR_OK);
    OsAccountInfo osAccountInfoTwo;
    EXPECT_EQ(OsAccountManager::QueryOsAccountById(commonOsAccountInfo.GetLocalId(), osAccountInfoTwo), ERR_OK);
    EXPECT_EQ(osAccountInfoTwo.GetLocalId(), commonOsAccountInfo.GetLocalId());
    OsAccountInfo osAccountInfoThree;
    ASSERT_EQ(OsAccountManager::CreateOsAccount("Modulelist042", OsAccountType::GUEST, osAccountInfoThree), ERR_OK);
    std::vector<OsAccountInfo> osAccountInfos;
    ASSERT_EQ(OsAccountManager::QueryAllCreatedOsAccounts(osAccountInfos), ERR_OK);
    ASSERT_EQ(osAccountInfos.size(), 3);
    ASSERT_EQ(OsAccountManager::RemoveOsAccount(osAccountInfoThree.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest043
 * @tc.desc: Test SetOsAccountProfilePhoto with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4IU33
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest043, TestSize.Level1)
{
    EXPECT_EQ(OsAccountManager::SetOsAccountProfilePhoto(commonOsAccountInfo.GetLocalId(), PHOTO_IMG_ERROR), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest044
 * @tc.desc: Test GetOsAccountProfilePhoto with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI4IU6N
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest044, TestSize.Level1)
{
    EXPECT_EQ(OsAccountManager::SetOsAccountProfilePhoto(commonOsAccountInfo.GetLocalId(), PHOTO_IMG), ERR_OK);
    std::string photo;
    EXPECT_EQ(OsAccountManager::GetOsAccountProfilePhoto(commonOsAccountInfo.GetLocalId(), photo), ERR_OK);
    EXPECT_EQ(photo, PHOTO_IMG);
}

/**
 * @tc.name: OsAccountManagerModuleTest045
 * @tc.desc: test get default photo.
 * @tc.type: FUNC
 * @tc.require: issueI4IU6N
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest045, TestSize.Level1)
{
    std::string photo;
    EXPECT_EQ(OsAccountManager::GetOsAccountProfilePhoto(commonOsAccountInfo.GetLocalId(), photo), ERR_OK);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: OsAccountManagerModuleTest046
 * @tc.desc: Test GetOsAccountProfilePhoto with invalid id.
 * @tc.type: FUNC
 * @tc.require: issueI4IU6N
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest046, TestSize.Level1)
{
    std::string photo;
    EXPECT_NE(OsAccountManager::GetOsAccountProfilePhoto(Constants::MAX_USER_ID + 1, photo), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest047
 * @tc.desc: Test StartOsAccount with valid id.
 * @tc.type: FUNC
 * @tc.require: issueI4IU3B
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest047, TestSize.Level1)
{
    EXPECT_EQ(OsAccountManager::StartOsAccount(commonOsAccountInfo.GetLocalId()), ERR_OK);
    EXPECT_EQ(OsAccountManager::DeactivateOsAccount(commonOsAccountInfo.GetLocalId()), ERR_OK);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: OsAccountManagerModuleTest048
 * @tc.desc: Test StartOsAccount with invalid id.
 * @tc.type: FUNC
 * @tc.require: issueI4IU3B
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest048, TestSize.Level1)
{
    EXPECT_EQ(OsAccountManager::StartOsAccount(Constants::MAX_USER_ID + 1), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest049
 * @tc.desc: Test StartOsAccount with started id.
 * @tc.type: FUNC
 * @tc.require: issueI4IU3B
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest049, TestSize.Level1)
{
    EXPECT_EQ(OsAccountManager::StartOsAccount(Constants::START_USER_ID), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest052
 * @tc.desc: Test IsOsAccountVerified with invalid data.
 * @tc.type: FUNC
 * @tc.require: issueI4IU3B
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest052, TestSize.Level1)
{
    bool isVerified = false;
    EXPECT_NE(OsAccountManager::IsOsAccountVerified(ERROR_LOCAL_ID, isVerified), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest061
 * @tc.desc: Test get os account info from database
 * @tc.type: FUNC
 * @tc.require: issueI4JBFI
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest061, TestSize.Level1)
{
    char udid[Constants::DEVICE_UUID_LENGTH] = {0};
    int ret = GetDevUdid(udid, Constants::DEVICE_UUID_LENGTH);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: OsAccountManagerModuleTest062
 * @tc.desc: Test get os account info from database
 * @tc.type: FUNC
 * @tc.require: issueI4JBFI
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest062, TestSize.Level1)
{
    char udid[Constants::DEVICE_UUID_LENGTH] = {0};
    int ret = GetDevUdid(udid, Constants::DEVICE_UUID_LENGTH);
    EXPECT_EQ(ret, 0);
}

#if defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
/**
 * @tc.name: OsAccountManagerModuleTest063
 * @tc.desc: Test get os account info from database
 * @tc.type: FUNC
 * @tc.require: issueI4JBFI
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest063, TestSize.Level1)
{
    char udid[Constants::DEVICE_UUID_LENGTH] = {0};
    int ret = GetDevUdid(udid, Constants::DEVICE_UUID_LENGTH);
    ASSERT_EQ(ret, 0);

    // create a new account
    OsAccountInfo osAccountInfoOne;
    EXPECT_NE(OsAccountManager::CreateOsAccount("", OsAccountType::GUEST, osAccountInfoOne), ERR_OK);

    // get created account info
    OsAccountInfo osAccountInfo;
    ret = OsAccountManager::GetOsAccountFromDatabase("", osAccountInfoOne.GetLocalId(), osAccountInfo);
    EXPECT_NE(ret, ERR_OK);
    EXPECT_NE(OsAccountManager::RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest065
 * @tc.desc: Test get os account info from database
 * @tc.type: FUNC
 * @tc.require: issueI4JBFI
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest065, TestSize.Level1)
{
    char udid[Constants::DEVICE_UUID_LENGTH] = {0};
    int ret = GetDevUdid(udid, Constants::DEVICE_UUID_LENGTH);
    ASSERT_EQ(ret, 0);
    std::string storeID = std::string(udid);

    // create a new os account
    OsAccountInfo osAccountInfoOne;
    EXPECT_NE(OsAccountManager::CreateOsAccount("", OsAccountType::GUEST, osAccountInfoOne), ERR_OK);

    // get created account info
    OsAccountInfo osAccountInfo;
    ret = OsAccountManager::GetOsAccountFromDatabase(storeID, osAccountInfoOne.GetLocalId(), osAccountInfo);
    EXPECT_NE(ret, ERR_OK);

    // remove the new os account
    ret = OsAccountManager::RemoveOsAccount(osAccountInfoOne.GetLocalId());
    EXPECT_NE(ret, ERR_OK);

    // cannot find the account in database
    OsAccountInfo osAccountInfoAfterRm;
    ret = OsAccountManager::GetOsAccountFromDatabase(storeID, osAccountInfoOne.GetLocalId(), osAccountInfoAfterRm);
    EXPECT_NE(ret, ERR_OK);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS
#endif // defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)

/**
 * @tc.name: OsAccountManagerModuleTest066
 * @tc.desc: Test query active os account ids.
 * @tc.type: FUNC
 * @tc.require: issueI4M8FW
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest066, TestSize.Level1)
{
    std::vector<int32_t> ids;
    EXPECT_EQ(OsAccountManager::QueryActiveOsAccountIds(ids), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest067
 * @tc.desc: Test GetBundleIdFromUid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest067, TestSize.Level1)
{
    int id = -1;
    int expectedBundleID = 5;  // the expected result user ID
    int testUid = 1000000 + expectedBundleID;   // uid for test
    EXPECT_EQ(OsAccountManager::GetBundleIdFromUid(testUid, id), ERR_OK);
    EXPECT_EQ(expectedBundleID, id);
}

/**
 * @tc.name: OsAccountManagerModuleTest068
 * @tc.desc: Test IsMainOsAccount.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest068, TestSize.Level1)
{
    bool isMainOsAccount = false;
    EXPECT_EQ(OsAccountManager::IsMainOsAccount(isMainOsAccount), ERR_OK);
    int id = -1;
    EXPECT_EQ(OsAccountManager::GetOsAccountLocalIdFromProcess(id), ERR_OK);
    EXPECT_EQ(isMainOsAccount, id == MAIN_ACCOUNT_ID);
}

/**
 * @tc.name: OsAccountManagerModuleTest069
 * @tc.desc: Test SetGlobalOsAccountConstraints.
 * @tc.type: FUNC
 * @tc.require:
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest069, TestSize.Level1)
{
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    ASSERT_TRUE(MockTokenId("edm"));
    bool tempStatus = false;
    EXPECT_EQ(OsAccountManager::IsOsAccountConstraintEnable(MAIN_ACCOUNT_ID, CONSTANT_PRINT, tempStatus), ERR_OK);
    EXPECT_EQ(OsAccountManager::SetGlobalOsAccountConstraints(
        CONSTANTS_VECTOR, true, commonOsAccountInfo.GetLocalId(), true), ERR_OK);
    OsAccountInfo newOsAccountInfo;
    ASSERT_EQ(OsAccountManager::CreateOsAccount(STRING_TEST_NAME_TWO, OsAccountType::NORMAL, newOsAccountInfo), ERR_OK);

    EXPECT_EQ(OsAccountManager::SetSpecificOsAccountConstraints(
        CONSTANTS_VECTOR, false, newOsAccountInfo.GetLocalId(), commonOsAccountInfo.GetLocalId(), true), ERR_OK);

    bool isEnable = false;
    EXPECT_EQ(OsAccountManager::IsOsAccountConstraintEnable(
        newOsAccountInfo.GetLocalId(), CONSTANT_PRINT, isEnable), ERR_OK);
    EXPECT_EQ(isEnable, true);

    isEnable = false;
    EXPECT_EQ(
        OsAccountManager::IsOsAccountConstraintEnable(commonOsAccountInfo.GetLocalId(), CONSTANT_PRINT, isEnable),
        ERR_OK);
    EXPECT_EQ(isEnable, true);
    isEnable = false;
    EXPECT_EQ(
        OsAccountManager::IsOsAccountConstraintEnable(MAIN_ACCOUNT_ID, CONSTANT_PRINT, isEnable),
        ERR_OK);
    EXPECT_EQ(isEnable, true);

    EXPECT_EQ(OsAccountManager::SetSpecificOsAccountConstraints(
        CONSTANTS_VECTOR, true, newOsAccountInfo.GetLocalId(), commonOsAccountInfo.GetLocalId(), true), ERR_OK);

    isEnable = false;
    EXPECT_EQ(OsAccountManager::SetGlobalOsAccountConstraints(
        CONSTANTS_VECTOR, false, commonOsAccountInfo.GetLocalId(), true), ERR_OK);

    EXPECT_EQ(OsAccountManager::IsOsAccountConstraintEnable(
        newOsAccountInfo.GetLocalId(), CONSTANT_PRINT, isEnable), ERR_OK);
    EXPECT_EQ(isEnable, true);

    isEnable = true;
    EXPECT_EQ(
        OsAccountManager::IsOsAccountConstraintEnable(commonOsAccountInfo.GetLocalId(), CONSTANT_PRINT, isEnable),
        ERR_OK);
    EXPECT_EQ(isEnable, false);
    isEnable = true;
    EXPECT_EQ(
        OsAccountManager::IsOsAccountConstraintEnable(MAIN_ACCOUNT_ID, CONSTANT_PRINT, isEnable),
        ERR_OK);
    EXPECT_EQ(isEnable, false);
    EXPECT_EQ(isEnable, tempStatus);
    EXPECT_EQ(OsAccountManager::SetGlobalOsAccountConstraints(
        INVALID_CONSTRAINTS, false, commonOsAccountInfo.GetLocalId(), true), ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    ASSERT_EQ(OsAccountManager::RemoveOsAccount(newOsAccountInfo.GetLocalId()), ERR_OK);
    ASSERT_TRUE(SetSelfTokenID(selfTokenId) == 0);
}

/**
 * @tc.name: OsAccountManagerModuleTest070
 * @tc.desc: Test SetGlobalOsAccountConstraints.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest070, TestSize.Level1)
{
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    ASSERT_TRUE(MockTokenId("edm"));
    OsAccountInfo osAccountInfoTwo;
    ASSERT_EQ(OsAccountManager::CreateOsAccount(STRING_TEST_NAME_TWO, OsAccountType::NORMAL, osAccountInfoTwo), ERR_OK);

    EXPECT_EQ(OsAccountManager::SetGlobalOsAccountConstraints(
        CONSTANTS_VECTOR, true, commonOsAccountInfo.GetLocalId(), true), ERR_OK);
    EXPECT_EQ(OsAccountManager::SetGlobalOsAccountConstraints(
        CONSTANTS_VECTOR, true, osAccountInfoTwo.GetLocalId(), true), ERR_OK);
    bool isEnable = false;
    EXPECT_EQ(
        OsAccountManager::IsOsAccountConstraintEnable(commonOsAccountInfo.GetLocalId(), CONSTANT_PRINT, isEnable),
        ERR_OK);
    EXPECT_EQ(isEnable, true);
    isEnable = false;
    EXPECT_EQ(
        OsAccountManager::IsOsAccountConstraintEnable(MAIN_ACCOUNT_ID, CONSTANT_PRINT, isEnable),
        ERR_OK);
    EXPECT_EQ(isEnable, true);
    isEnable = false;
    EXPECT_EQ(OsAccountManager::SetGlobalOsAccountConstraints(
        CONSTANTS_VECTOR, false, commonOsAccountInfo.GetLocalId(), true), ERR_OK);
    EXPECT_EQ(
        OsAccountManager::IsOsAccountConstraintEnable(commonOsAccountInfo.GetLocalId(), CONSTANT_PRINT, isEnable),
        ERR_OK);
    EXPECT_EQ(isEnable, true);
    isEnable = false;
    EXPECT_EQ(
        OsAccountManager::IsOsAccountConstraintEnable(MAIN_ACCOUNT_ID, CONSTANT_PRINT, isEnable),
        ERR_OK);
    EXPECT_EQ(isEnable, true);

    ASSERT_EQ(OsAccountManager::RemoveOsAccount(osAccountInfoTwo.GetLocalId()), ERR_OK);
    isEnable = true;
    EXPECT_EQ(
        OsAccountManager::IsOsAccountConstraintEnable(MAIN_ACCOUNT_ID, CONSTANT_PRINT, isEnable),
        ERR_OK);
    EXPECT_EQ(isEnable, false);
    ASSERT_TRUE(SetSelfTokenID(selfTokenId) == 0);
}

/**
 * @tc.name: OsAccountManagerModuleTest071
 * @tc.desc: Test SetSpecificOsAccountConstraints.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest071, TestSize.Level1)
{
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    ASSERT_TRUE(MockTokenId("edm"));
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(OsAccountManager::CreateOsAccount("ModuleTest071", OsAccountType::NORMAL, osAccountInfoOne), ERR_OK);

    EXPECT_EQ(OsAccountManager::SetSpecificOsAccountConstraints(
        CONSTANTS_VECTOR, true, MAIN_ACCOUNT_ID, osAccountInfoOne.GetLocalId(), true), ERR_OK);
    bool isEnable = true;
    EXPECT_EQ(
        OsAccountManager::IsOsAccountConstraintEnable(osAccountInfoOne.GetLocalId(), CONSTANT_PRINT, isEnable),
        ERR_OK);
    EXPECT_EQ(isEnable, false);
    isEnable = false;
    EXPECT_EQ(
        OsAccountManager::IsOsAccountConstraintEnable(MAIN_ACCOUNT_ID, CONSTANT_PRINT, isEnable),
        ERR_OK);
    EXPECT_EQ(isEnable, true);
    isEnable = true;
    EXPECT_EQ(OsAccountManager::SetSpecificOsAccountConstraints(
        CONSTANTS_VECTOR, false, MAIN_ACCOUNT_ID, osAccountInfoOne.GetLocalId(), true), ERR_OK);
    EXPECT_EQ(
        OsAccountManager::IsOsAccountConstraintEnable(MAIN_ACCOUNT_ID, CONSTANT_PRINT, isEnable),
        ERR_OK);
    EXPECT_EQ(isEnable, false);
    EXPECT_EQ(OsAccountManager::SetSpecificOsAccountConstraints(INVALID_CONSTRAINTS, false, MAIN_ACCOUNT_ID,
        osAccountInfoOne.GetLocalId(), true), ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    ASSERT_EQ(OsAccountManager::RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    ASSERT_TRUE(SetSelfTokenID(selfTokenId) == 0);
}

/**
 * @tc.name: OsAccountManagerModuleTest072
 * @tc.desc: Test QueryOsAccountConstraintSourceTypes.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest072, TestSize.Level1)
{
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    ASSERT_TRUE(MockTokenId("edm"));
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(OsAccountManager::CreateOsAccount("ModuleTest072", OsAccountType::NORMAL, osAccountInfoOne), ERR_OK);
    EXPECT_EQ(OsAccountManager::SetSpecificOsAccountConstraints(
        CONSTANTS_VECTOR, true, MAIN_ACCOUNT_ID, osAccountInfoOne.GetLocalId(), true), ERR_OK);
    bool isEnable = false;
    EXPECT_EQ(
        OsAccountManager::IsOsAccountConstraintEnable(MAIN_ACCOUNT_ID, CONSTANT_PRINT, isEnable),
        ERR_OK);
    EXPECT_EQ(isEnable, true);

    std::vector<ConstraintSourceTypeInfo> constraintSourceTypeInfos;
    EXPECT_EQ(OsAccountManager::QueryOsAccountConstraintSourceTypes(
        MAIN_ACCOUNT_ID, CONSTANT_PRINT, constraintSourceTypeInfos), ERR_OK);

    EXPECT_EQ(constraintSourceTypeInfos[0].typeInfo, 2);
    ASSERT_EQ(OsAccountManager::RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    constraintSourceTypeInfos.clear();
    EXPECT_NE(OsAccountManager::QueryOsAccountConstraintSourceTypes(
        999, CONSTANT_PRINT, constraintSourceTypeInfos), ERR_OK);
    isEnable = true;
    EXPECT_EQ(
        OsAccountManager::IsOsAccountConstraintEnable(MAIN_ACCOUNT_ID, CONSTANT_PRINT, isEnable),
        ERR_OK);
    EXPECT_EQ(isEnable, false);
    ASSERT_TRUE(SetSelfTokenID(selfTokenId) == 0);
}

/**
 * @tc.name: OsAccountManagerModuleTest073
 * @tc.desc: Test QueryOsAccountConstraintSourceTypes.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest073, TestSize.Level1)
{
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    ASSERT_TRUE(MockTokenId("edm"));
    OsAccountInfo osAccountInfoOne;
    ASSERT_EQ(OsAccountManager::CreateOsAccount("ModuleTest073", OsAccountType::NORMAL, osAccountInfoOne), ERR_OK);
    OsAccountInfo osAccountInfoTwo;
    ASSERT_EQ(OsAccountManager::CreateOsAccount(STRING_TEST_NAME_TWO, OsAccountType::NORMAL, osAccountInfoTwo), ERR_OK);

    std::vector<ConstraintSourceTypeInfo> constraintSourceTypeInfos;
    EXPECT_EQ(OsAccountManager::QueryOsAccountConstraintSourceTypes(
        MAIN_ACCOUNT_ID, CONSTANT_PRINT, constraintSourceTypeInfos), ERR_OK);
    EXPECT_EQ(constraintSourceTypeInfos[0].typeInfo, 0);

    EXPECT_EQ(OsAccountManager::SetGlobalOsAccountConstraints(
        CONSTANTS_VECTOR_TEST, true, osAccountInfoOne.GetLocalId(), false), ERR_OK);
    EXPECT_EQ(OsAccountManager::SetGlobalOsAccountConstraints(
        CONSTANTS_VECTOR_TEST, true, osAccountInfoTwo.GetLocalId(), false), ERR_OK);

    bool isEnable = false;
    EXPECT_EQ(
        OsAccountManager::IsOsAccountConstraintEnable(MAIN_ACCOUNT_ID, CONSTRAINT_PRIVATE_DNS_SET, isEnable),
        ERR_OK);
    EXPECT_EQ(isEnable, true);

    EXPECT_EQ(OsAccountManager::QueryOsAccountConstraintSourceTypes(
        MAIN_ACCOUNT_ID, CONSTRAINT_PRIVATE_DNS_SET, constraintSourceTypeInfos), ERR_OK);
    EXPECT_EQ(constraintSourceTypeInfos.size(), 2);
    ACCOUNT_LOGD("OsAccountManagerModuleTest073  constraintSourceTypeInfos %{public}d  %{public}d",
        constraintSourceTypeInfos[0].localId, constraintSourceTypeInfos[0].typeInfo);
    ACCOUNT_LOGD("OsAccountManagerModuleTest073  constraintSourceTypeInfos %{public}d  %{public}d",
        constraintSourceTypeInfos[1].localId, constraintSourceTypeInfos[1].typeInfo);
    ASSERT_EQ(OsAccountManager::RemoveOsAccount(osAccountInfoTwo.GetLocalId()), ERR_OK);

    ASSERT_EQ(OsAccountManager::RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);

    EXPECT_EQ(OsAccountManager::QueryOsAccountConstraintSourceTypes(
        MAIN_ACCOUNT_ID, CONSTRAINT_PRIVATE_DNS_SET, constraintSourceTypeInfos), ERR_OK);
    EXPECT_EQ(constraintSourceTypeInfos.size(), 1);
    EXPECT_EQ(constraintSourceTypeInfos[0].typeInfo, 0);
    ASSERT_TRUE(SetSelfTokenID(selfTokenId) == 0);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: OsAccountManagerModuleTest074
 * @tc.desc: Test QueryOsAccountConstraintSourceTypes.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest074, TestSize.Level1)
{
    std::vector<ConstraintSourceTypeInfo> constraintSourceTypeInfos;
    EXPECT_EQ(OsAccountManager::QueryOsAccountConstraintSourceTypes(
        MAIN_ACCOUNT_ID, CONSTRAINT_PRIVATE_DNS_SET, constraintSourceTypeInfos), ERR_OK);
    EXPECT_EQ(constraintSourceTypeInfos.size(), 1);
    EXPECT_EQ(constraintSourceTypeInfos[0].typeInfo, 0);
}

/**
 * @tc.name: OsAccountManagerModuleTest075
 * @tc.desc: Test GetOsAccountAllConstraints.
 * @tc.type: FUNC
 * @tc.require:
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest075, TestSize.Level1)
{
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    ASSERT_TRUE(MockTokenId("edm"));
    std::vector<std::string> constraints;
    EXPECT_EQ(OsAccountManager::GetOsAccountAllConstraints(commonOsAccountInfo.GetLocalId(), constraints), ERR_OK);
    int counts = constraints.size();

    EXPECT_EQ(OsAccountManager::SetGlobalOsAccountConstraints(
        CONSTANTS_VECTOR_TEST, true, commonOsAccountInfo.GetLocalId(), true), ERR_OK);

    EXPECT_EQ(OsAccountManager::SetSpecificOsAccountConstraints(
        CONSTANTS_VECTOR_TEST, true, MAIN_ACCOUNT_ID, commonOsAccountInfo.GetLocalId(), true), ERR_OK);

    constraints.clear();
    EXPECT_EQ(OsAccountManager::GetOsAccountAllConstraints(commonOsAccountInfo.GetLocalId(), constraints), ERR_OK);
    EXPECT_NE(constraints.size(), counts + 2); // test number
    ASSERT_TRUE(SetSelfTokenID(selfTokenId) == 0);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: OsAccountManagerModuleTest076
 * @tc.desc: Test IsCurrentOsAccountVerified.
 * @tc.type: FUNC
 * @tc.require: issueI4JBFI
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest076, TestSize.Level1)
{
    bool isVerified = true;
    EXPECT_EQ(OsAccountManager::IsCurrentOsAccountVerified(isVerified), ERR_OK);
    EXPECT_EQ(isVerified, false);
}

/**
 * @tc.name: OsAccountManagerModuleTest077
 * @tc.desc: Test IsOsAccountCompleted.
 * @tc.type: FUNC
 * @tc.require: issueI4JBFI
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest077, TestSize.Level1)
{
    bool isOsAccountCompleted = false;
    EXPECT_EQ(OsAccountManager::IsOsAccountCompleted(MAIN_ACCOUNT_ID, isOsAccountCompleted), ERR_OK);
    EXPECT_EQ(isOsAccountCompleted, true);
}

/**
 * @tc.name: OsAccountManagerModuleTest078
 * @tc.desc: Test IsOsAccountCompleted.
 * @tc.type: FUNC
 * @tc.require: issueI4JBFI
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest078, TestSize.Level1)
{
    bool isOsAccountCompleted = true;
    EXPECT_NE(OsAccountManager::IsOsAccountCompleted(ERROR_LOCAL_ID, isOsAccountCompleted), ERR_OK);
    EXPECT_EQ(isOsAccountCompleted, false);
}

/**
 * @tc.name: OsAccountManagerModuleTest079
 * @tc.desc: Test SetCurrentOsAccountIsVerified.
 * @tc.type: FUNC
 * @tc.require: issueI4JBFI
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest079, TestSize.Level1)
{
    bool isVerified = true;
    EXPECT_NE(OsAccountManager::SetCurrentOsAccountIsVerified(true), ERR_OK);
    EXPECT_EQ(OsAccountManager::IsCurrentOsAccountVerified(isVerified), ERR_OK);
    EXPECT_EQ(isVerified, false);
}

#if defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
/**
 * @tc.name: OsAccountManagerModuleTest080
 * @tc.desc: Test GetCreatedOsAccountNumFromDatabase.
 * @tc.type: FUNC
 * @tc.require: issueI4JBFI
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest080, TestSize.Level1)
{
    int createdOsAccountNum = -1;
    #ifdef BUNDLE_ADAPTER_MOCK
    EXPECT_NE(OsAccountManager::GetCreatedOsAccountNumFromDatabase("", createdOsAccountNum), ERR_OK);
    #else // BUNDLE_ADAPTER_MOCK
    EXPECT_EQ(OsAccountManager::GetCreatedOsAccountNumFromDatabase("", createdOsAccountNum), ERR_OK);
    EXPECT_NE(createdOsAccountNum, -1);
    #endif
}

/**
 * @tc.name: OsAccountManagerModuleTest081
 * @tc.desc: Test GetCreatedOsAccountNumFromDatabase.
 * @tc.type: FUNC
 * @tc.require: issueI4JBFI
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest081, TestSize.Level1)
{
    int createdOsAccountNum = -1;
    EXPECT_NE(OsAccountManager::GetCreatedOsAccountNumFromDatabase("ERROR_STORE_ID", createdOsAccountNum), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest082
 * @tc.desc: Test GetSerialNumberFromDatabase.
 * @tc.type: FUNC
 * @tc.require: issueI4JBFI
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest082, TestSize.Level1)
{
    int64_t serialNumber = -1;
    #ifdef BUNDLE_ADAPTER_MOCK
    EXPECT_NE(OsAccountManager::GetSerialNumberFromDatabase("", serialNumber), ERR_OK);
    #else // BUNDLE_ADAPTER_MOCK
    EXPECT_EQ(OsAccountManager::GetSerialNumberFromDatabase("", serialNumber), ERR_OK);
    EXPECT_NE(serialNumber, -1);
    #endif
}

/**
 * @tc.name: OsAccountManagerModuleTest083
 * @tc.desc: Test GetSerialNumberFromDatabase.
 * @tc.type: FUNC
 * @tc.require: issueI4JBFI
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest083, TestSize.Level1)
{
    int64_t serialNumber = -1;
    EXPECT_NE(OsAccountManager::GetSerialNumberFromDatabase("ERROR_STORE_ID", serialNumber), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest084
 * @tc.desc: Test GetMaxAllowCreateIdFromDatabase.
 * @tc.type: FUNC
 * @tc.require: issueI4JBFI
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest084, TestSize.Level1)
{
    int maxAllowCreateId = -1;
    #ifdef BUNDLE_ADAPTER_MOCK
    EXPECT_NE(OsAccountManager::GetMaxAllowCreateIdFromDatabase("", maxAllowCreateId), ERR_OK);
    #else // BUNDLE_ADAPTER_MOCK
    EXPECT_EQ(OsAccountManager::GetMaxAllowCreateIdFromDatabase("", maxAllowCreateId), ERR_OK);
    EXPECT_NE(maxAllowCreateId, -1);
    #endif
}

/**
 * @tc.name: OsAccountManagerModuleTest085
 * @tc.desc: Test GetMaxAllowCreateIdFromDatabase.
 * @tc.type: FUNC
 * @tc.require: issueI4JBFI
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest085, TestSize.Level1)
{
    int maxAllowCreateId = -1;
    EXPECT_NE(OsAccountManager::GetMaxAllowCreateIdFromDatabase("ERROR_STORE_ID", maxAllowCreateId), ERR_OK);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: OsAccountManagerModuleTest086
 * @tc.desc: Test GetOsAccountListFromDatabase.
 * @tc.type: FUNC
 * @tc.require: issueI4JBFI
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest086, TestSize.Level1)
{
    std::vector<OsAccountInfo> osAccountList;
    #ifdef BUNDLE_ADAPTER_MOCK
    EXPECT_NE(OsAccountManager::GetOsAccountListFromDatabase("", osAccountList), ERR_OK);
    #else // BUNDLE_ADAPTER_MOCK
    EXPECT_EQ(OsAccountManager::GetOsAccountListFromDatabase("", osAccountList), ERR_OK);
    EXPECT_NE(osAccountList.size(), 0);
    #endif
}

/**
 * @tc.name: OsAccountManagerModuleTest087
 * @tc.desc: Test GetOsAccountListFromDatabase.
 * @tc.type: FUNC
 * @tc.require: issueI4JBFI
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest087, TestSize.Level1)
{
    std::vector<OsAccountInfo> osAccountList;
    #ifdef BUNDLE_ADAPTER_MOCK
    EXPECT_NE(OsAccountManager::GetOsAccountListFromDatabase("ERROR_STORE_ID", osAccountList), ERR_OK);
    #else // BUNDLE_ADAPTER_MOCK
    EXPECT_EQ(OsAccountManager::GetOsAccountListFromDatabase("ERROR_STORE_ID", osAccountList), ERR_OK);
    EXPECT_EQ(osAccountList.size(), 0);
    #endif
}
#endif // defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)

/**
 * @tc.name: OsAccountManagerModuleTest088
 * @tc.desc: Test ActivateOsAccount.
 * @tc.type: FUNC
 * @tc.require: issueI4JBFI
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest088, TestSize.Level1)
{
    EXPECT_NE(OsAccountManager::ActivateOsAccount(INVALID_ID), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest089
 * @tc.desc: Test ActivateOsAccount.
 * @tc.type: FUNC
 * @tc.require: issueI4JBFI
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest089, TestSize.Level1)
{
    EXPECT_NE(OsAccountManager::ActivateOsAccount(ERROR_LOCAL_ID), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest090
 * @tc.desc: Test remove activating os account.
 * @tc.type: FUNC
 * @tc.require: issueI4JBFI
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest090, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    EXPECT_EQ(OsAccountManager::CreateOsAccount("ModuleTest090", OsAccountType::NORMAL, osAccountInfoOne), ERR_OK);
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: UnlockUserTest001
 * @tc.desc: Test 'unlockUser' without PIN when secret_flag exist and user is locked.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, UnlockUserTest001, TestSize.Level4)
{
    OsAccountInfo osAccountInfo;
    ASSERT_EQ(OsAccountManager::CreateOsAccount("UnlockUserTest001", OsAccountType::NORMAL, osAccountInfo), ERR_OK);
    std::string path = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR +
        std::to_string(osAccountInfo.GetLocalId()) + Constants::PATH_SEPARATOR + Constants::USER_SECRET_FLAG_FILE_NAME;
    auto accountFileOperator = std::make_shared<AccountFileOperator>();
    EXPECT_EQ(accountFileOperator->InputFileByPathAndContent(path, ""), ERR_OK);
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(osAccountInfo.GetLocalId()), ERR_OK);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(osAccountInfo.GetLocalId()), ERR_OK);
}

  /**
   * @tc.name: UnlockUserTest002
   * @tc.desc: Test 'unlockUser' without PIN when secret_flag exist and user is already unlocked.
   * @tc.type: FUNC
   * @tc.require:
   */
HWTEST_F(OsAccountManagerModuleTest, UnlockUserTest002, TestSize.Level4)
{
    OsAccountInfo osAccountInfo;
    ASSERT_EQ(OsAccountManager::CreateOsAccount("UnlockUserTest002", OsAccountType::NORMAL, osAccountInfo), ERR_OK);
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(osAccountInfo.GetLocalId()), ERR_OK);
    std::string path = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR +
        std::to_string(osAccountInfo.GetLocalId()) + Constants::PATH_SEPARATOR + Constants::USER_SECRET_FLAG_FILE_NAME;
    auto accountFileOperator = std::make_shared<AccountFileOperator>();
    EXPECT_EQ(accountFileOperator->InputFileByPathAndContent(path, ""), ERR_OK);
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(MAIN_ACCOUNT_ID), ERR_OK);
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(osAccountInfo.GetLocalId()), ERR_OK);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(osAccountInfo.GetLocalId()), ERR_OK);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: OsAccountManagerModuleTest091
 * @tc.desc: Test SubscribeOsAccount.
 * @tc.type: FUNC
 * @tc.require: issueI4JBFI
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest091, TestSize.Level1)
{
    std::shared_ptr<OsAccountSubscriber> subscriber = nullptr;
    EXPECT_NE(OsAccountManager::SubscribeOsAccount(subscriber), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest092
 * @tc.desc: Test UnsubscribeOsAccount.
 * @tc.type: FUNC
 * @tc.require: issueI4JBFI
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest092, TestSize.Level1)
{
    std::shared_ptr<OsAccountSubscriber> subscriber = nullptr;
    EXPECT_NE(OsAccountManager::UnsubscribeOsAccount(subscriber), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest093
 * @tc.desc: Test GetOsAccountSwitchMod.
 * @tc.type: FUNC
 * @tc.require: issueI4JBFI
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest093, TestSize.Level1)
{
    int modResult = 1;
    EXPECT_EQ(OsAccountManager::GetOsAccountSwitchMod(), modResult);
}

class TestOsAccountSubscriber : public OsAccountSubscriber {
public:
    void OnAccountsChanged(const int& id) {}
};

/**
 * @tc.name: OsAccountManagerModuleTest095
 * @tc.desc: test SubscribeOsAccount/UnSubscribeOsAccount nomal branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest095, TestSize.Level1)
{
    auto subscriber = std::make_shared<TestOsAccountSubscriber>();
    EXPECT_NE(nullptr, subscriber);
    EXPECT_EQ(ERR_OK, OsAccountManager::SubscribeOsAccount(subscriber));
    EXPECT_EQ(ERR_OK, OsAccountManager::UnsubscribeOsAccount(subscriber));
}

/**
 * @tc.name: OsAccountManagerModuleTest096
 * @tc.desc: test SubscribeOsAccount subscribed twice.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest096, TestSize.Level1)
{
    auto subscriber = std::make_shared<TestOsAccountSubscriber>();
    EXPECT_NE(nullptr, subscriber);
    EXPECT_EQ(ERR_OK, OsAccountManager::SubscribeOsAccount(subscriber));
    EXPECT_EQ(ERR_OK, OsAccountManager::SubscribeOsAccount(subscriber));
    EXPECT_EQ(ERR_OK, OsAccountManager::UnsubscribeOsAccount(subscriber));
}

/**
 * @tc.name: OsAccountManagerModuleTest097
 * @tc.desc: test SubscribeOsAccount subscribed exceed limitation.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest097, TestSize.Level1)
{
    std::vector<std::shared_ptr<OsAccountSubscriber>> subscribers;
    for (int i = 0; i < Constants::SUBSCRIBER_MAX_SIZE; i++) {
        auto subscriber = std::make_shared<TestOsAccountSubscriber>();
        EXPECT_NE(nullptr, subscriber);
        EXPECT_EQ(ERR_OK, OsAccountManager::SubscribeOsAccount(subscriber));
        subscribers.emplace_back(subscriber);
    }
    auto subscriber = std::make_shared<TestOsAccountSubscriber>();
    EXPECT_NE(nullptr, subscriber);
    EXPECT_EQ(ERR_OSACCOUNT_KIT_SUBSCRIBE_ERROR, OsAccountManager::SubscribeOsAccount(subscriber));

    for (int i = 0; i < Constants::SUBSCRIBER_MAX_SIZE; i++) {
        EXPECT_EQ(ERR_OK, OsAccountManager::UnsubscribeOsAccount(subscribers[i]));
    }
}

/**
 * @tc.name: OsAccountManagerModuleTest098
 * @tc.desc: test UnsubscribeOsAccount not subscribed .
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest098, TestSize.Level1)
{
    auto subscriber = std::make_shared<TestOsAccountSubscriber>();
    EXPECT_NE(nullptr, subscriber);
    EXPECT_EQ(ERR_OSACCOUNT_KIT_NO_SPECIFIED_SUBSCRIBER_HAS_BEEN_REGISTERED,
        OsAccountManager::UnsubscribeOsAccount(subscriber));
}

#if defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)
/**
 * @tc.name: OsAccountManagerModuleTest099
 * @tc.desc: test GetOsAccountFromDatabase normal branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest099, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
#ifdef BUNDLE_ADAPTER_MOCK
    EXPECT_NE(ERR_OK, OsAccountManager::GetOsAccountFromDatabase("", MAIN_ACCOUNT_ID, osAccountInfo));
#else // BUNDLE_ADAPTER_MOCK
    EXPECT_EQ(ERR_OK, OsAccountManager::GetOsAccountFromDatabase("", MAIN_ACCOUNT_ID, osAccountInfo));
#endif
}
#endif // defined(HAS_KV_STORE_PART) && defined(DISTRIBUTED_FEATURE_ENABLED)

/**
 * @tc.name: OsAccountManagerModuleTest100
 * @tc.desc: test cGetOsAccountLocalIdFromUid with invalid uid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest100, TestSize.Level1)
{
    int uid = -1;
    int id;
    EXPECT_EQ(ERR_ACCOUNT_COMMON_INVALID_PARAMETER, OsAccountManager::GetOsAccountLocalIdFromUid(uid, id));
}

/**
 * @tc.name: OsAccountManagerModuleTest101
 * @tc.desc: test cGetOsAccountLocalIdFromUid with invalid uid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest101, TestSize.Level1)
{
    int uid = -1;
    int bundleId;
    EXPECT_EQ(ERR_ACCOUNT_COMMON_INVALID_PARAMETER, OsAccountManager::GetBundleIdFromUid(uid, bundleId));
}

/**
 * @tc.name: OsAccountManagerModuleTest102
 * @tc.desc: test IsOsAccountActived with invalid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest102, TestSize.Level1)
{
    bool isOsAccountActived = true;
    EXPECT_EQ(OsAccountManager::IsOsAccountActived(Constants::MAX_USER_ID + 1, isOsAccountActived),
        ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
    EXPECT_EQ(isOsAccountActived, false);
}

/**
 * @tc.name: OsAccountManagerModuleTest103
 * @tc.desc: test IsOsAccountConstraintEnable/CheckOsAccountConstraintEnabled with invalid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest103, TestSize.Level1)
{
    bool isConstraintEnable = true;
    EXPECT_EQ(ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR, OsAccountManager::IsOsAccountConstraintEnable(
        Constants::MAX_USER_ID + 1, CONSTANT_PRINT, isConstraintEnable));
    EXPECT_EQ(isConstraintEnable, false);
    EXPECT_EQ(ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR, OsAccountManager::CheckOsAccountConstraintEnabled(
        Constants::MAX_USER_ID + 1, CONSTANT_PRINT, isConstraintEnable));
    EXPECT_EQ(isConstraintEnable, false);
}

/**
 * @tc.name: OsAccountManagerModuleTest104
 * @tc.desc: test SetOsAccountName with invalid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest104, TestSize.Level1)
{
    const std::string localName = "testname";
    EXPECT_EQ(OsAccountManager::SetOsAccountName(Constants::MAX_USER_ID + 1, localName),
        ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
    EXPECT_EQ(localName, "testname");
}

/**
 * @tc.name: OsAccountManagerModuleTest106
 * @tc.desc: test SetOsAccountProfilePhoto with invalid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest106, TestSize.Level1)
{
    EXPECT_EQ(OsAccountManager::SetOsAccountProfilePhoto(Constants::MAX_USER_ID + 1, PHOTO_IMG),
        ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: OsAccountManagerModuleTest108
 * @tc.desc: test SetOsAccountIsVerified with invalid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest108, TestSize.Level1)
{
    EXPECT_EQ(OsAccountManager::SetOsAccountIsVerified(Constants::MAX_USER_ID + 1, false),
        ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: OsAccountManagerModuleTest110
 * @tc.desc: Test osaccount call service interface not pass system applicaiton verify.
 * @tc.type: FUNC
 * @tc.require: issueI66BG5
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest110, TestSize.Level3)
{
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission(ALL_ACCOUNT_PERMISSION_LIST, tokenID, false));

    OsAccountInfo osAccountInfoTwo;
    ASSERT_EQ(
        OsAccountManager::QueryOsAccountById(LOCAL_ID, osAccountInfoTwo), ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);

    std::string photo;
    ASSERT_EQ(OsAccountManager::GetOsAccountProfilePhoto(LOCAL_ID, photo), ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);

    ASSERT_EQ(OsAccountManager::SetOsAccountProfilePhoto(LOCAL_ID, PHOTO_IMG), ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);

    auto subscriber = std::make_shared<TestOsAccountSubscriber>();
    ASSERT_NE(nullptr, subscriber);
    ASSERT_EQ(OsAccountManager::SubscribeOsAccount(subscriber), ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);

    bool isMainOsAccount = false;
    ASSERT_EQ(OsAccountManager::IsMainOsAccount(isMainOsAccount), ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);

    std::vector<ConstraintSourceTypeInfo> constraintSourceTypeInfos;
    ASSERT_EQ(OsAccountManager::QueryOsAccountConstraintSourceTypes(
        MAIN_ACCOUNT_ID, CONSTANT_PRINT, constraintSourceTypeInfos), ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);

    ASSERT_TRUE(RecoveryPermission(tokenID));
}

/**
 * @tc.name: OsAccountManagerModuleTest112
 * @tc.desc: Test osaccount call service interface pass system app verify.
 * @tc.type: FUNC
 * @tc.require: issueI66BG5
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest112, TestSize.Level3)
{
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission(ALL_ACCOUNT_PERMISSION_LIST, tokenID));

    OsAccountInfo osAccountInfoTwo;
    ASSERT_NE(
        OsAccountManager::QueryOsAccountById(LOCAL_ID, osAccountInfoTwo), ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);

    std::string photo;
    ASSERT_NE(OsAccountManager::GetOsAccountProfilePhoto(LOCAL_ID, photo), ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);

    ASSERT_NE(OsAccountManager::SetOsAccountProfilePhoto(LOCAL_ID, PHOTO_IMG), ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);

    auto subscriber = std::make_shared<TestOsAccountSubscriber>();
    ASSERT_NE(nullptr, subscriber);
    ASSERT_NE(OsAccountManager::SubscribeOsAccount(subscriber), ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);

    auto subscriberTwo = std::make_shared<TestOsAccountSubscriber>();
    ASSERT_NE(nullptr, subscriberTwo);
    ASSERT_EQ(ERR_OK, OsAccountManager::SubscribeOsAccount(subscriberTwo));
    ASSERT_EQ(OsAccountManager::UnsubscribeOsAccount(subscriberTwo), ERR_OK);

    bool isMainOsAccount = false;
    ASSERT_NE(OsAccountManager::IsMainOsAccount(isMainOsAccount), ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);

    std::vector<ConstraintSourceTypeInfo> constraintSourceTypeInfos;
    ASSERT_NE(OsAccountManager::QueryOsAccountConstraintSourceTypes(
        MAIN_ACCOUNT_ID, CONSTANT_PRINT, constraintSourceTypeInfos), ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);

    ASSERT_TRUE(RecoveryPermission(tokenID));
}

/**
 * @tc.name: OsAccountManagerModuleTest113
 * @tc.desc: Test set/get default activated os account id.
 * @tc.type: FUNC
 * @tc.require: issueI6AQUQ
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest113, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    int id;
    EXPECT_EQ(OsAccountManager::GetDefaultActivatedOsAccount(id), ERR_OK);
    EXPECT_EQ(id, MAIN_ACCOUNT_ID);
    // The test set a nonexistent id as the default id
    EXPECT_NE(OsAccountManager::SetDefaultActivatedOsAccount(commonOsAccountInfo.GetLocalId() + 1), ERR_OK);
    EXPECT_NE(OsAccountManager::SetDefaultActivatedOsAccount(MAIN_ACCOUNT_ID - 1), ERR_OK);
    EXPECT_NE(OsAccountManager::SetDefaultActivatedOsAccount(Constants::MAX_USER_ID + 1), ERR_OK);
    EXPECT_EQ(OsAccountManager::CreateOsAccount("ModuleTest113", OsAccountType::NORMAL, osAccountInfoOne), ERR_OK);
    EXPECT_EQ(OsAccountManager::SetDefaultActivatedOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    EXPECT_EQ(OsAccountManager::GetDefaultActivatedOsAccount(id), ERR_OK);
    EXPECT_EQ(id, osAccountInfoOne.GetLocalId());
    EXPECT_EQ(OsAccountManager::SetDefaultActivatedOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(osAccountInfoOne.GetLocalId()), ERR_OK);
    EXPECT_EQ(OsAccountManager::GetDefaultActivatedOsAccount(id), ERR_OK);
    EXPECT_NE(id, osAccountInfoOne.GetLocalId());
    EXPECT_EQ(id, MAIN_ACCOUNT_ID);
    EXPECT_EQ(OsAccountManager::SetDefaultActivatedOsAccount(MAIN_ACCOUNT_ID), ERR_OK);
    EXPECT_EQ(OsAccountManager::GetDefaultActivatedOsAccount(id), ERR_OK);
    EXPECT_EQ(id, MAIN_ACCOUNT_ID);
}

/**
 * @tc.name: OsAccountManagerModuleTest114
 * @tc.desc: Test DeactivateOsAccount success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest114, TestSize.Level1)
{
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(commonOsAccountInfo.GetLocalId()), ERR_OK);

#ifndef BUNDLE_ADAPTER_MOCK
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_STOPPING);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_STOPPED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    auto listener = std::make_shared<MockSubscriberListener>();
    std::shared_ptr<AccountTestEventSubscriber> subscriberPtr =
        std::make_shared<AccountTestEventSubscriber>(subscribeInfo, listener);
    ASSERT_EQ(EventFwk::CommonEventManager::SubscribeCommonEvent(subscriberPtr), true);
    EXPECT_CALL(*listener, OnReceiveEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_STOPPING)).Times(Exactly(1));
    EXPECT_CALL(*listener, OnReceiveEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_STOPPED)).Times(Exactly(1));
#endif

    OsAccountSubscribeInfo subscribeStoppingInfo(OS_ACCOUNT_SUBSCRIBE_TYPE::STOPPING, "subscribeStopping");
    auto stoppingPtr = std::make_shared<MockOsAccountSubscriber>();
    auto stoppingSubscriber = std::make_shared<DeactivateOsAccountSubscriber>(subscribeStoppingInfo, stoppingPtr);
    EXPECT_EQ(ERR_OK, OsAccountManager::SubscribeOsAccount(stoppingSubscriber));
    EXPECT_CALL(*stoppingPtr, OnAccountsChanged(commonOsAccountInfo.GetLocalId())).Times(Exactly(1));

    OsAccountSubscribeInfo subscribeStoppedInfo(OS_ACCOUNT_SUBSCRIBE_TYPE::STOPPED, "subscribeStopped");
    auto stoppedPtr = std::make_shared<MockOsAccountSubscriber>();
    auto stoppedSubscriber = std::make_shared<DeactivateOsAccountSubscriber>(subscribeStoppedInfo, stoppedPtr);
    EXPECT_EQ(ERR_OK, OsAccountManager::SubscribeOsAccount(stoppedSubscriber));
    EXPECT_CALL(*stoppedPtr, OnAccountsChanged(commonOsAccountInfo.GetLocalId())).Times(Exactly(1));
    OsAccount::GetInstance().RestoreListenerRecords();

    EXPECT_EQ(OsAccountManager::DeactivateOsAccount(commonOsAccountInfo.GetLocalId()), ERR_OK);

#ifndef BUNDLE_ADAPTER_MOCK
    Wait(subscriberPtr);
#endif
    Wait(stoppingSubscriber);
    Wait(stoppedSubscriber);

#ifndef BUNDLE_ADAPTER_MOCK
    EXPECT_EQ(EventFwk::CommonEventManager::UnSubscribeCommonEvent(subscriberPtr), true);
#endif
    EXPECT_EQ(ERR_OK, OsAccountManager::UnsubscribeOsAccount(stoppingSubscriber));
    EXPECT_EQ(ERR_OK, OsAccountManager::UnsubscribeOsAccount(stoppedSubscriber));
#ifndef BUNDLE_ADAPTER_MOCK
    testing::Mock::AllowLeak(listener.get());
#endif
}

/**
 * @tc.name: OsAccountManagerModuleTest115
 * @tc.desc: Test DeactivateOsAccount with invalid id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest115, TestSize.Level1)
{
#ifndef SUPPORT_STOP_MAIN_OS_ACCOUNT
    EXPECT_EQ(OsAccountManager::DeactivateOsAccount(Constants::START_USER_ID),
              ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_STOP_ACTIVE_ERROR);
#else
    EXPECT_EQ(OsAccountManager::DeactivateOsAccount(Constants::START_USER_ID), ERR_OK);
#endif
    EXPECT_EQ(OsAccountManager::DeactivateOsAccount(Constants::START_USER_ID - 1),
              ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
    EXPECT_EQ(OsAccountManager::DeactivateOsAccount(Constants::MAX_USER_ID + 1),
        ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: OsAccountManagerModuleTest116
 * @tc.desc: Test ActivateOsAccount.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest116, TestSize.Level1)
{
    OsAccountManager::ActivateOsAccount(MAIN_ACCOUNT_ID);

    // activing os account
    OsAccountSubscribeInfo subscribeActivingInfo(OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATING, "subscribeActiving");
    auto activingSubscriber = std::make_shared<ActiveOsAccountSubscriber>(subscribeActivingInfo);
    EXPECT_EQ(ERR_OK, OsAccountManager::SubscribeOsAccount(activingSubscriber));
    EXPECT_CALL(*activingSubscriber, OnAccountsChanged(commonOsAccountInfo.GetLocalId())).Times(Exactly(1));
    // activated os account
    OsAccountSubscribeInfo subscribeActivatedInfo(OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATED, "subscribeActivated");
    auto activedSubscriber = std::make_shared<ActiveOsAccountSubscriber>(subscribeActivatedInfo);
    EXPECT_EQ(ERR_OK, OsAccountManager::SubscribeOsAccount(activedSubscriber));
    EXPECT_CALL(*activedSubscriber, OnAccountsChanged(commonOsAccountInfo.GetLocalId())).Times(Exactly(1));

    // switched os account
    OsAccountSubscribeInfo subscribeSwitchedInfo(OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHED, "subscribeSwitched");
    auto switchedSubscriber = std::make_shared<ActiveOsAccountSubscriber>(subscribeSwitchedInfo);
    EXPECT_EQ(ERR_OK, OsAccountManager::SubscribeOsAccount(switchedSubscriber));
    EXPECT_CALL(*switchedSubscriber, OnAccountsSwitch(
        commonOsAccountInfo.GetLocalId(), MAIN_ACCOUNT_ID)).Times(Exactly(1));

    // switching os account
    OsAccountSubscribeInfo subscribeSwitchingInfo(OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHING, "subscribeSwitching");
    auto switchingSubscriber = std::make_shared<ActiveOsAccountSubscriber>(subscribeSwitchingInfo);
    EXPECT_EQ(ERR_OK, OsAccountManager::SubscribeOsAccount(switchingSubscriber));
    EXPECT_CALL(*switchingSubscriber, OnAccountsSwitch(
        commonOsAccountInfo.GetLocalId(), MAIN_ACCOUNT_ID)).Times(Exactly(1));
    OsAccount::GetInstance().RestoreListenerRecords();

    // common event: COMMON_EVENT_USER_FOREGROUND 、 COMMON_EVENT_USER_BACKGROUND
#ifndef BUNDLE_ADAPTER_MOCK
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_USER_FOREGROUND);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_USER_BACKGROUND);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    auto listener = std::make_shared<MockSubscriberListener>();
    std::shared_ptr<AccountTestEventSubscriber> subscriberPtr =
        std::make_shared<AccountTestEventSubscriber>(subscribeInfo, listener);
    ASSERT_EQ(CommonEventManager::SubscribeCommonEvent(subscriberPtr), true);
    EXPECT_CALL(*listener, OnReceiveEvent(CommonEventSupport::COMMON_EVENT_USER_BACKGROUND)).Times(Exactly(1));
    EXPECT_CALL(*listener, OnReceiveEvent(CommonEventSupport::COMMON_EVENT_USER_FOREGROUND)).Times(Exactly(1));
#endif

    EXPECT_EQ(OsAccountManager::ActivateOsAccount(commonOsAccountInfo.GetLocalId()), ERR_OK);

#ifndef BUNDLE_ADAPTER_MOCK
    Wait(subscriberPtr);
#endif
    EXPECT_EQ(ERR_OK, OsAccountManager::UnsubscribeOsAccount(activingSubscriber));
    EXPECT_EQ(ERR_OK, OsAccountManager::UnsubscribeOsAccount(activedSubscriber));
    EXPECT_EQ(ERR_OK, OsAccountManager::UnsubscribeOsAccount(switchedSubscriber));
    EXPECT_EQ(ERR_OK, OsAccountManager::UnsubscribeOsAccount(switchingSubscriber));
#ifndef BUNDLE_ADAPTER_MOCK
    EXPECT_EQ(CommonEventManager::UnSubscribeCommonEvent(subscriberPtr), true);
#endif

    EXPECT_EQ(OsAccountManager::DeactivateOsAccount(commonOsAccountInfo.GetLocalId()), ERR_OK);
#ifndef BUNDLE_ADAPTER_MOCK
    testing::Mock::AllowLeak(listener.get());
#endif
}

#ifdef ENABLE_MULTIPLE_ACTIVE_ACCOUNTS
void TestStateAfterActivateOsAccount()
{
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(ERR_OK, OsAccountManager::QueryOsAccountById(commonOsAccountInfo.GetLocalId(), osAccountInfo));
    EXPECT_EQ(osAccountInfo.GetIsVerified(), true);
    EXPECT_EQ(osAccountInfo.GetIsLoggedIn(), true);
    EXPECT_EQ(osAccountInfo.GetIsActived(), true);
    EXPECT_EQ(osAccountInfo.GetIsForeground(), true);
    EXPECT_EQ(osAccountInfo.GetDisplayId(), 0);
    EXPECT_TRUE(osAccountInfo.GetLastLoginTime() > commonOsAccountInfo.GetLastLoginTime());

    EXPECT_EQ(ERR_OK, OsAccountManager::QueryOsAccountById(MAIN_ACCOUNT_ID, osAccountInfo));
    EXPECT_EQ(osAccountInfo.GetIsVerified(), true);
    EXPECT_EQ(osAccountInfo.GetIsLoggedIn(), true);
    EXPECT_EQ(osAccountInfo.GetIsActived(), true);
    EXPECT_EQ(osAccountInfo.GetIsForeground(), false);
    EXPECT_NE(osAccountInfo.GetDisplayId(), 0);
}

void TestStateAfterDeactivateOsAccount()
{
    OsAccountInfo osAccountInfo;
    EXPECT_EQ(ERR_OK, OsAccountManager::QueryOsAccountById(commonOsAccountInfo.GetLocalId(), osAccountInfo));
    DomainAccountInfo domainAccountInfo;
    osAccountInfo.GetDomainInfo(domainAccountInfo);
    EXPECT_EQ(domainAccountInfo.status_, DomainAccountStatus::LOGOUT);
    EXPECT_EQ(osAccountInfo.GetIsVerified(), false);
    EXPECT_EQ(osAccountInfo.GetIsLoggedIn(), false);
#ifndef SUPPORT_STOP_MAIN_OS_ACCOUNT
    EXPECT_EQ(osAccountInfo.GetIsActived(), false);
    EXPECT_EQ(osAccountInfo.GetIsForeground(), false);
    EXPECT_NE(osAccountInfo.GetDisplayId(), 0);

    EXPECT_EQ(ERR_OK, OsAccountManager::QueryOsAccountById(MAIN_ACCOUNT_ID, osAccountInfo));
    EXPECT_EQ(osAccountInfo.GetIsActived(), true);
    EXPECT_EQ(osAccountInfo.GetIsForeground(), true);
    EXPECT_EQ(osAccountInfo.GetDisplayId(), 0);
#else
    EXPECT_EQ(osAccountInfo.GetIsActived(), true);
    EXPECT_EQ(osAccountInfo.GetIsForeground(), true);
    EXPECT_EQ(osAccountInfo.GetDisplayId(), 0);
#endif
}

/**
 * @tc.name: OsAccountManagerModuleTest117
 * @tc.desc: Test ActivateOsAccount
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest117, TestSize.Level1)
{
#ifdef SUPPORT_STOP_MAIN_OS_ACCOUNT
    EXPECT_EQ(commonOsAccountInfo.GetIsForeground(), true);
    EXPECT_EQ(commonOsAccountInfo.GetDisplayId(), 0);
#else
    EXPECT_EQ(commonOsAccountInfo.GetIsForeground(), false);
    EXPECT_NE(commonOsAccountInfo.GetDisplayId(), 0);
#endif // SUPPORT_STOP_MAIN_OS_ACCOUNT
    std::vector<int32_t> ids;
    OsAccountManager::QueryActiveOsAccountIds(ids);
    EXPECT_EQ(ids.size() > 0, true);
#ifdef SUPPORT_STOP_MAIN_OS_ACCOUNT
    EXPECT_EQ(ids[0], commonOsAccountInfo.GetLocalId());
#else
    EXPECT_NE(ids[0], commonOsAccountInfo.GetLocalId());
#endif // SUPPORT_STOP_MAIN_OS_ACCOUNT

    EXPECT_EQ(OsAccountManager::ActivateOsAccount(commonOsAccountInfo.GetLocalId()), ERR_OK);
    ids.clear();
    OsAccountManager::QueryActiveOsAccountIds(ids);
    EXPECT_EQ(ids.size() > 0, true);
    EXPECT_EQ(ids[0], commonOsAccountInfo.GetLocalId());
    TestStateAfterActivateOsAccount();

    EXPECT_EQ(OsAccountManager::DeactivateOsAccount(commonOsAccountInfo.GetLocalId()), ERR_OK);
    ids.clear();
    OsAccountManager::QueryActiveOsAccountIds(ids);
    EXPECT_EQ(ids.size() > 0, true);
#ifndef SUPPORT_STOP_MAIN_OS_ACCOUNT
    EXPECT_EQ(ids[0], 100);
#else
    EXPECT_EQ(ids[0], commonOsAccountInfo.GetLocalId());
#endif
    TestStateAfterDeactivateOsAccount();
}
#endif

#ifdef SUPPORT_STOP_MAIN_OS_ACCOUNT
/**
 * @tc.name: OsAccountManagerModuleTest118
 * @tc.desc: Test ActivateOsAccount.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest118, TestSize.Level1)
{
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(commonOsAccountInfo.GetLocalId()), ERR_OK);

    // activing os account
    OsAccountSubscribeInfo subscribeActivingInfo(OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATING, "subscribeActiving");
    auto activingSubscriber = std::make_shared<ActiveOsAccountSubscriber>(subscribeActivingInfo);
    EXPECT_EQ(ERR_OK, OsAccountManager::SubscribeOsAccount(activingSubscriber));
    EXPECT_CALL(*activingSubscriber, OnAccountsChanged(commonOsAccountInfo.GetLocalId())).Times(Exactly(1));
    // activated os account
    OsAccountSubscribeInfo subscribeActivatedInfo(OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATED, "subscribeActived");
    auto activedSubscriber = std::make_shared<ActiveOsAccountSubscriber>(subscribeActivatedInfo);
    EXPECT_EQ(ERR_OK, OsAccountManager::SubscribeOsAccount(activedSubscriber));
    EXPECT_CALL(*activedSubscriber, OnAccountsChanged(commonOsAccountInfo.GetLocalId())).Times(Exactly(1));

    // switched os account
    OsAccountSubscribeInfo subscribeSwitchedInfo(OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHED, "subscribeSwitched");
    auto switchedSubscriber = std::make_shared<ActiveOsAccountSubscriber>(subscribeSwitchedInfo);
    EXPECT_EQ(ERR_OK, OsAccountManager::SubscribeOsAccount(switchedSubscriber));
    EXPECT_CALL(*switchedSubscriber, OnAccountsSwitch(commonOsAccountInfo.GetLocalId(), _)).Times(Exactly(1));

    // switching os account
    OsAccountSubscribeInfo subscribeSwitchingInfo(OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHING, "subscribeSwitching");
    auto switchingSubscriber = std::make_shared<ActiveOsAccountSubscriber>(subscribeSwitchingInfo);
    EXPECT_EQ(ERR_OK, OsAccountManager::SubscribeOsAccount(switchingSubscriber));
    EXPECT_CALL(*switchingSubscriber, OnAccountsSwitch(commonOsAccountInfo.GetLocalId(), _)).Times(Exactly(1));
    OsAccount::GetInstance().RestoreListenerRecords();

    // common event: COMMON_EVENT_USER_FOREGROUND 、 COMMON_EVENT_USER_BACKGROUND
#ifndef BUNDLE_ADAPTER_MOCK
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_USER_FOREGROUND);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_USER_BACKGROUND);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    auto listener = std::make_shared<MockSubscriberListener>();
    std::shared_ptr<AccountTestEventSubscriber> subscriberPtr =
        std::make_shared<AccountTestEventSubscriber>(subscribeInfo, listener);
    ASSERT_EQ(CommonEventManager::SubscribeCommonEvent(subscriberPtr), true);
    EXPECT_CALL(*listener, OnReceiveEvent(CommonEventSupport::COMMON_EVENT_USER_BACKGROUND)).Times(Exactly(0));
    EXPECT_CALL(*listener, OnReceiveEvent(CommonEventSupport::COMMON_EVENT_USER_FOREGROUND)).Times(Exactly(1));
#endif

    EXPECT_EQ(OsAccountManager::DeactivateOsAccount(commonOsAccountInfo.GetLocalId()), ERR_OK);
    sleep(1);
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(commonOsAccountInfo.GetLocalId()), ERR_OK);
    sleep(1);

    EXPECT_EQ(ERR_OK, OsAccountManager::UnsubscribeOsAccount(activingSubscriber));
    EXPECT_EQ(ERR_OK, OsAccountManager::UnsubscribeOsAccount(activedSubscriber));
    EXPECT_EQ(ERR_OK, OsAccountManager::UnsubscribeOsAccount(switchedSubscriber));
    EXPECT_EQ(ERR_OK, OsAccountManager::UnsubscribeOsAccount(switchingSubscriber));
#ifndef BUNDLE_ADAPTER_MOCK
    EXPECT_EQ(CommonEventManager::UnSubscribeCommonEvent(subscriberPtr), true);
#endif
}
#endif // SUPPORT_STOP_MAIN_OS_ACCOUNT

#ifdef SUPPORT_LOCK_OS_ACCOUNT
/**
 * @tc.name: OsAccountManagerModuleTest119
 * @tc.desc: test PublishOsAccountLockEvent with invalid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest119, TestSize.Level1)
{
    EXPECT_EQ(OsAccountManager::PublishOsAccountLockEvent(-1, true), ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
    EXPECT_EQ(OsAccountManager::PublishOsAccountLockEvent(50, true), ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR);
}

/**
 * @tc.name: OsAccountManagerModuleTest120
 * @tc.desc: test LockOsAccount with invalid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest120, TestSize.Level1)
{
    EXPECT_EQ(OsAccountManager::LockOsAccount(-1), ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
    EXPECT_EQ(OsAccountManager::LockOsAccount(50), ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR);
}

/**
 * @tc.name: OsAccountManagerModuleTest121
 * @tc.desc: test PublishOsAccountLockEvent with valid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest121, TestSize.Level1)
{
    EXPECT_EQ(OsAccountManager::PublishOsAccountLockEvent(100, false), ERR_OK);
}

/**
 * @tc.name: OsAccountManagerModuleTest122
 * @tc.desc: test LockOsAccount with valid data.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest122, TestSize.Level1)
{
    EXPECT_NE(OsAccountManager::LockOsAccount(100), ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}
#ifdef BUNDLE_ADAPTER_MOCK
/**
 * @tc.name: OsAccountManagerModuleTest123
 * @tc.desc: test subscribe common event of user locking and locked.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest123, TestSize.Level1)
{
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_LOCKING);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_LOCKED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    auto listener = std::make_shared<MockSubscriberListener>();
    EXPECT_CALL(*listener,
        OnReceiveEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_LOCKING)).Times(Exactly(1));
    EXPECT_CALL(*listener,
        OnReceiveEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_LOCKED)).Times(Exactly(1));
    std::shared_ptr<AccountTestEventSubscriber> subscriberPtr =
        std::make_shared<AccountTestEventSubscriber>(subscribeInfo, listener);
    ASSERT_EQ(EventFwk::CommonEventManager::SubscribeCommonEvent(subscriberPtr), true);
    EXPECT_EQ(OsAccountManager::PublishOsAccountLockEvent(100, true), ERR_OK);
    EXPECT_EQ(OsAccountManager::PublishOsAccountLockEvent(100, false), ERR_OK);
    testing::Mock::AllowLeak(listener.get());
}
#endif
#else
/**
 * @tc.name: OsAccountManagerModuleTest124
 * @tc.desc: test not support PublishOsAccountLockEvent and LockOsAccount.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, OsAccountManagerModuleTest124, TestSize.Level1)
{
    EXPECT_EQ(OsAccountManager::LockOsAccount(100), ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR);
    EXPECT_EQ(OsAccountManager::PublishOsAccountLockEvent(100, true),
        ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR);
}
#endif

/**
 * @tc.name: GetOsAccountType001
 * @tc.desc: Test GetOsAccountType.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, GetOsAccountType001, TestSize.Level1)
{
    OsAccountType type = OsAccountType::ADMIN;
    EXPECT_EQ(OsAccountManager::GetOsAccountType(commonOsAccountInfo.GetLocalId(), type), ERR_OK);
    EXPECT_EQ(type, OsAccountType::NORMAL);
}

/**
 * @tc.name: PrivateTypeTest001
 * @tc.desc: Test PRIVATE type os account.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, PrivateTypeTest001, TestSize.Level1)
{
    std::string privateTestName = "PrivateTestName001";
    std::string privateTestNameTwo = "PrivateTestName002";
    // test create private os account with normal account duplicate name
    OsAccountInfo osAccountInfoB;
    ASSERT_EQ(OsAccountManager::CreateOsAccount(privateTestName, OsAccountType::PRIVATE, osAccountInfoB), ERR_OK);
    OsAccountInfo osAccountInfoC;
    ASSERT_EQ(OsAccountManager::CreateOsAccount(privateTestNameTwo, OsAccountType::PRIVATE, osAccountInfoC),
        ERR_OSACCOUNT_SERVICE_CONTROL_MAX_CAN_CREATE_ERROR);

    // test get os account type by id
    OsAccountType type;
    EXPECT_EQ(OsAccountManager::GetOsAccountType(osAccountInfoB.GetLocalId(), type), ERR_OK);
    EXPECT_EQ(type, OsAccountType::PRIVATE);
    EXPECT_EQ(OsAccountManager::GetOsAccountType(commonOsAccountInfo.GetLocalId(), type), ERR_OK);
    EXPECT_EQ(type, OsAccountType::NORMAL);

    // test create normal os account with private account duplicate name
    OsAccountInfo osAccountInfoD;
    ASSERT_EQ(OsAccountManager::CreateOsAccount(privateTestName, OsAccountType::NORMAL, osAccountInfoD), ERR_OK);

    // test set name with private account duplicate name
    EXPECT_EQ(OsAccountManager::SetOsAccountName(osAccountInfoB.GetLocalId(), privateTestNameTwo), ERR_OK);
    EXPECT_EQ(OsAccountManager::SetOsAccountName(osAccountInfoD.GetLocalId(), privateTestNameTwo), ERR_OK);

    // test delete private os account
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(osAccountInfoB.GetLocalId()), ERR_OK);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(osAccountInfoD.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: IsOsAccountForeground001
 * @tc.desc: Test call IsOsAccountForeground(bool &isForeground) with singleton app.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, IsOsAccountForeground001, TestSize.Level1)
{
    bool isForeground = true;
    EXPECT_EQ(OsAccountManager::IsOsAccountForeground(isForeground), ERR_OK);
    // uid = 0, localId = 0, not in foreground
    EXPECT_EQ(isForeground, false);
}

/**
 * @tc.name: IsOsAccountForeground002
 * @tc.desc: Test call IsOsAccountForeground(bool &isForeground) with non singleton app.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, IsOsAccountForeground002, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    ASSERT_EQ(OsAccountManager::CreateOsAccount("IsOsAccountForeground002", OsAccountType::NORMAL, osAccountInfo),
              ERR_OK);

    bool isForeground = true;

    // test not in foreground before switch
    EXPECT_EQ(setuid(osAccountInfo.GetLocalId() * UID_TRANSFORM_DIVISOR), 0);
    EXPECT_EQ(OsAccountManager::IsOsAccountForeground(isForeground), ERR_OK);
    EXPECT_EQ(isForeground, false);

    // switch to foreground
    EXPECT_EQ(setuid(ROOT_UID), 0);
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(osAccountInfo.GetLocalId()), ERR_OK);

    // test in foreground after switch
    isForeground = false;
    EXPECT_EQ(setuid(osAccountInfo.GetLocalId() * UID_TRANSFORM_DIVISOR), 0);
    EXPECT_EQ(OsAccountManager::IsOsAccountForeground(isForeground), ERR_OK);
    EXPECT_EQ(isForeground, true);

    EXPECT_EQ(setuid(ROOT_UID), 0);
    EXPECT_EQ(OsAccountManager::RemoveOsAccount(osAccountInfo.GetLocalId()), ERR_OK);

    // test not found after remove account
    EXPECT_EQ(setuid(osAccountInfo.GetLocalId() * UID_TRANSFORM_DIVISOR), 0);
    EXPECT_EQ(OsAccountManager::IsOsAccountForeground(isForeground), ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
    EXPECT_EQ(setuid(ROOT_UID), 0);
}

/**
 * @tc.name: IsOsAccountForeground003
 * @tc.desc: Test call IsOsAccountForeground(int32_t localId, bool &isForeground) success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, IsOsAccountForeground003, TestSize.Level1)
{
    bool isForeground = true;

    // test not in foreground before switch
    EXPECT_EQ(OsAccountManager::IsOsAccountForeground(commonOsAccountInfo.GetLocalId(), isForeground), ERR_OK);
    EXPECT_EQ(isForeground, false);

    // switch to foreground
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(commonOsAccountInfo.GetLocalId()), ERR_OK);

    // test in foreground
    isForeground = false;
    EXPECT_EQ(OsAccountManager::IsOsAccountForeground(commonOsAccountInfo.GetLocalId(), isForeground), ERR_OK);
    EXPECT_EQ(isForeground, true);

    EXPECT_EQ(OsAccountManager::DeactivateOsAccount(commonOsAccountInfo.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: IsOsAccountForeground004
 * @tc.desc: Test call IsOsAccountForeground(int32_t localId, bool &isForeground) failed with invalid param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, IsOsAccountForeground004, TestSize.Level1)
{
    bool isForeground = true;

    // test localId < 0
    EXPECT_EQ(OsAccountManager::IsOsAccountForeground(-1, isForeground), ERR_ACCOUNT_COMMON_INVALID_PARAMETER);

    // test localId = 0
    EXPECT_EQ(OsAccountManager::IsOsAccountForeground(0, isForeground), ERR_OK);
    EXPECT_EQ(isForeground, false);

    // test localId = 2
    EXPECT_EQ(OsAccountManager::IsOsAccountForeground(2, isForeground), ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);

    // test localId not exist
    EXPECT_EQ(OsAccountManager::IsOsAccountForeground(1099, isForeground), ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: IsOsAccountForeground005
 * @tc.desc: Test call IsOsAccountForeground(const int32_t localId, const uint64_t displayId, bool &isForeground)
 * success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, IsOsAccountForeground005, TestSize.Level1)
{
    bool isForeground = true;

    // test not in foreground before switch
    OsAccountManager::ActivateOsAccount(100);
    EXPECT_EQ(OsAccountManager::IsOsAccountForeground(commonOsAccountInfo.GetLocalId(), Constants::DEFAULT_DISPALY_ID,
                                                      isForeground),
              ERR_OK);
    EXPECT_EQ(isForeground, false);

    // switch to foreground
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(commonOsAccountInfo.GetLocalId()), ERR_OK);

    // test in foreground
    isForeground = false;
    EXPECT_EQ(OsAccountManager::IsOsAccountForeground(commonOsAccountInfo.GetLocalId(), Constants::DEFAULT_DISPALY_ID,
                                                      isForeground),
              ERR_OK);
    EXPECT_EQ(isForeground, true);

    EXPECT_EQ(OsAccountManager::DeactivateOsAccount(commonOsAccountInfo.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: IsOsAccountForeground006
 * @tc.desc: Test call IsOsAccountForeground(const int32_t localId, const uint64_t displayId, bool &isForeground) failed
 * with invalid param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, IsOsAccountForeground006, TestSize.Level1)
{
    bool isForeground = true;

    // test localId < 0
    EXPECT_EQ(OsAccountManager::IsOsAccountForeground(-1, Constants::DEFAULT_DISPALY_ID, isForeground),
              ERR_ACCOUNT_COMMON_INVALID_PARAMETER);

    // test localId = 0
    EXPECT_EQ(OsAccountManager::IsOsAccountForeground(0, Constants::DEFAULT_DISPALY_ID, isForeground), ERR_OK);
    EXPECT_EQ(isForeground, false);

    // test localId = 2
    EXPECT_EQ(OsAccountManager::IsOsAccountForeground(2, Constants::DEFAULT_DISPALY_ID, isForeground),
              ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);

    // test localId not exist
    EXPECT_EQ(OsAccountManager::IsOsAccountForeground(1099, Constants::DEFAULT_DISPALY_ID, isForeground),
              ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);

    // test displayId not exist
    EXPECT_EQ(OsAccountManager::IsOsAccountForeground(MAIN_ACCOUNT_ID, 100000, isForeground),
              ERR_ACCOUNT_COMMON_DISPLAY_ID_NOT_EXIST_ERROR);
}

/**
 * @tc.name: GetForegroundOsAccountLocalId001
 * @tc.desc: Test GetForegroundOsAccountLocalId(int32_t &localId) in main displayId success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, GetForegroundOsAccountLocalId001, TestSize.Level1)
{
    int32_t localId = 0;

    // test in main account
    OsAccountManager::ActivateOsAccount(MAIN_ACCOUNT_ID);
    EXPECT_EQ(OsAccountManager::GetForegroundOsAccountLocalId(localId), ERR_OK);
    EXPECT_EQ(localId, MAIN_ACCOUNT_ID);

    // test in account GetForegroundOsAccountLocalId001
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(commonOsAccountInfo.GetLocalId()), ERR_OK);
    EXPECT_EQ(OsAccountManager::GetForegroundOsAccountLocalId(localId), ERR_OK);
    EXPECT_EQ(localId, commonOsAccountInfo.GetLocalId());

    // test in main account after switch
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(MAIN_ACCOUNT_ID), ERR_OK);
    EXPECT_EQ(OsAccountManager::GetForegroundOsAccountLocalId(localId), ERR_OK);
    EXPECT_EQ(localId, MAIN_ACCOUNT_ID);

    EXPECT_EQ(OsAccountManager::DeactivateOsAccount(commonOsAccountInfo.GetLocalId()), ERR_OK);
}

/**
 * @tc.name: GetForegroundOsAccountLocalId002
 * @tc.desc: Test GetForegroundOsAccountLocalId(const uint64_t displayId, int32_t &localId) success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, GetForegroundOsAccountLocalId002, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    ASSERT_EQ(
        OsAccountManager::CreateOsAccount("GetForegroundOsAccountLocalId002", OsAccountType::NORMAL, osAccountInfo),
        ERR_OK);

    int32_t localId = 0;

    // test in main account
    OsAccountManager::ActivateOsAccount(MAIN_ACCOUNT_ID);
    EXPECT_EQ(OsAccountManager::GetForegroundOsAccountLocalId(Constants::DEFAULT_DISPALY_ID, localId), ERR_OK);
    EXPECT_EQ(localId, MAIN_ACCOUNT_ID);

    // test in account GetForegroundOsAccountLocalId002
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(osAccountInfo.GetLocalId()), ERR_OK);
    EXPECT_EQ(OsAccountManager::GetForegroundOsAccountLocalId(Constants::DEFAULT_DISPALY_ID, localId), ERR_OK);
    EXPECT_EQ(localId, osAccountInfo.GetLocalId());

    ASSERT_EQ(OsAccountManager::RemoveOsAccount(osAccountInfo.GetLocalId()), ERR_OK);

    // test in main account
    EXPECT_EQ(OsAccountManager::GetForegroundOsAccountLocalId(Constants::DEFAULT_DISPALY_ID, localId), ERR_OK);
    EXPECT_EQ(localId, MAIN_ACCOUNT_ID);
}

/**
 * @tc.name: GetForegroundOsAccountLocalId006
 * @tc.desc: Test call GetForegroundOsAccountLocalId(const uint64_t displayId, int32_t &localId) failed with invalid
 * param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, GetForegroundOsAccountLocalId006, TestSize.Level1)
{
    int32_t localId = 0;

    // test displayId not exist
    EXPECT_EQ(OsAccountManager::GetForegroundOsAccountLocalId(100000, localId),
              ERR_ACCOUNT_COMMON_DISPLAY_ID_NOT_EXIST_ERROR);
}

/**
 * @tc.name: GetForegroundOsAccounts001
 * @tc.desc: Test GetForegroundOsAccounts(std::vector<ForegroundOsAccount> &accounts) success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, GetForegroundOsAccounts001, TestSize.Level1)
{
    // test account not in foregroud list after create
    std::vector<ForegroundOsAccount> accounts;
    EXPECT_EQ(OsAccountManager::GetForegroundOsAccounts(accounts), ERR_OK);
    auto it = std::find_if(accounts.begin(), accounts.end(), [&](const ForegroundOsAccount &foregroundAccounts) {
        return foregroundAccounts.localId == commonOsAccountInfo.GetLocalId();
    });
    EXPECT_TRUE(it == accounts.end());

    // test account in foregroud list after active
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(commonOsAccountInfo.GetLocalId()), ERR_OK);
    EXPECT_EQ(OsAccountManager::GetForegroundOsAccounts(accounts), ERR_OK);
    it = std::find_if(accounts.begin(), accounts.end(), [&](const ForegroundOsAccount &foregroundAccounts) {
        return foregroundAccounts.localId == commonOsAccountInfo.GetLocalId();
    });
    EXPECT_TRUE(it != accounts.end());
    EXPECT_EQ(it->displayId, Constants::DEFAULT_DISPALY_ID);

    // test account in foregroud list after switch
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(MAIN_ACCOUNT_ID), ERR_OK);
    EXPECT_EQ(OsAccountManager::GetForegroundOsAccounts(accounts), ERR_OK);
    it = std::find_if(accounts.begin(), accounts.end(), [&](const ForegroundOsAccount &foregroundAccounts) {
        return foregroundAccounts.localId == MAIN_ACCOUNT_ID;
    });
    EXPECT_TRUE(it != accounts.end());
    EXPECT_EQ(it->displayId, Constants::DEFAULT_DISPALY_ID);

    // test account not in foregroud list after deactive
    EXPECT_EQ(OsAccountManager::DeactivateOsAccount(commonOsAccountInfo.GetLocalId()), ERR_OK);
    EXPECT_EQ(OsAccountManager::GetForegroundOsAccounts(accounts), ERR_OK);
    it = std::find_if(accounts.begin(), accounts.end(), [&](const ForegroundOsAccount &foregroundAccounts) {
        return foregroundAccounts.localId == commonOsAccountInfo.GetLocalId();
    });
    EXPECT_TRUE(it == accounts.end());
}


/**
 * @tc.name: SetOsAccountToBeRemoved001
 * @tc.desc: Test SetOsAccountToBeRemoved.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, SetOsAccountToBeRemoved001, TestSize.Level1)
{
    EXPECT_EQ(commonOsAccountInfo.GetToBeRemoved(), false);
    EXPECT_EQ(OsAccountManager::SetOsAccountToBeRemoved(commonOsAccountInfo.GetLocalId() + 1, true),
        ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
    EXPECT_EQ(OsAccountManager::SetOsAccountToBeRemoved(commonOsAccountInfo.GetLocalId(), true), ERR_OK);
    EXPECT_EQ(OsAccountManager::QueryOsAccountById(commonOsAccountInfo.GetLocalId(), commonOsAccountInfo), ERR_OK);
    EXPECT_EQ(commonOsAccountInfo.GetToBeRemoved(), true);
    EXPECT_EQ(OsAccountManager::SetOsAccountToBeRemoved(commonOsAccountInfo.GetLocalId(), false), ERR_OK);
}

#ifdef ENABLE_MULTIPLE_ACTIVE_ACCOUNTS
/**
 * @tc.name: GetBackgroundOsAccountLocalIds001
 * @tc.desc: Test GetBackgroundOsAccountLocalIds(std::vector<int32_t> &localIds) success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, GetBackgroundOsAccountLocalIds001, TestSize.Level1)
{
    OsAccountInfo account;
    ASSERT_EQ(OsAccountManager::CreateOsAccount("GetBackgroundOsAccountLocalIds001", OsAccountType::NORMAL, account),
              ERR_OK);

    // test account not in backgroud list after create
    std::vector<int32_t> localIds;
    EXPECT_EQ(OsAccountManager::GetBackgroundOsAccountLocalIds(localIds), ERR_OK);
    auto it = std::find_if(localIds.begin(), localIds.end(),
                           [&](int32_t localId) { return localId == account.GetLocalId(); });
    EXPECT_TRUE(it == localIds.end());

    // test account in backgroud list after switch
    OsAccountManager::ActivateOsAccount(MAIN_ACCOUNT_ID);
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(account.GetLocalId()), ERR_OK);
    EXPECT_EQ(OsAccountManager::GetBackgroundOsAccountLocalIds(localIds), ERR_OK);
    it = std::find_if(localIds.begin(), localIds.end(), [&](int32_t localId) { return localId == MAIN_ACCOUNT_ID; });
    EXPECT_TRUE(it != localIds.end());

    // test account in backgroud list after switch
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(MAIN_ACCOUNT_ID), ERR_OK);
    EXPECT_EQ(OsAccountManager::GetBackgroundOsAccountLocalIds(localIds), ERR_OK);
    it = std::find_if(localIds.begin(), localIds.end(),
                      [&](int32_t localId) { return localId == account.GetLocalId(); });
    EXPECT_TRUE(it != localIds.end());

    ASSERT_EQ(OsAccountManager::RemoveOsAccount(account.GetLocalId()), ERR_OK);

    // test account not in backgroud list after remove
    EXPECT_EQ(OsAccountManager::GetBackgroundOsAccountLocalIds(localIds), ERR_OK);
    it = std::find_if(localIds.begin(), localIds.end(),
                      [&](int32_t localId) { return localId == account.GetLocalId(); });
    EXPECT_TRUE(it == localIds.end());
}
#endif
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

/**
 * @tc.name: DeactivateAllOsAccountsModuleTest001
 * @tc.desc: Test DeactivateAllOsAccounts success.
 * @tc.type: FUNC
 * @tc.require:
 */
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(OsAccountManagerModuleTest, DeactivateAllOsAccountsModuleTest001, TestSize.Level1)
{
    ASSERT_TRUE(commonOsAccountInfo.GetLocalId() > Constants::START_USER_ID);
    EXPECT_EQ(OsAccountManager::ActivateOsAccount(commonOsAccountInfo.GetLocalId()), ERR_OK);
    EXPECT_EQ(OsAccountManager::DeactivateAllOsAccounts(), ERR_OK);

    std::vector<int32_t> ids;
    EXPECT_EQ(OsAccountManager::QueryActiveOsAccountIds(ids), ERR_OK);
    EXPECT_EQ(ids.empty(), true);

    EXPECT_EQ(OsAccountManager::ActivateOsAccount(MAIN_ACCOUNT_ID), ERR_OK);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS
/**
 * @tc.name: IsOsAccountDeactivatingModuleTest001
 * @tc.desc: Test IsOsAccountDeactivating success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, IsOsAccountDeactivatingModuleTest001, TestSize.Level1)
{
    bool isDeactivating;
    EXPECT_EQ(OsAccountManager::IsOsAccountDeactivating(MAIN_ACCOUNT_ID, isDeactivating), ERR_OK);
}

/**
 * @tc.name: GetOsAccountNameById001
 * @tc.desc: Test GetOsAccountNameById without permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, GetOsAccountNameById001, TestSize.Level1)
{
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission({}, tokenID));
    setuid(MAIN_ACCOUNT_ID * UID_TRANSFORM_DIVISOR); // test main uid
    std::string name;
    EXPECT_EQ(OsAccountManager::GetOsAccountNameById(MAIN_ACCOUNT_ID, name), ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    setuid(ROOT_UID);
    ASSERT_TRUE(RecoveryPermission(tokenID));
}

/**
 * @tc.name: GetOsAccountNameById002
 * @tc.desc: Test GetOsAccountNameById with permission INTERACT_ACROSS_LOCAL_ACCOUNTS.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, GetOsAccountNameById002, TestSize.Level1)
{
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission({"ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS"}, tokenID));
    setuid(MAIN_ACCOUNT_ID * UID_TRANSFORM_DIVISOR); // test main uid
    std::string name;
    EXPECT_EQ(OsAccountManager::GetOsAccountNameById(MAIN_ACCOUNT_ID, name), ERR_OK);
    setuid(ROOT_UID);
    ASSERT_TRUE(RecoveryPermission(tokenID));
}

/**
 * @tc.name: GetOsAccountNameById003
 * @tc.desc: Test GetOsAccountNameById with permission MANAGE_LOCAL_ACCOUNTS.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, GetOsAccountNameById003, TestSize.Level1)
{
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission({"ohos.permission.MANAGE_LOCAL_ACCOUNTS"}, tokenID));
    setuid(MAIN_ACCOUNT_ID * UID_TRANSFORM_DIVISOR); // test main uid
    std::string name;
    EXPECT_EQ(OsAccountManager::GetOsAccountNameById(MAIN_ACCOUNT_ID, name), ERR_OK);
    setuid(ROOT_UID);
    ASSERT_TRUE(RecoveryPermission(tokenID));
}

/**
 * @tc.name: GetOsAccountNameById004
 * @tc.desc: Test GetOsAccountNameById with permission MANAGE_LOCAL_ACCOUNTS and INTERACT_ACROSS_LOCAL_ACCOUNTS.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, GetOsAccountNameById004, TestSize.Level1)
{
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission({"ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS"}, tokenID));
    ASSERT_TRUE(AllocPermission({"ohos.permission.MANAGE_LOCAL_ACCOUNTS"}, tokenID));
    setuid(MAIN_ACCOUNT_ID * UID_TRANSFORM_DIVISOR); // test main uid
    std::string name;
    EXPECT_EQ(OsAccountManager::GetOsAccountNameById(MAIN_ACCOUNT_ID, name), ERR_OK);
    setuid(ROOT_UID);
    ASSERT_TRUE(RecoveryPermission(tokenID));
}

/**
 * @tc.name: GetOsAccountNameById005
 * @tc.desc: Test GetOsAccountNameById with caller is not system item.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, GetOsAccountNameById005, TestSize.Level1)
{
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission({"ohos.permission.MANAGE_LOCAL_ACCOUNTS"}, tokenID, false));
    setuid(MAIN_ACCOUNT_ID * UID_TRANSFORM_DIVISOR); // test main uid
    std::string name;
    EXPECT_EQ(OsAccountManager::GetOsAccountNameById(MAIN_ACCOUNT_ID, name), ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);
    setuid(ROOT_UID);
    ASSERT_TRUE(RecoveryPermission(tokenID));
}

#ifndef BUNDLE_ADAPTER_MOCK
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
/**
 * @tc.name: QueryDistributedVirtualDeviceId001
 * @tc.desc: Test QueryDistributedVirtualDeviceId.
 * @tc.type: FUNC
 * @tc.require: issueI4JBFF
 */
HWTEST_F(OsAccountManagerModuleTest, QueryDistributedVirtualDeviceId001, TestSize.Level1)
{
    int32_t localId = commonOsAccountInfo.GetLocalId();
    ASSERT_EQ(OsAccountManager::ActivateOsAccount(localId), ERR_OK);
    std::string dvid1 = "";
    std::string bundleName1 = "bundleName1";
    ErrCode ret = OsAccountManager::QueryDistributedVirtualDeviceId(bundleName1, localId, dvid1);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(dvid1, "");

    OhosAccountInfo ohosInfo;
    ohosInfo.SetRawUid("65689555212565665");
    ohosInfo.uid_ = "656895552125sdsdsdaaqw65665";
    ohosInfo.name_ = "name";
    ret = OhosAccountKits::GetInstance().SetOsAccountDistributedInfo(localId, ohosInfo, OHOS_ACCOUNT_EVENT_LOGIN);
    EXPECT_EQ(ret, ERR_OK);

    EXPECT_EQ(OsAccountManager::QueryDistributedVirtualDeviceId(bundleName1, localId, dvid1), ERR_OK);
    EXPECT_EQ(dvid1, "6275B655D729154E72F39914C257EB3CD6024D930F88E698DB4414DCCF1847FD");

    std::string dvid2 = "";
    std::string bundleName2 = "bundleName2";
    EXPECT_EQ(OsAccountManager::QueryDistributedVirtualDeviceId(bundleName2, localId, dvid2), ERR_OK);
    EXPECT_NE(dvid2, "");
    EXPECT_NE(dvid2, dvid1);

    EXPECT_EQ(OhosAccountKits::GetInstance().UpdateOhosAccountInfo("name", ohosInfo.uid_, OHOS_ACCOUNT_EVENT_LOGOUT),
        ERR_OK);
    dvid1 = "";
    EXPECT_EQ(OsAccountManager::QueryDistributedVirtualDeviceId(bundleName1, localId, dvid1), ERR_OK);
    EXPECT_EQ(dvid1, "");

    OhosAccountInfo ohosInfo2;
    ohosInfo2.SetRawUid("65689555212568888");
    ohosInfo2.uid_ = "656895552125fgfghhgjjhkhw68888";
    ohosInfo2.name_ = "name2";
    ret = OhosAccountKits::GetInstance().SetOsAccountDistributedInfo(localId, ohosInfo2, OHOS_ACCOUNT_EVENT_LOGIN);
    EXPECT_EQ(ret, ERR_OK);

    std::string dvid3 = "";
    ret = OsAccountManager::QueryDistributedVirtualDeviceId(bundleName2, localId, dvid3);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(dvid3, dvid2);

    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission({}, tokenID));
    setuid(commonOsAccountInfo.GetLocalId() * UID_TRANSFORM_DIVISOR);
    ret = OsAccountManager::QueryDistributedVirtualDeviceId(bundleName2, localId, dvid3);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    setuid(ROOT_UID);
    ASSERT_TRUE(RecoveryPermission(tokenID));
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS
#endif

#ifdef BUNDLE_ADAPTER_MOCK
/**
 * @tc.name: GetCreatedOsAccountNumFromDatabaseMockTest001
 * @tc.desc: Test GetCreatedOsAccountNumFromDatabase.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, GetCreatedOsAccountNumFromDatabaseMockTest001, TestSize.Level1)
{
    int createdOsAccountNum;
    EXPECT_NE(OsAccountManager::GetCreatedOsAccountNumFromDatabase("", createdOsAccountNum), ERR_OK);
}

/**
 * @tc.name: GetSerialNumberFromDatabaseMockTest001
 * @tc.desc: Test GetSerialNumberFromDatabase.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, GetSerialNumberFromDatabaseMockTest001, TestSize.Level1)
{
    int64_t serialNumber;
    EXPECT_NE(ERR_OK, OsAccountManager::GetSerialNumberFromDatabase("", serialNumber));
}

/**
 * @tc.name: GetMaxAllowCreateIdFromDatabaseMockTest001
 * @tc.desc: Test GetMaxAllowCreateIdFromDatabase.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, GetMaxAllowCreateIdFromDatabaseMockTest001, TestSize.Level1)
{
    int id;
    EXPECT_NE(ERR_OK, OsAccountManager::GetMaxAllowCreateIdFromDatabase("", id));
}

/**
 * @tc.name: GetOsAccountFromDatabaseMockTest001
 * @tc.desc: Test GetOsAccountFromDatabase.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, GetOsAccountFromDatabaseMockTest001, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    EXPECT_NE(ERR_OK, OsAccountManager::GetOsAccountFromDatabase("", MAIN_ACCOUNT_ID, osAccountInfo));
}

/**
 * @tc.name: GetOsAccountListFromDatabaseMockTest001
 * @tc.desc: Test GetOsAccountListFromDatabase.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerModuleTest, GetOsAccountListFromDatabaseMockTest001, TestSize.Level1)
{
    std::vector<OsAccountInfo> osAccountList;
    EXPECT_NE(ERR_OK, OsAccountManager::GetOsAccountListFromDatabase("", osAccountList));
}
#endif

/**
 * @tc.name: QueryDistributedVirtualDeviceId002
 * @tc.desc: Test QueryDistributedVirtualDeviceId.
 * @tc.type: FUNC
 * @tc.require: issueI4JBFF
 */
HWTEST_F(OsAccountManagerModuleTest, QueryDistributedVirtualDeviceId002, TestSize.Level1)
{
    std::string dvid = "";
    EXPECT_EQ(OsAccountManager::QueryDistributedVirtualDeviceId("", 100, dvid), ERR_OK);
}

/**
 * @tc.name: SubscribeConstraints001
 * @tc.desc: Test SubscribeConstraints001.
 * @tc.type: FUNC
 * @tc.require: issueI4JBFF
 */
HWTEST_F(OsAccountManagerModuleTest, SubscribeConstraints001, TestSize.Level1)
{
    EXPECT_EQ(OsAccountManager::SubscribeOsAccountConstraints(nullptr), ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    EXPECT_EQ(OsAccountManager::UnsubscribeOsAccountConstraints(nullptr), ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}