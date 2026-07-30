/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "account_error_no.h"
#include "account_info.h"
#include "ohos_account_constants.h"

#define private public
#include "ohos_account_manager.h"
#include "ohos_account_data_deal.h"
#undef private

namespace OHOS {
namespace AccountSA {
using namespace testing::ext;

namespace {
const std::int32_t TEST_USER_ID = 100;
const std::string TEST_NAME = "TestName";
const std::string TEST_UID = "TestUid";
const std::string TEST_SHA_UID = "6C28D0B5A98C3F1AE9FFF3FFE9D2A46B93792EFAA07A53C18E2B36A3C81B48CB";
std::string g_eventLogin = OHOS_ACCOUNT_EVENT_LOGIN;
std::string g_eventLogout = OHOS_ACCOUNT_EVENT_LOGOUT;
std::string g_eventLogoff = OHOS_ACCOUNT_EVENT_LOGOFF;
std::string g_eventTokenInvalid = OHOS_ACCOUNT_EVENT_TOKEN_INVALID;

static bool g_hasLogin = false;
static bool g_accountInfoFromJsonFail = true;
static bool g_accountInfoToJsonFail = true;
}

class OhosAccountDfxCoverageTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
};

void OhosAccountDfxCoverageTest::SetUp()
{
    g_hasLogin = false;
    g_accountInfoFromJsonFail = true;
    g_accountInfoToJsonFail = true;
}

void OhosAccountDfxCoverageTest::TearDown()
{
    g_hasLogin = false;
    g_accountInfoFromJsonFail = true;
    g_accountInfoToJsonFail = true;
}

#ifndef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE

#ifdef ENABLE_FILE_WATCHER
OhosAccountDataDeal::OhosAccountDataDeal(const std::string &configFileDir)
    : configFileDir_(configFileDir),
    accountFileWatcherMgr_(AccountFileWatcherMgr::GetInstance())
{
    accountFileOperator_ = nullptr;
    initOk_ = false;
    checkCallbackFunc_ = nullptr;
}
#else
OhosAccountDataDeal::OhosAccountDataDeal(const std::string &configFileDir)
    : configFileDir_(configFileDir)
{
    accountFileOperator_ = nullptr;
    initOk_ = false;
}
#endif // ENABLE_FILE_WATCHER

ErrCode OhosAccountDataDeal::Init(int32_t userId)
{
    return ERR_OK;
}

ErrCode OhosAccountDataDeal::AccountInfoFromJson(AccountInfo &accountInfo, int32_t userId)
{
    if (g_accountInfoFromJsonFail) {
        return ERR_ACCOUNT_DATADEAL_JSON_FILE_CORRUPTION;
    }
    if (!g_hasLogin) {
        accountInfo.ohosAccountInfo_.name_ = DEFAULT_OHOS_ACCOUNT_NAME;
        accountInfo.ohosAccountInfo_.uid_ = DEFAULT_OHOS_ACCOUNT_UID;
        accountInfo.ohosAccountInfo_.status_ = ACCOUNT_STATE_UNBOUND;
    } else {
        accountInfo.ohosAccountInfo_.name_ = TEST_NAME;
        accountInfo.ohosAccountInfo_.uid_ = TEST_SHA_UID;
        accountInfo.ohosAccountInfo_.status_ = ACCOUNT_STATE_LOGIN;
    }

    accountInfo.userId_ = TEST_USER_ID;
    return ERR_OK;
}

ErrCode OhosAccountDataDeal::AccountInfoToJson(const AccountInfo &accountInfo)
{
    if (g_accountInfoToJsonFail) {
        return ERR_ACCOUNT_COMMON_FILE_OPEN_FAILED;
    }
    return ERR_OK;
}

/**
 * @tc.name: OhosAccountDfxCoverageTest001
 * @tc.desc: Test LoginOhosAccount with AccountInfoToJson failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountDfxCoverageTest, OhosAccountDfxCoverageTest001, TestSize.Level3)
{
    g_accountInfoFromJsonFail = false;
    g_accountInfoToJsonFail = true;

    OhosAccountManager& manager = OhosAccountManager::GetInstance();
    manager.dataDealer_ = std::make_unique<OhosAccountDataDeal>("");

    OhosAccountInfo ohosAccountInfo;
    ohosAccountInfo.name_ = TEST_NAME;
    ohosAccountInfo.uid_ = TEST_UID;

    ErrCode result = manager.LoginOhosAccount(TEST_USER_ID, ohosAccountInfo, g_eventLogin);
    EXPECT_EQ(result, ERR_ACCOUNT_ZIDL_ACCOUNT_SERVICE_ERROR);
}

/**
 * @tc.name: OhosAccountDfxCoverageTest002
 * @tc.desc: Test LogoutOhosAccount with AccountInfoFromJson failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountDfxCoverageTest, OhosAccountDfxCoverageTest002, TestSize.Level3)
{
    g_accountInfoFromJsonFail = true;

    OhosAccountManager& manager = OhosAccountManager::GetInstance();
    manager.dataDealer_ = std::make_unique<OhosAccountDataDeal>("");

    OhosAccountInfo ohosAccountInfo;
    ohosAccountInfo.name_ = TEST_NAME;
    ohosAccountInfo.uid_ = TEST_UID;

    ErrCode result = manager.LogoutOhosAccount(TEST_USER_ID, ohosAccountInfo, g_eventLogout);
    EXPECT_EQ(result, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: OhosAccountDfxCoverageTest003
 * @tc.desc: Test LogoutOhosAccount with logged in account and AccountInfoToJson failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountDfxCoverageTest, OhosAccountDfxCoverageTest003, TestSize.Level3)
{
    g_accountInfoFromJsonFail = false;
    g_accountInfoToJsonFail = true;
    g_hasLogin = true;
    OhosAccountManager& manager = OhosAccountManager::GetInstance();
    manager.dataDealer_ = std::make_unique<OhosAccountDataDeal>("");

    OhosAccountInfo ohosAccountInfo;
    ohosAccountInfo.name_ = TEST_NAME;
    ohosAccountInfo.uid_ = TEST_UID;

    ErrCode result = manager.LogoutOhosAccount(TEST_USER_ID, ohosAccountInfo, g_eventLogout);
    EXPECT_EQ(result, ERR_ACCOUNT_ZIDL_ACCOUNT_SERVICE_ERROR);
}

/**
 * @tc.name: OhosAccountDfxCoverageTest004
 * @tc.desc: Test LogoffOhosAccount with logged in account and AccountInfoToJson failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountDfxCoverageTest, OhosAccountDfxCoverageTest004, TestSize.Level3)
{
    g_accountInfoFromJsonFail = false;
    g_accountInfoToJsonFail = true;
    g_hasLogin = true;
    OhosAccountManager& manager = OhosAccountManager::GetInstance();
    manager.dataDealer_ = std::make_unique<OhosAccountDataDeal>("");

    OhosAccountInfo ohosAccountInfo;
    ohosAccountInfo.name_ = TEST_NAME;
    ohosAccountInfo.uid_ = TEST_UID;

    ErrCode result = manager.LogoffOhosAccount(TEST_USER_ID, ohosAccountInfo, g_eventLogoff);
    EXPECT_EQ(result, ERR_ACCOUNT_ZIDL_ACCOUNT_SERVICE_ERROR);
}

/**
 * @tc.name: OhosAccountDfxCoverageTest005
 * @tc.desc: Test HandleOhosAccountTokenInvalidEvent with logged in account and AccountInfoToJson failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountDfxCoverageTest, OhosAccountDfxCoverageTest005, TestSize.Level3)
{
    g_accountInfoFromJsonFail = false;
    g_accountInfoToJsonFail = true;
    g_hasLogin = true;
    OhosAccountManager& manager = OhosAccountManager::GetInstance();
    manager.dataDealer_ = std::make_unique<OhosAccountDataDeal>("");

    OhosAccountInfo ohosAccountInfo;
    ohosAccountInfo.name_ = TEST_NAME;
    ohosAccountInfo.uid_ = TEST_UID;

    ErrCode result = manager.HandleOhosAccountTokenInvalidEvent(TEST_USER_ID, ohosAccountInfo, g_eventTokenInvalid);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: OhosAccountDfxCoverageTest006
 * @tc.desc: Test LoginOhosAccount with AccountInfoToJson success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountDfxCoverageTest, OhosAccountDfxCoverageTest006, TestSize.Level3)
{
    g_accountInfoFromJsonFail = false;
    g_accountInfoToJsonFail = false;
    g_hasLogin = false;

    OhosAccountManager& manager = OhosAccountManager::GetInstance();
    manager.dataDealer_ = std::make_unique<OhosAccountDataDeal>("");

    OhosAccountInfo ohosAccountInfo;
    ohosAccountInfo.name_ = TEST_NAME;
    ohosAccountInfo.uid_ = TEST_UID;

    ErrCode result = manager.LoginOhosAccount(TEST_USER_ID, ohosAccountInfo, g_eventLogin);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: OhosAccountDfxCoverageTest007
 * @tc.desc: Test LogoutOhosAccount with AccountInfoToJson success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountDfxCoverageTest, OhosAccountDfxCoverageTest007, TestSize.Level3)
{
    g_accountInfoFromJsonFail = false;
    g_accountInfoToJsonFail = false;
    g_hasLogin = true;

    OhosAccountManager& manager = OhosAccountManager::GetInstance();
    manager.dataDealer_ = std::make_unique<OhosAccountDataDeal>("");

    OhosAccountInfo ohosAccountInfo;
    ohosAccountInfo.name_ = TEST_NAME;
    ohosAccountInfo.uid_ = TEST_UID;

    ErrCode result = manager.LogoutOhosAccount(TEST_USER_ID, ohosAccountInfo, g_eventLogout);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: OhosAccountDfxCoverageTest008
 * @tc.desc: Test LogoffOhosAccount with AccountInfoToJson success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountDfxCoverageTest, OhosAccountDfxCoverageTest008, TestSize.Level3)
{
    g_accountInfoFromJsonFail = false;
    g_accountInfoToJsonFail = false;
    g_hasLogin = true;

    OhosAccountManager& manager = OhosAccountManager::GetInstance();
    manager.dataDealer_ = std::make_unique<OhosAccountDataDeal>("");

    OhosAccountInfo ohosAccountInfo;
    ohosAccountInfo.name_ = TEST_NAME;
    ohosAccountInfo.uid_ = TEST_UID;

    ErrCode result = manager.LogoffOhosAccount(TEST_USER_ID, ohosAccountInfo, g_eventLogoff);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: OhosAccountDfxCoverageTest009
 * @tc.desc: Test HandleOhosAccountTokenInvalidEvent with AccountInfoToJson success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OhosAccountDfxCoverageTest, OhosAccountDfxCoverageTest009, TestSize.Level3)
{
    g_accountInfoFromJsonFail = false;
    g_accountInfoToJsonFail = false;
    g_hasLogin = true;

    OhosAccountManager& manager = OhosAccountManager::GetInstance();
    manager.dataDealer_ = std::make_unique<OhosAccountDataDeal>("");

    OhosAccountInfo ohosAccountInfo;
    ohosAccountInfo.name_ = TEST_NAME;
    ohosAccountInfo.uid_ = TEST_UID;

    ErrCode result = manager.HandleOhosAccountTokenInvalidEvent(TEST_USER_ID, ohosAccountInfo, g_eventTokenInvalid);
    EXPECT_EQ(result, ERR_OK);
}

#endif // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE

} // namespace AccountSA
} // namespace OHOS