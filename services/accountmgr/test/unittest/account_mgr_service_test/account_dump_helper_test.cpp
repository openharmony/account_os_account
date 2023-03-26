/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#define private public
#include "account_dump_helper.h"
#undef private
#include "account_error_no.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "account_event_provider.h"
#include "iinner_os_account_manager.h"
#include "ohos_account_kits.h"
#include "ohos_account_manager.h"
#include "os_account.h"
#include "os_account_manager_service.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string TEST_ACCOUNT_NAME = "TestAccountName";
const std::string TEST_ACCOUNT_UID = "123456789";
}

class AccountDumpHelperTest : public testing::Test {
public:
    AccountDumpHelperTest();
    ~AccountDumpHelperTest() {}

    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<OhosAccountManager> ohosAccount_ {};
    OsAccountManagerService* osAccount_ {};
    std::unique_ptr<AccountDumpHelper> accountDumpHelper_ {};
};

AccountDumpHelperTest::AccountDumpHelperTest() {}

void AccountDumpHelperTest::SetUpTestCase()
{}

void AccountDumpHelperTest::TearDownTestCase()
{
    std::vector<OsAccountInfo> osAccountInfos;
    OsAccount::GetInstance().QueryAllCreatedOsAccounts(osAccountInfos);
    for (const auto &info : osAccountInfos) {
        OsAccount::GetInstance().RemoveOsAccount(info.GetLocalId());
    }
}

void AccountDumpHelperTest::SetUp()
{
    ohosAccount_ = std::make_shared<OhosAccountManager>();
    osAccount_ = new (std::nothrow) OsAccountManagerService();
    if (ohosAccount_ == nullptr || !ohosAccount_->OnInitialize()) {
        std::cout << "AccountDumpHelperTest, error! ohos account manager init failed!" << std::endl;
    }
    if (osAccount_ == nullptr) {
        std::cout << "AccountDumpHelperTest, error! osAccount_ is nullptr!" << std::endl;
    }
    accountDumpHelper_ = std::make_unique<AccountDumpHelper>(ohosAccount_, osAccount_);
    if (accountDumpHelper_ == nullptr) {
        std::cout << "AccountDumpHelperTest, error! accountDumpHelper_ is nullptr!" << std::endl;
    }
}

void AccountDumpHelperTest::TearDown()
{
    if (osAccount_ != nullptr) {
        delete osAccount_;
        osAccount_ = nullptr;
    }
}

/**
 * @tc.name: AccountDumpNoParameterTest001
 * @tc.desc: Test account info with no parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountDumpHelperTest, AccountDumpNoParameterTest001, TestSize.Level0)
{
    /**
     * @tc.steps: step1. Input no parameter
     */
    std::string out;
    vector<std::string> cmd;
    if (accountDumpHelper_ == nullptr) {
        std::cout << "AccountDumpNoParameterTest001, accountDumpHelper_ is nullptr!" << std::endl;
        return;
    }

    accountDumpHelper_->Dump(cmd, out);
    auto pos = out.find("Account Manager service, enter '-h' for usage", 0);
    EXPECT_NE(std::string::npos, pos);
}

/**
 * @tc.name: AccountDumpParameterTest001
 * @tc.desc: Test account info display
 * @tc.type: FUNC
 * @tc.require: SR000CUF6J
 */
HWTEST_F(AccountDumpHelperTest, AccountDumpParameterTest001, TestSize.Level0)
{
    OsAccountInfo osAccountInfo;
    // create an os account
    EXPECT_EQ(ERR_OK, OsAccount::GetInstance().CreateOsAccount("test", OsAccountType::NORMAL, osAccountInfo));

    OhosAccountInfo accountInfo;
    accountInfo.name_ = TEST_ACCOUNT_NAME;
    accountInfo.status_ = ACCOUNT_STATE_LOGIN;
    accountInfo.uid_ = TEST_ACCOUNT_UID;
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().SetOhosAccountInfo(accountInfo, "Ohos.account.event.LOGIN"));

    /**
     * @tc.steps: step1. Input one parameter
     */
    std::string out;
    vector<std::string> cmd = {"-ohos_account_infos"};
    if (accountDumpHelper_ == nullptr) {
        std::cout << "AccountDumpParameterTest001, accountDumpHelper_ is nullptr!" << std::endl;
        return;
    }

    accountDumpHelper_->Dump(cmd, out);
    auto pos = out.find("OhosAccount name", 0);
    EXPECT_NE(std::string::npos, pos);
    pos = out.find("OhosAccount uid", 0);
    EXPECT_NE(std::string::npos, pos);
    pos = out.find("OhosAccount status", 0);
    EXPECT_NE(std::string::npos, pos);
    pos = out.find("OhosAccount bind time", 0);
    EXPECT_NE(std::string::npos, pos);
    pos = out.find("Bind local user id", 0);
    EXPECT_NE(std::string::npos, pos);
}

/**
 * @tc.name: AccountDumpParameterTest002
 * @tc.desc: Test account info display
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountDumpHelperTest, AccountDumpParameterTest002, TestSize.Level0)
{
    /**
     * @tc.steps: step1. Input one parameter
     */
    std::string out;
    vector<std::string> cmd = {"-os_account_infos"};
    ASSERT_NE(accountDumpHelper_, nullptr);
    accountDumpHelper_->Dump(cmd, out);
    auto pos = out.find("ID:", 0);
    EXPECT_NE(std::string::npos, pos);
}

/**
 * @tc.name: AccountDumpParameterTest003
 * @tc.desc: Test account info display
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountDumpHelperTest, AccountDumpParameterTest003, TestSize.Level0)
{
    /**
     * @tc.steps: step1. Input one parameter
     */
    std::string out;
    vector<std::string> cmd = {"-time_info_dump"};
    ASSERT_NE(accountDumpHelper_, nullptr);
    accountDumpHelper_->Dump(cmd, out);
    auto pos = out.find("ServiceInstanceCreateTime", 0);
    EXPECT_NE(std::string::npos, pos);
}

/**
 * @tc.name: AccountDumpParameterTest004
 * @tc.desc: Test account info display
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountDumpHelperTest, AccountDumpParameterTest004, TestSize.Level0)
{
    /**
     * @tc.steps: step1. Input one parameter
     */
    std::string out;
    vector<std::string> cmd = {"-h"};
    ASSERT_NE(accountDumpHelper_, nullptr);
    accountDumpHelper_->Dump(cmd, out);
    auto pos = out.find("Usage:dump", 0);
    EXPECT_NE(std::string::npos, pos);
}

/**
 * @tc.name: AccountDumpParameterTest005
 * @tc.desc: Test account info display
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountDumpHelperTest, AccountDumpParameterTest005, TestSize.Level0)
{
    accountDumpHelper_ = nullptr;
    accountDumpHelper_ = std::make_unique<AccountDumpHelper>(nullptr, osAccount_);
    ASSERT_NE(accountDumpHelper_, nullptr);
    std::string out;
    vector<std::string> cmd = {"-ohos_account_infos"};
    accountDumpHelper_->Dump(cmd, out);
    auto pos = out.find("System error", 0);
    EXPECT_NE(std::string::npos, pos);
}

/**
 * @tc.name: AccountDumpParameterTest006
 * @tc.desc: Test account info display
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountDumpHelperTest, AccountDumpParameterTest006, TestSize.Level0)
{
    ASSERT_NE(accountDumpHelper_, nullptr);
    accountDumpHelper_->innerMgrService_ = nullptr;
    std::string out;
    vector<std::string> cmd = {"-ohos_account_infos"};
    accountDumpHelper_->Dump(cmd, out);
    auto pos = out.find("System error", 0);
    EXPECT_NE(std::string::npos, pos);
}

/**
 * @tc.name: AccountDumpParameterTest007
 * @tc.desc: Test account info display
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountDumpHelperTest, AccountDumpParameterTest007, TestSize.Level0)
{
    accountDumpHelper_ = nullptr;
    accountDumpHelper_ = std::make_unique<AccountDumpHelper>(ohosAccount_, nullptr);
    ASSERT_NE(accountDumpHelper_, nullptr);
    std::string out;
    vector<std::string> cmd = {"-os_account_infos"};
    accountDumpHelper_->Dump(cmd, out);
    auto pos = out.find("System error", 0);
    EXPECT_NE(std::string::npos, pos);
}

/**
 * @tc.name: AccountDumpTwoParameterTest001
 * @tc.desc: Test account log-level set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountDumpHelperTest, AccountDumpTwoParameterTest001, TestSize.Level0)
{
    ASSERT_NE(accountDumpHelper_, nullptr);
    /**
     * @tc.steps: step1. Input two parameters
     */
    std::string out;
    vector<std::string> setCmd = {"-set_log_level", "-1"};
    accountDumpHelper_->Dump(setCmd, out);
    auto pos = out.find("Invalid logLevel", 0);
    EXPECT_NE(std::string::npos, pos);

    setCmd.clear();
    setCmd = {"-set_log_level", "11"};
    accountDumpHelper_->Dump(setCmd, out);
    pos = out.find("Invalid logLevel", 0);
    EXPECT_NE(std::string::npos, pos);

    setCmd.clear();
    setCmd = {"-set_log_level", "$$"};
    accountDumpHelper_->Dump(setCmd, out);
    pos = out.find("Invalid format of log level", 0);
    EXPECT_NE(std::string::npos, pos);
}

/**
 * @tc.name: AccountDumpTwoParameterTest002
 * @tc.desc: Test account log-level set
 * @tc.type: FUNC
 * @tc.require: AR000CUF6N
 */
HWTEST_F(AccountDumpHelperTest, AccountDumpTwoParameterTest002, TestSize.Level0)
{
    /**
     * @tc.steps: step1. Input two parameters
     */
    std::string out;
    std::string logLevel;
    std::string prompt = "Current Log Level: ";
    vector<std::string> setCmd = {"-set_log_level", "1"};
    vector<std::string> getCmd = {"-show_log_level"};
    ASSERT_NE(accountDumpHelper_, nullptr);

    accountDumpHelper_->Dump(setCmd, out);
    auto pos = out.find("Set logLevel success", 0);
    EXPECT_NE(std::string::npos, pos);
    accountDumpHelper_->Dump(getCmd, out);
    pos = out.find(prompt, 0);
    EXPECT_NE(std::string::npos, pos);
    logLevel = out.substr(pos + prompt.length());
    EXPECT_EQ("1", logLevel.substr(0, 1));
}

/**
 * @tc.name: AccountDumpTwoParameterTest003
 * @tc.desc: Test account log-level set
 * @tc.type: FUNC
 * @tc.require: AR000CUF6N
 */
HWTEST_F(AccountDumpHelperTest, AccountDumpTwoParameterTest003, TestSize.Level0)
{
    ASSERT_NE(accountDumpHelper_, nullptr);
    /**
     * @tc.steps: step1. Input two parameters
     */
    std::string out;
    vector<std::string> setCmd = {"-ss", "1"};
    accountDumpHelper_->Dump(setCmd, out);
    auto pos = out.find("Usage:dump", 0);
    EXPECT_NE(std::string::npos, pos);
}

/**
 * @tc.name: AccountDumpInvalidParameterTest003
 * @tc.desc: Test account info display
 * @tc.type: FUNC
 * @tc.require: AR000CUF6N
 */
HWTEST_F(AccountDumpHelperTest, AccountDumpInvalidParameterTest003, TestSize.Level0)
{
    /**
     * @tc.steps: step1. Input invalid parameter
     */
    std::string out;
    vector<std::string> cmd = {"This_is_invalid_cmd"};
    ASSERT_NE(accountDumpHelper_, nullptr);
    accountDumpHelper_->Dump(cmd, out);
    auto pos = out.find("Usage:dump", 0);
    EXPECT_NE(std::string::npos, pos);
}
