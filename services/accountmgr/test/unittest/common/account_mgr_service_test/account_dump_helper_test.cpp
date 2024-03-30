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

#include <dirent.h>
#include <fstream>
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

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
#include "os_account_file_operator.h"
#include "os_account_manager_service.h"
#define private public
#include "perf_stat.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;
using namespace OHOS::AccountSA::Constants;

namespace {
const std::string TEST_ACCOUNT_NAME = "TestAccountName";
const std::string TEST_ACCOUNT_UID = "123456789";
const std::string DEFAULT_ANON_STR = "**********";
}

class AccountDumpHelperTest : public testing::Test {
public:
    AccountDumpHelperTest();
    ~AccountDumpHelperTest() {}

    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    OsAccountManagerService* osAccount_ {};
    std::unique_ptr<AccountDumpHelper> accountDumpHelper_ {};
};

AccountDumpHelperTest::AccountDumpHelperTest() {}

void AccountDumpHelperTest::SetUpTestCase()
{
    OhosAccountManager::GetInstance().OnInitialize();
}

void AccountDumpHelperTest::TearDownTestCase()
{
    std::vector<OsAccountInfo> osAccountInfos;
    OsAccount::GetInstance().QueryAllCreatedOsAccounts(osAccountInfos);
    for (const auto &info : osAccountInfos) {
        if (info.GetLocalId() == START_USER_ID) {
            continue;
        }
        ACCOUNT_LOGI("[TearDownTestCase] remove account %{public}d", info.GetLocalId());
        OsAccount::GetInstance().RemoveOsAccount(info.GetLocalId());
    }
}

void AccountDumpHelperTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());

    osAccount_ = new (std::nothrow) OsAccountManagerService();
    if (osAccount_ == nullptr) {
        std::cout << "AccountDumpHelperTest, error! osAccount_ is nullptr!" << std::endl;
    }
    accountDumpHelper_ = std::make_unique<AccountDumpHelper>(osAccount_);
}

void AccountDumpHelperTest::TearDown()
{
    if (osAccount_ != nullptr) {
        delete osAccount_;
        osAccount_ = nullptr;
    }
}

#ifndef HAS_KV_STORE_PART
static int RenameFile(const std::string &src, const std::string &des)
{
    return rename(src.c_str(), des.c_str());
}
#endif

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
    ASSERT_NE(accountDumpHelper_, nullptr);

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
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
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
    ASSERT_NE(accountDumpHelper_, nullptr);

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
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

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
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
HWTEST_F(AccountDumpHelperTest, AccountDumpParameterTest003, TestSize.Level0)
{
    /**
     * @tc.steps: step1. Input one parameter
     */
    std::string out;
    vector<std::string> cmd = {"-time_info_dump"};
    ASSERT_NE(accountDumpHelper_, nullptr);
    accountDumpHelper_->Dump(cmd, out);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS

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
    accountDumpHelper_ = std::make_unique<AccountDumpHelper>(osAccount_);
    ASSERT_NE(accountDumpHelper_, nullptr);
    std::string out;
    vector<std::string> cmd = {"-ohos_account_infos"};
    accountDumpHelper_->Dump(cmd, out);
    auto pos = out.find("System error", 0);
    EXPECT_EQ(std::string::npos, pos);
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
    accountDumpHelper_ = std::make_unique<AccountDumpHelper>(nullptr);
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

/**
 * @tc.name: AnonymizeNameStrTest001
 * @tc.desc: test input invalid parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountDumpHelperTest, AnonymizeNameStrTest001, TestSize.Level0)
{
    /**
     * @tc.steps: step1. Input invalid parameter
     */
    std::string name = "";
    std::string out = accountDumpHelper_->AnonymizeNameStr(name);
    EXPECT_EQ(out, "");
}

/**
 * @tc.name: AnonymizeUidStrTest001
 * @tc.desc: test input invalid parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountDumpHelperTest, AnonymizeUidStrTest001, TestSize.Level0)
{
    /**
     * @tc.steps: step1. Input invalid parameter
     */
    std::string name = "ohosAnonymousUid";
    std::string out = accountDumpHelper_->AnonymizeUidStr(name);
    EXPECT_EQ(out, name);
}

/**
 * @tc.name: AnonymizeUidStrTest002
 * @tc.desc: test input invalid parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountDumpHelperTest, AnonymizeUidStrTest002, TestSize.Level0)
{
    /**
     * @tc.steps: step1. Input invalid parameter
     */
    std::string out = accountDumpHelper_->AnonymizeUidStr("");
    EXPECT_EQ(out, "");
}

/**
 * @tc.name: AnonymizeUidStrTest003
 * @tc.desc: test input invalid parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountDumpHelperTest, AnonymizeUidStrTest003, TestSize.Level0)
{
    /**
     * @tc.steps: step1. Input invalid parameter
     */
    std::string name = "1";
    std::string out = accountDumpHelper_->AnonymizeUidStr(name);
    EXPECT_EQ(out, DEFAULT_ANON_STR);
}

/**
 * @tc.name: ShowOhosAccountInfoTest001
 * @tc.desc: test the file saved to OhosAccountInfo cannot be obtained
 * @tc.type: FUNC
 * @tc.require:
 */
#ifndef HAS_KV_STORE_PART
HWTEST_F(AccountDumpHelperTest, ShowOhosAccountInfoTest001, TestSize.Level0)
{
    RenameFile(Constants::ACCOUNT_LIST_FILE_JSON_PATH,
        Constants::ACCOUNT_LIST_FILE_JSON_PATH + "_blk");

    std::string out;
    accountDumpHelper_->ShowOhosAccountInfo(out);
    auto pos = out.find("Cannot query os account list", 0);
    EXPECT_NE(std::string::npos, pos);

    RenameFile(Constants::ACCOUNT_LIST_FILE_JSON_PATH + "_blk",
        Constants::ACCOUNT_LIST_FILE_JSON_PATH);
}

/**
 * @tc.name: ShowOhosAccountInfoTest002
 * @tc.desc: test read empty OhosAccountInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountDumpHelperTest, ShowOhosAccountInfoTest002, TestSize.Level0)
{
    /**
     * @tc.steps: step1. Input invalid parameter
     */
    RenameFile(Constants::ACCOUNT_LIST_FILE_JSON_PATH,
        Constants::ACCOUNT_LIST_FILE_JSON_PATH + "_blk");
    if (access(Constants::ACCOUNT_LIST_FILE_JSON_PATH.c_str(), F_OK) != 0) {
        FILE *fp = fopen(Constants::ACCOUNT_LIST_FILE_JSON_PATH.c_str(), "w");
        EXPECT_NE(fp, nullptr);
        fclose(fp);
    }
    EXPECT_EQ(access(Constants::ACCOUNT_LIST_FILE_JSON_PATH.c_str(), F_OK), 0);

    std::string out;
    accountDumpHelper_->ShowOhosAccountInfo(out);
    auto pos = out.find("System error:", 0);
    EXPECT_NE(std::string::npos, pos);

    remove(Constants::ACCOUNT_LIST_FILE_JSON_PATH.c_str());
    RenameFile(Constants::ACCOUNT_LIST_FILE_JSON_PATH + "_blk",
        Constants::ACCOUNT_LIST_FILE_JSON_PATH);
}
#endif