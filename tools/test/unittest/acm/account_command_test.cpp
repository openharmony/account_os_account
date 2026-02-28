/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "account_command.h"
#include "account_file_operator.h"
#undef private
#include "account_log_wrapper.h"
#include "account_test_common.h"
#define private public
#include "iinner_os_account_manager.h"
#include "os_account_manager_service.h"
#include "os_account_proxy.h"
#undef private
#include "singleton.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AAFwk;
using namespace OHOS::AccountSA;
using namespace OHOS::AccountSA::Constants;

namespace {
const std::string HELP_MSG_UNKNOWN_OPTION = "fail: unknown option.";

const std::string STRING_LOCAL_ACCOUNT_NAME = "local_account_name";
const std::string STRING_TYPE_NORMAL = "normal";
const std::string STRING_TYPE_ADMIN = "admin";
const std::string STRING_TYPE_GUEST = "guest";
const std::string STRING_TYPE_INVALID = "type_invalid";
const std::string STRING_CONSTRAINT_INVALID = "constraint.invalid";
const std::string STRING_LOCAL_ACCOUNT_ID = "1024";
const std::string STRING_CONSTRAINT = "constraint.bluetooth";
const std::string STRING_CONSTRAINT1 = "constraint.bluetooth,constraint.bluetooth.set";
}  // namespace
class AccountCommandTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    std::string cmd_ = "stop";
};

void AccountCommandTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "SetUpTestCase enter";
    ASSERT_NE(GetAllAccountPermission(), 0);
#ifdef ACCOUNT_TEST
    AccountFileOperator osAccountFileOperator;
    osAccountFileOperator.DeleteDirOrFile(USER_INFO_BASE);
    GTEST_LOG_(INFO) << "delete account test path " << USER_INFO_BASE;
#endif  // ACCOUNT_TEST

    auto osAccountService = new (std::nothrow) OsAccountManagerService();
    ASSERT_NE(osAccountService, nullptr);
    IInnerOsAccountManager::GetInstance().Init();
    IInnerOsAccountManager::GetInstance().ActivateDefaultOsAccount();
    OsAccount::GetInstance().proxy_ = new (std::nothrow) OsAccountProxy(osAccountService->AsObject());
    ASSERT_NE(OsAccount::GetInstance().proxy_, nullptr);
}

void AccountCommandTest::TearDownTestCase()
{
    GTEST_LOG_(INFO) << "TearDownTestCase";
#ifdef ACCOUNT_TEST
    AccountFileOperator osAccountFileOperator;
    osAccountFileOperator.DeleteDirOrFile(USER_INFO_BASE);
    GTEST_LOG_(INFO) << "delete account test path " << USER_INFO_BASE;
#endif  // ACCOUNT_TEST
}

void AccountCommandTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());

    // reset optind to 0
    optind = 0;
}

void AccountCommandTest::TearDown()
{}

/**
 * @tc.name: Acm_Command_0100
 * @tc.desc: Verify the "acm" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_0100, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG);
}

/**
 * @tc.name: Acm_Command_0200
 * @tc.desc: Verify the "acm xxx" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_0200, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("xxx"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), cmd.GetCommandErrorMsg() + HELP_MSG);
}

/**
 * @tc.name: Acm_Command_0300
 * @tc.desc: Verify the "acm -xxx" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_0300, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("-xxx"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), cmd.GetCommandErrorMsg() + HELP_MSG);
}

/**
 * @tc.name: Acm_Command_0400
 * @tc.desc: Verify the "acm --xxx" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_0400, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("--xxx"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), cmd.GetCommandErrorMsg() + HELP_MSG);
}

/**
 * @tc.name: Acm_Command_0500
 * @tc.desc: Verify the "acm help" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_0500, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("help"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG);
}


/**
 * @tc.name: Acm_Command_Create_0100
 * @tc.desc: Verify the "acm create" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Create_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("Acm_Command_Create_0100");
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("create"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_NO_OPTION + "\n" + HELP_MSG_CREATE);
}

/**
 * @tc.name: Acm_Command_Create_0200
 * @tc.desc: Verify the "acm create xxx" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Create_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("Acm_Command_Create_0200");
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("create"),
        const_cast<char *>("xxx"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_NO_OPTION + "\n" + HELP_MSG_CREATE);
}

/**
 * @tc.name: Acm_Command_Create_0300
 * @tc.desc: Verify the "acm create -x" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Create_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("Acm_Command_Create_0300");
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("create"),
        const_cast<char *>("-x"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_UNKNOWN_OPTION + "\n" + HELP_MSG_CREATE);
}

/**
 * @tc.name: Acm_Command_Create_0400
 * @tc.desc: Verify the "acm create -xxx" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Create_0400, TestSize.Level1)
{
    ACCOUNT_LOGI("Acm_Command_Create_0400");
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("create"),
        const_cast<char *>("-xxx"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_UNKNOWN_OPTION + "\n" + HELP_MSG_CREATE);
}

/**
 * @tc.name: Acm_Command_Create_0500
 * @tc.desc: Verify the "acm create --x" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Create_0500, TestSize.Level1)
{
    ACCOUNT_LOGI("Acm_Command_Create_0500");
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("create"),
        const_cast<char *>("--x"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_UNKNOWN_OPTION + "\n" + HELP_MSG_CREATE);
}

/**
 * @tc.name: Acm_Command_Create_0600
 * @tc.desc: Verify the "acm create --xxx" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Create_0600, TestSize.Level1)
{
    ACCOUNT_LOGI("Acm_Command_Create_0600");
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("create"),
        const_cast<char *>("--xxx"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_UNKNOWN_OPTION + "\n" + HELP_MSG_CREATE);
}

/**
 * @tc.name: Acm_Command_Create_0700
 * @tc.desc: Verify the "acm create -h" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Create_0700, TestSize.Level1)
{
    ACCOUNT_LOGI("Acm_Command_Create_0700");
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("create"),
        const_cast<char *>("-h"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_CREATE);
}

/**
 * @tc.name: Acm_Command_Create_0800
 * @tc.desc: Verify the "acm create --help" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Create_0800, TestSize.Level1)
{
    ACCOUNT_LOGI("Acm_Command_Create_0800");
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("create"),
        const_cast<char *>("--help"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_CREATE);
}

/**
 * @tc.name: Acm_Command_Create_0900
 * @tc.desc: Verify the "acm create -n" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Create_0900, TestSize.Level1)
{
    ACCOUNT_LOGI("Acm_Command_Create_0900");
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("create"),
        const_cast<char *>("-n"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_OPTION_REQUIRES_AN_ARGUMENT + "\n" + HELP_MSG_CREATE);
}

/**
 * @tc.name: Acm_Command_Create_1000
 * @tc.desc: Verify the "acm create -n <local-account-name>" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Create_1000, TestSize.Level1)
{
    ACCOUNT_LOGI("Acm_Command_Create_1000");
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("create"),
        const_cast<char *>("-n"),
        const_cast<char *>("Acm_Command_Create_1000"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_NO_TYPE_OPTION + "\n" + HELP_MSG_CREATE);
}

/**
 * @tc.name: Acm_Command_Create_1100
 * @tc.desc: Verify the "acm create -t" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Create_1100, TestSize.Level1)
{
    ACCOUNT_LOGI("Acm_Command_Create_1100");
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("create"),
        const_cast<char *>("-t"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_OPTION_REQUIRES_AN_ARGUMENT + "\n" + HELP_MSG_CREATE);
}

/**
 * @tc.name: Acm_Command_Create_1200
 * @tc.desc: Verify the "acm create -t <type>" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Create_1200, TestSize.Level1)
{
    ACCOUNT_LOGI("Acm_Command_Create_1200");
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("create"),
        const_cast<char *>("-t"),
        const_cast<char *>(STRING_TYPE_INVALID.c_str()),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_INVALID_TYPE_ARGUMENT + "\n" + HELP_MSG_CREATE);
}

/**
 * @tc.name: Acm_Command_Create_1300
 * @tc.desc: Verify the "acm create -t <type>" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Create_1300, TestSize.Level1)
{
    ACCOUNT_LOGI("Acm_Command_Create_1300");
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("create"),
        const_cast<char *>("-t"),
        const_cast<char *>(STRING_TYPE_NORMAL.c_str()),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_NO_NAME_OPTION + "\n" + HELP_MSG_CREATE);
}

/**
 * @tc.name: Acm_Command_Create_1400
 * @tc.desc: Verify the "acm create -n <local-account-name> -t" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Create_1400, TestSize.Level1)
{
    ACCOUNT_LOGI("Acm_Command_Create_1400");
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("create"),
        const_cast<char *>("-n"),
        const_cast<char *>("Acm_Command_Create_1400"),
        const_cast<char *>("-t"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_OPTION_REQUIRES_AN_ARGUMENT + "\n" + HELP_MSG_CREATE);
}

/**
 * @tc.name: Acm_Command_Create_1500
 * @tc.desc: Verify the "acm create -n <local-account-name> -t <type>" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Create_1500, TestSize.Level1)
{
    ACCOUNT_LOGI("Acm_Command_Create_1500");
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("create"),
        const_cast<char *>("-n"),
        const_cast<char *>("Acm_Command_Create_1500"),
        const_cast<char *>("-t"),
        const_cast<char *>(STRING_TYPE_INVALID.c_str()),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_INVALID_TYPE_ARGUMENT + "\n" + HELP_MSG_CREATE);
}

/**
 * @tc.name: Acm_Command_Create_1600
 * @tc.desc: Verify the "acm create -n <local-account-name> -t <type>" command with normal type.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountCommandTest, Acm_Command_Create_1600, TestSize.Level1)
{
    ACCOUNT_LOGI("Acm_Command_Create_1600");
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("create"),
        const_cast<char *>("-n"),
        const_cast<char *>("Acm_Command_Create_1600"),
        const_cast<char *>("-t"),
        const_cast<char *>(STRING_TYPE_NORMAL.c_str()),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), STRING_CREATE_OS_ACCOUNT_OK + "\n");
}

/**
 * @tc.name: Acm_Command_Create_1700
 * @tc.desc: Verify the "acm create -n <local-account-name> -t <type>" command with admin type.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountCommandTest, Acm_Command_Create_1700, TestSize.Level1)
{
    ACCOUNT_LOGI("Acm_Command_Create_1700");
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("create"),
        const_cast<char *>("-n"),
        const_cast<char *>("Acm_Command_Create_1700"),
        const_cast<char *>("-t"),
        const_cast<char *>(STRING_TYPE_ADMIN.c_str()),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), STRING_CREATE_OS_ACCOUNT_OK + "\n");
}

/**
 * @tc.name: Acm_Command_Create_1800
 * @tc.desc: Verify the "acm create -n <local-account-name> -t <type>" command with guest type.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountCommandTest, Acm_Command_Create_1800, TestSize.Level1)
{
    ACCOUNT_LOGI("Acm_Command_Create_1800");
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("create"),
        const_cast<char *>("-n"),
        const_cast<char *>("Acm_Command_Create_1800"),
        const_cast<char *>("-t"),
        const_cast<char *>(STRING_TYPE_GUEST.c_str()),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), STRING_CREATE_OS_ACCOUNT_OK + "\n");
}

/**
 * @tc.name: Acm_Command_Create_1900
 * @tc.desc: Verify the "acm create -n <local-account-name> -t <type>" command, local-account-name is over max length.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountCommandTest, Acm_Command_Create_1900, TestSize.Level1)
{
    ACCOUNT_LOGI("Acm_Command_Create_1900");
    std::string maxAccountName(1025, 's'); // 1025:over max length
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("create"),
        const_cast<char *>("-n"),
        const_cast<char *>(maxAccountName.c_str()),
        const_cast<char *>("-t"),
        const_cast<char *>(STRING_TYPE_NORMAL.c_str()),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), STRING_CREATE_OS_ACCOUNT_NG + "\n");
}


/**
 * @tc.name: Acm_Command_Delete_0100
 * @tc.desc: Verify the "acm delete" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Delete_0100, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("delete"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_NO_OPTION + "\n" + HELP_MSG_DELETE);
}

/**
 * @tc.name: Acm_Command_Delete_0200
 * @tc.desc: Verify the "acm delete xxx" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Delete_0200, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("delete"),
        const_cast<char *>("xxx"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_NO_OPTION + "\n" + HELP_MSG_DELETE);
}

/**
 * @tc.name: Acm_Command_Delete_0300
 * @tc.desc: Verify the "acm delete -x" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Delete_0300, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("delete"),
        const_cast<char *>("-x"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_UNKNOWN_OPTION + "\n" + HELP_MSG_DELETE);
}

/**
 * @tc.name: Acm_Command_Delete_0400
 * @tc.desc: Verify the "acm delete -xxx" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Delete_0400, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("delete"),
        const_cast<char *>("-xxx"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_UNKNOWN_OPTION + "\n" + HELP_MSG_DELETE);
}

/**
 * @tc.name: Acm_Command_Delete_0500
 * @tc.desc: Verify the "acm delete --x" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Delete_0500, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("delete"),
        const_cast<char *>("--x"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_UNKNOWN_OPTION + "\n" + HELP_MSG_DELETE);
}

/**
 * @tc.name: Acm_Command_Delete_0600
 * @tc.desc: Verify the "acm delete --xxx" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Delete_0600, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("delete"),
        const_cast<char *>("--xxx"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_UNKNOWN_OPTION + "\n" + HELP_MSG_DELETE);
}

/**
 * @tc.name: Acm_Command_Delete_0700
 * @tc.desc: Verify the "acm delete -h" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Delete_0700, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("delete"),
        const_cast<char *>("-h"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_DELETE);
}

/**
 * @tc.name: Acm_Command_Delete_0800
 * @tc.desc: Verify the "acm delete --help" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Delete_0800, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("delete"),
        const_cast<char *>("--help"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_DELETE);
}

/**
 * @tc.name: Acm_Command_Delete_0900
 * @tc.desc: Verify the "acm delete -i" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Delete_0900, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("delete"),
        const_cast<char *>("-i"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_OPTION_REQUIRES_AN_ARGUMENT + "\n" + HELP_MSG_DELETE);
}

/**
 * @tc.name: Acm_Command_Delete_1000
 * @tc.desc: Verify the "acm delete -i" command with invalid userId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountCommandTest, Acm_Command_Delete_1000, TestSize.Level1)
{
    std::string userId = "88";
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("delete"),
        const_cast<char *>("-i"),
        const_cast<char *>(userId.c_str()),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), STRING_DELETE_OS_ACCOUNT_NG + "\n");
}

/**
 * @tc.name: Acm_Command_Delete_1100
 * @tc.desc: Verify the "acm delete -i" command with valid userId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountCommandTest, Acm_Command_Delete_1100, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    // create an os account
    EXPECT_EQ(ERR_OK, OsAccount::GetInstance().CreateOsAccount(TOOL_NAME, OsAccountType::NORMAL, osAccountInfo));

    std::string userId = std::to_string(osAccountInfo.GetLocalId());
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("delete"),
        const_cast<char *>("-i"),
        const_cast<char *>(userId.c_str()),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), STRING_DELETE_OS_ACCOUNT_OK + "\n");
}

/**
 * @tc.name: Acm_Command_Delete_1200
 * @tc.desc: Verify the "acm delete -i 0" command with valid userId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountCommandTest, Acm_Command_Delete_1200, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("delete"),
        const_cast<char *>("-i"),
        const_cast<char *>("0"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), STRING_DELETE_OS_ACCOUNT_NG + "\n");
}


/**
 * @tc.name: Acm_Command_Dump_0100
 * @tc.desc: Verify the "acm dump" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Dump_0100, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("dump"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_NO_OPTION + "\n" + HELP_MSG_DUMP);
}

/**
 * @tc.name: Acm_Command_Dump_0200
 * @tc.desc: Verify the "acm dump xxx" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Dump_0200, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("dump"),
        const_cast<char *>("xxx"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_NO_OPTION + "\n" + HELP_MSG_DUMP);
}

/**
 * @tc.name: Acm_Command_Dump_0300
 * @tc.desc: Verify the "acm dump -x" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Dump_0300, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("dump"),
        const_cast<char *>("-x"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_UNKNOWN_OPTION + "\n" + HELP_MSG_DUMP);
}

/**
 * @tc.name: Acm_Command_Dump_0400
 * @tc.desc: Verify the "acm dump -xxx" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Dump_0400, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("dump"),
        const_cast<char *>("-xxx"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_UNKNOWN_OPTION + "\n" + HELP_MSG_DUMP);
}

/**
 * @tc.name: Acm_Command_Dump_0500
 * @tc.desc: Verify the "acm dump --x" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Dump_0500, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("dump"),
        const_cast<char *>("--x"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_UNKNOWN_OPTION + "\n" + HELP_MSG_DUMP);
}

/**
 * @tc.name: Acm_Command_Dump_0600
 * @tc.desc: Verify the "acm dump --xxx" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Dump_0600, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("dump"),
        const_cast<char *>("--xxx"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_UNKNOWN_OPTION + "\n" + HELP_MSG_DUMP);
}

/**
 * @tc.name: Acm_Command_Dump_0700
 * @tc.desc: Verify the "acm dump -h" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Dump_0700, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("dump"),
        const_cast<char *>("-h"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_DUMP);
}

/**
 * @tc.name: Acm_Command_Dump_0800
 * @tc.desc: Verify the "acm dump --help" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Dump_0800, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("dump"),
        const_cast<char *>("--help"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_DUMP);
}

/**
 * @tc.name: Acm_Command_Dump_0900
 * @tc.desc: Verify the "acm dump -i" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Dump_0900, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("dump"),
        const_cast<char *>("-i"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_OPTION_REQUIRES_AN_ARGUMENT + "\n" + HELP_MSG_DUMP);
}

/**
 * @tc.name: Acm_Command_Dump_1000
 * @tc.desc: Verify the "acm dump -i" command.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountCommandTest, Acm_Command_Dump_1000, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("dump"),
        const_cast<char *>("-i"),
        const_cast<char *>("0"),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_FALSE(cmd.ExecCommand().empty());
}

/**
 * @tc.name: Acm_Command_Dump_1100
 * @tc.desc: Verify the "acm dump -i" command.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountCommandTest, Acm_Command_Dump_1100, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    // create an os account
    EXPECT_EQ(ERR_OK, OsAccount::GetInstance().CreateOsAccount(TOOL_NAME, OsAccountType::NORMAL, osAccountInfo));

    std::string userId = std::to_string(osAccountInfo.GetLocalId());
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("dump"),
        const_cast<char *>("-i"),
        const_cast<char *>(userId.c_str()),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_FALSE(cmd.ExecCommand().empty());
    OsAccount::GetInstance().RemoveOsAccount(osAccountInfo.GetLocalId());
}


/**
 * @tc.name: Acm_Command_Set_0100
 * @tc.desc: Verify the "acm set" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Set_0100, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("set"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_NO_OPTION + "\n" + HELP_MSG_SET);
}

/**
 * @tc.name: Acm_Command_Set_0200
 * @tc.desc: Verify the "acm set xxx" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Set_0200, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("set"),
        const_cast<char *>("xxx"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_NO_OPTION + "\n" + HELP_MSG_SET);
}

/**
 * @tc.name: Acm_Command_Set_0300
 * @tc.desc: Verify the "acm set -x" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Set_0300, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("set"),
        const_cast<char *>("-x"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_UNKNOWN_OPTION + "\n" + HELP_MSG_SET);
}

/**
 * @tc.name: Acm_Command_Set_0400
 * @tc.desc: Verify the "acm set -xxx" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Set_0400, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("set"),
        const_cast<char *>("-xxx"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_UNKNOWN_OPTION + "\n" + HELP_MSG_SET);
}

/**
 * @tc.name: Acm_Command_Set_0500
 * @tc.desc: Verify the "acm set --x" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Set_0500, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("set"),
        const_cast<char *>("--x"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_UNKNOWN_OPTION + "\n" + HELP_MSG_SET);
}

/**
 * @tc.name: Acm_Command_Set_0600
 * @tc.desc: Verify the "acm set --xxx" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Set_0600, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("set"),
        const_cast<char *>("--xxx"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_UNKNOWN_OPTION + "\n" + HELP_MSG_SET);
}

/**
 * @tc.name: Acm_Command_Set_0700
 * @tc.desc: Verify the "acm set -h" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Set_0700, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("set"),
        const_cast<char *>("-h"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_SET);
}

/**
 * @tc.name: Acm_Command_Set_0800
 * @tc.desc: Verify the "acm set --help" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Set_0800, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("set"),
        const_cast<char *>("--help"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_SET);
}

/**
 * @tc.name: Acm_Command_Set_0900
 * @tc.desc: Verify the "acm set -i" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Set_0900, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("set"),
        const_cast<char *>("-i"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_OPTION_REQUIRES_AN_ARGUMENT + "\n" + HELP_MSG_SET);
}

/**
 * @tc.name: Acm_Command_Set_1000
 * @tc.desc: Verify the "acm set -i <local-account-id>" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Set_1000, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("set"),
        const_cast<char *>("-i"),
        const_cast<char *>(STRING_LOCAL_ACCOUNT_ID.c_str()),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_NO_CONSTRAINTS_OPTION + "\n" + HELP_MSG_SET);
}

/**
 * @tc.name: Acm_Command_Set_1100
 * @tc.desc: Verify the "acm set -c" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Set_1100, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("set"),
        const_cast<char *>("-c"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_OPTION_REQUIRES_AN_ARGUMENT + "\n" + HELP_MSG_SET);
}

/**
 * @tc.name: Acm_Command_Set_1200
 * @tc.desc: Verify the "acm set -c <constraints>" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Set_1200, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("set"),
        const_cast<char *>("-c"),
        const_cast<char *>(STRING_CONSTRAINT.c_str()),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_NO_ID_OPTION + "\n" + HELP_MSG_SET);
}

/**
 * @tc.name: Acm_Command_Set_1300
 * @tc.desc: Verify the "acm set -i <local-account-id> -c" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Set_1300, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("set"),
        const_cast<char *>("-i"),
        const_cast<char *>(STRING_LOCAL_ACCOUNT_ID.c_str()),
        const_cast<char *>("-c"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_OPTION_REQUIRES_AN_ARGUMENT + "\n" + HELP_MSG_SET);
}

/**
 * @tc.name: Acm_Command_Set_1400
 * @tc.desc: Verify the "acm set -c <constraints> -i" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Set_1400, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("set"),
        const_cast<char *>("-c"),
        const_cast<char *>(STRING_CONSTRAINT.c_str()),
        const_cast<char *>("-i"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_OPTION_REQUIRES_AN_ARGUMENT + "\n" + HELP_MSG_SET);
}

/**
 * @tc.name: Acm_Command_Set_1500
 * @tc.desc: Verify the "acm set -c <constraints> -i" command.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountCommandTest, Acm_Command_Set_1500, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    // create an os account
    EXPECT_EQ(ERR_OK, OsAccount::GetInstance().CreateOsAccount(TOOL_NAME, OsAccountType::NORMAL, osAccountInfo));

    std::string userId = std::to_string(osAccountInfo.GetLocalId());
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("set"),
        const_cast<char *>("-c"),
        const_cast<char *>(STRING_CONSTRAINT1.c_str()),
        const_cast<char *>("-i"),
        const_cast<char *>(userId.c_str()),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), STRING_SET_OS_ACCOUNT_CONSTRAINTS_OK + "\n");
    OsAccount::GetInstance().RemoveOsAccount(osAccountInfo.GetLocalId());
}


/**
 * @tc.name: Acm_Command_Switch_0100
 * @tc.desc: Verify the "acm switch" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Switch_0100, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("switch"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_NO_OPTION + "\n" + HELP_MSG_SWITCH);
}

/**
 * @tc.name: Acm_Command_Switch_0200
 * @tc.desc: Verify the "acm switch xxx" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Switch_0200, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("switch"),
        const_cast<char *>("xxx"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_NO_OPTION + "\n" + HELP_MSG_SWITCH);
}

/**
 * @tc.name: Acm_Command_Switch_0300
 * @tc.desc: Verify the "acm switch -x" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Switch_0300, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("switch"),
        const_cast<char *>("-x"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_UNKNOWN_OPTION + "\n" + HELP_MSG_SWITCH);
}

/**
 * @tc.name: Acm_Command_Switch_0400
 * @tc.desc: Verify the "acm switch -xxx" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Switch_0400, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("switch"),
        const_cast<char *>("-xxx"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_UNKNOWN_OPTION + "\n" + HELP_MSG_SWITCH);
}

/**
 * @tc.name: Acm_Command_Switch_0500
 * @tc.desc: Verify the "acm switch --x" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Switch_0500, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("switch"),
        const_cast<char *>("--x"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_UNKNOWN_OPTION + "\n" + HELP_MSG_SWITCH);
}

/**
 * @tc.name: Acm_Command_Switch_0600
 * @tc.desc: Verify the "acm switch --xxx" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Switch_0600, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("switch"),
        const_cast<char *>("--xxx"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_UNKNOWN_OPTION + "\n" + HELP_MSG_SWITCH);
}

/**
 * @tc.name: Acm_Command_Switch_0700
 * @tc.desc: Verify the "acm switch -h" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Switch_0700, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("switch"),
        const_cast<char *>("-h"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_SWITCH);
}

/**
 * @tc.name: Acm_Command_Switch_0800
 * @tc.desc: Verify the "acm switch --help" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Switch_0800, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("switch"),
        const_cast<char *>("--help"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_SWITCH);
}

/**
 * @tc.name: Acm_Command_Switch_0900
 * @tc.desc: Verify the "acm switch -i" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_Switch_0900, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("switch"),
        const_cast<char *>("-i"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_OPTION_REQUIRES_AN_ARGUMENT + "\n" + HELP_MSG_SWITCH);
}

/**
 * @tc.name: Acm_Command_Switch_1000
 * @tc.desc: Verify the "acm switch -i" command.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountCommandTest, Acm_Command_Switch_1000, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    // create an os account
    EXPECT_EQ(ERR_OK, OsAccount::GetInstance().CreateOsAccount(TOOL_NAME, OsAccountType::NORMAL, osAccountInfo));

    std::string userId = std::to_string(osAccountInfo.GetLocalId());
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("switch"),
        const_cast<char *>("-i"),
        const_cast<char *>(userId.c_str()),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), STRING_SWITCH_OS_ACCOUNT_OK + "\n");
    OsAccount::GetInstance().RemoveOsAccount(osAccountInfo.GetLocalId());
}

/**
 * @tc.name: Acm_Command_Switch_1100
 * @tc.desc: Verify the "acm switch -i <id> -D <displayId>" command.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountCommandTest, Acm_Command_Switch_1100, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    // create an os account
    EXPECT_EQ(ERR_OK, OsAccount::GetInstance().CreateOsAccount(TOOL_NAME, OsAccountType::NORMAL, osAccountInfo));

    std::string userId = std::to_string(osAccountInfo.GetLocalId());
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("switch"),
        const_cast<char *>("-i"),
        const_cast<char *>(userId.c_str()),
        const_cast<char *>("-d"),
        const_cast<char *>("0"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), STRING_SWITCH_OS_ACCOUNT_OK + "\n");
    OsAccount::GetInstance().RemoveOsAccount(osAccountInfo.GetLocalId());
}

/**
 * @tc.name: Acm_Command_Switch_1200
 * @tc.desc: Verify the "acm switch -d" command without argument.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountCommandTest, Acm_Command_Switch_1200, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("switch"),
        const_cast<char *>("-d"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_OPTION_REQUIRES_AN_ARGUMENT + "\n" + HELP_MSG_SWITCH);
}

/**
 * @tc.name: Acm_Command_Switch_1300
 * @tc.desc: Verify the "acm switch -i <id> -d <invalid-displayId>" command.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountCommandTest, Acm_Command_Switch_1300, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("switch"),
        const_cast<char *>("-i"),
        const_cast<char *>("100"),
        const_cast<char *>("-d"),
        const_cast<char *>("-1"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), "fail: invalid display name.\n" + HELP_MSG_SWITCH);
}
