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

#include <filesystem>
#include <gtest/gtest.h>

#include "account_command.h"
#include "account_command_util.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AAFwk;
using namespace OHOS::AccountSA;
using namespace OHOS::AccountSA::Constants;

class AccountCommandCreateModuleTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    std::string cmd_ = "create";
};

void AccountCommandCreateModuleTest::SetUpTestCase()
{
#ifdef ACCOUNT_TEST
    if (std::filesystem::exists(USER_INFO_BASE)) {
        if (std::filesystem::remove_all(USER_INFO_BASE)) {
            GTEST_LOG_(INFO) << "delete account test path " << USER_INFO_BASE;
        }
    }
#endif  // ACCOUNT_TEST
}

void AccountCommandCreateModuleTest::TearDownTestCase()
{
#ifdef ACCOUNT_TEST
    if (std::filesystem::exists(USER_INFO_BASE)) {
        if (std::filesystem::remove_all(USER_INFO_BASE)) {
            GTEST_LOG_(INFO) << "delete account test path " << USER_INFO_BASE;
        }
    }
#endif  // ACCOUNT_TEST
}

void AccountCommandCreateModuleTest::SetUp()
{}

void AccountCommandCreateModuleTest::TearDown()
{}

/**
 * @tc.name: Acm_Command_Create_0100
 * @tc.desc: Verify the "acm create -n <local-account-name> -t <type>" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandCreateModuleTest, Acm_Command_Create_0100, TestSize.Level1)
{
    std::string commandResult = AccountCommandUtil::CreateOsAccount("Acm_Command_Create_0100");
    ASSERT_NE(commandResult.find(STRING_CREATE_OS_ACCOUNT_OK), std::string::npos);

    commandResult = AccountCommandUtil::DeleteLastOsAccount();
    ASSERT_NE(commandResult.find(STRING_DELETE_OS_ACCOUNT_OK), std::string::npos);
}
