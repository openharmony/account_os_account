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

#include "account_error_no.h"
#define private public
#include "os_account_manager_service.h"
#include "os_account_control_file_manager.h"
#undef private
#include "os_account_constants.h"

namespace OHOS {
namespace AccountSA {
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS;
using namespace AccountSA;

namespace {
const std::string STRING_TEST_NAME = "name";
}  // namespace
class OsAccountManagerServiceCreateOsAccountTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

public:
    std::shared_ptr<OsAccountManagerService> osAccountManagerService_;
    std::shared_ptr<OsAccountControlFileManager> osAccountControlFileManager_;
};
void OsAccountManagerServiceCreateOsAccountTest::SetUpTestCase(void)
{}

void OsAccountManagerServiceCreateOsAccountTest::TearDownTestCase(void)
{}

void OsAccountManagerServiceCreateOsAccountTest::SetUp(void)
{
    osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
    osAccountControlFileManager_ = std::make_shared<OsAccountControlFileManager>();
    osAccountControlFileManager_->Init();
}

void OsAccountManagerServiceCreateOsAccountTest::TearDown(void)
{}
/**
 * @tc.name: OsAccountManagerServiceCreateOsAccountTest001
 * @tc.desc: Test CreateOsAccount when create max accounts.
 * @tc.type: FUNC
 * @tc.require: AR000CUF55
 */
HWTEST_F(OsAccountManagerServiceCreateOsAccountTest, OsAccountManagerServiceCreateOsAccountTest001,
    Function | MediumTest | Level1)
{
    ErrCode errCode;
    for (auto i = Constants::START_USER_ID + 1; i <= Constants::MAX_USER_ID + 1; i++) {
        OsAccountInfo osAccountInfoOne;
        errCode = osAccountManagerService_->CreateOsAccount(STRING_TEST_NAME, 1, osAccountInfoOne);
    }
    EXPECT_NE(errCode, ERR_OK);
    for (auto i = Constants::START_USER_ID + 1; i <= Constants::MAX_USER_ID; i++) {
        osAccountControlFileManager_->DelOsAccount(i);
    }
}
}  // namespace AccountSA
}  // namespace OHOS