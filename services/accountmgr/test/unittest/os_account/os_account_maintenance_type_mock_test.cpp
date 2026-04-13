/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "account_log_wrapper.h"
#include "os_account_constants.h"
#define private public
#include "os_account_manager_service.h"
#undef private

namespace OHOS {
namespace AccountSA {
using namespace testing::ext;
class OsAccountMaintenanceTypeTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp();
    void TearDown() {}
    std::shared_ptr<OsAccountManagerService> osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
};

void OsAccountMaintenanceTypeTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    std::string testCaseName = std::string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

/**
 * @tc.name: MaintenanceTypeTest001
 * @tc.desc: Test create maintenance type account calling by hap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMaintenanceTypeTest, MaintenanceTypeTest001, TestSize.Level1)
{
    std::string name = "MaintenanceTypeTest001";
    OsAccountInfo info;
    EXPECT_EQ(ERR_ACCOUNT_COMMON_INVALID_PARAMETER,
        osAccountManagerService_->CreateOsAccount(name, OsAccountType::MAINTENANCE, info));
}

/**
 * @tc.name: ValidateShortNameTest001
 * @tc.desc: Test ValidateShortName with invalid inputs: empty, too long, special characters, and reserved names.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMaintenanceTypeTest, ValidateShortNameTest001, TestSize.Level1)
{
    // Empty short name
    EXPECT_EQ(ERR_ACCOUNT_COMMON_INVALID_PARAMETER, osAccountManagerService_->ValidateShortName(""));

    // Too long short name (> SHORT_NAME_MAX_SIZE = 255 chars)
    EXPECT_EQ(ERR_ACCOUNT_COMMON_INVALID_PARAMETER,
        osAccountManagerService_->ValidateShortName(std::string(Constants::SHORT_NAME_MAX_SIZE + 1, 'a')));

    // Special characters from SPECIAL_CHARACTER_ARRAY: "<>|\":*?/\"
    EXPECT_EQ(ERR_ACCOUNT_COMMON_INVALID_PARAMETER, osAccountManagerService_->ValidateShortName("invalid<name"));
    EXPECT_EQ(ERR_ACCOUNT_COMMON_INVALID_PARAMETER, osAccountManagerService_->ValidateShortName("invalid>name"));
    EXPECT_EQ(ERR_ACCOUNT_COMMON_INVALID_PARAMETER, osAccountManagerService_->ValidateShortName("invalid|name"));
    EXPECT_EQ(ERR_ACCOUNT_COMMON_INVALID_PARAMETER, osAccountManagerService_->ValidateShortName("invalid:name"));
    EXPECT_EQ(ERR_ACCOUNT_COMMON_INVALID_PARAMETER, osAccountManagerService_->ValidateShortName("invalid*name"));
    EXPECT_EQ(ERR_ACCOUNT_COMMON_INVALID_PARAMETER, osAccountManagerService_->ValidateShortName("invalid?name"));
    EXPECT_EQ(ERR_ACCOUNT_COMMON_INVALID_PARAMETER, osAccountManagerService_->ValidateShortName("invalid/name"));

    // Reserved names from SHORT_NAME_CANNOT_BE_NAME_ARRAY: "." and ".."
    EXPECT_EQ(ERR_ACCOUNT_COMMON_INVALID_PARAMETER, osAccountManagerService_->ValidateShortName("."));
    EXPECT_EQ(ERR_ACCOUNT_COMMON_INVALID_PARAMETER, osAccountManagerService_->ValidateShortName(".."));
}

/**
 * @tc.name: ValidateShortNameTest002
 * @tc.desc: Test ValidateShortName with valid inputs including boundary lengths.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMaintenanceTypeTest, ValidateShortNameTest002, TestSize.Level1)
{
    // Single character: minimal valid short name
    EXPECT_EQ(ERR_OK, osAccountManagerService_->ValidateShortName("a"));

    // Valid short name with numbers and letters
    EXPECT_EQ(ERR_OK, osAccountManagerService_->ValidateShortName("validname123"));

    // Exactly at maximum length (255 chars)
    EXPECT_EQ(ERR_OK,
        osAccountManagerService_->ValidateShortName(std::string(Constants::SHORT_NAME_MAX_SIZE, 'b')));

    // Names that look like reserved but are not (e.g., "..." is not in the reserved list)
    EXPECT_EQ(ERR_OK, osAccountManagerService_->ValidateShortName("..."));
}

/**
 * @tc.name: CheckLocalIdRestrictedTest001
 * @tc.desc: Test CheckLocalIdRestricted with ADMIN_LOCAL_ID, START_USER_ID, and large valid IDs.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMaintenanceTypeTest, CheckLocalIdRestrictedTest001, TestSize.Level1)
{
    // ADMIN_LOCAL_ID (0) is always restricted
    EXPECT_EQ(ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR,
        osAccountManagerService_->CheckLocalIdRestricted(Constants::ADMIN_LOCAL_ID));

    // START_USER_ID (100) is valid
    EXPECT_EQ(ERR_OK, osAccountManagerService_->CheckLocalIdRestricted(Constants::START_USER_ID));

    // IDs greater than or equal to START_USER_ID are valid
    EXPECT_EQ(ERR_OK, osAccountManagerService_->CheckLocalIdRestricted(101));
    EXPECT_EQ(ERR_OK, osAccountManagerService_->CheckLocalIdRestricted(1000));
}

/**
 * @tc.name: CheckLocalIdRestrictedTest002
 * @tc.desc: Test CheckLocalIdRestricted with a non-existent local ID below START_USER_ID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMaintenanceTypeTest, CheckLocalIdRestrictedTest002, TestSize.Level1)
{
    // Non-existent ID between ADMIN_LOCAL_ID and START_USER_ID: returns account-not-found or restricted
    ErrCode ret = osAccountManagerService_->CheckLocalIdRestricted(50);
    EXPECT_TRUE(ret == ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR ||
        ret == ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR);
}

/**
 * @tc.name: GetOsAccountShortNameCommonTest001
 * @tc.desc: Test GetOsAccountShortNameCommon with a non-existent account ID.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountMaintenanceTypeTest, GetOsAccountShortNameCommonTest001, TestSize.Level1)
{
    std::string shortName;
    EXPECT_NE(ERR_OK, osAccountManagerService_->GetOsAccountShortNameCommon(9999, shortName));
}
}  // namespace AccountSA
}  // namespace OHOS