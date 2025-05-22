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
#include "account_log_wrapper.h"
#include "os_account_manager_service.h"

namespace OHOS {
namespace AccountSA {
using namespace testing::ext;
class OsAccountMaintenanceTypeTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown() {}
    std::shared_ptr<OsAccountManagerService> osAccountManagerService_ = std::make_shared<OsAccountManagerService>();
};

void OsAccountMaintenanceTypeTest::TearDownTestCase()
{
    std::string cmd = "chown -R 3058:3058 /data/service/el1/public/account";
    system(cmd.c_str());
}

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
}  // namespace AccountSA
}  // namespace OHOS