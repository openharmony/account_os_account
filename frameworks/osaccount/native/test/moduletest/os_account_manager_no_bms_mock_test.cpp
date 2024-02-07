/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "account_log_wrapper.h"
#include "bundle_mgr_interface.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#define private public
#include "os_account_info.h"
#include "os_account_manager.h"
#undef private

#include "system_ability_definition.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;
using namespace OHOS::AccountSA::Constants;
namespace {
static bool CheckBundleName(std::vector<AppExecFwk::BundleInfo> checkList, string tarName)
{
    for (auto i : checkList) {
        if (i.name == tarName) {
            return true;
        }
    }
    return false;
}
}

class OsAccountManagerBmsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void OsAccountManagerBmsTest::SetUpTestCase(void)
{
#ifdef ACCOUNT_TEST
    AccountFileOperator osAccountFileOperator;
    osAccountFileOperator.DeleteDirOrFile(USER_INFO_BASE);
    GTEST_LOG_(INFO) << "delete account test path " << USER_INFO_BASE;
#endif  // ACCOUNT_TEST
}

void OsAccountManagerBmsTest::TearDownTestCase(void)
{
#ifdef ACCOUNT_TEST
    AccountFileOperator osAccountFileOperator;
    osAccountFileOperator.DeleteDirOrFile(USER_INFO_BASE);
    GTEST_LOG_(INFO) << "delete account test path " << USER_INFO_BASE;
#endif  // ACCOUNT_TEST
}

void OsAccountManagerBmsTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void OsAccountManagerBmsTest::TearDown(void)
{}

/**
 * @tc.name: OsAccountManagerBmsTest001
 * @tc.desc: create os account with disallowed hap list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerBmsTest, OsAccountManagerBmsTest001, TestSize.Level1)
{
    OsAccountInfo osAccountInfoOne;
    CreateOsAccountOptions options;
    options.disallowedHapList = {
        "cn.openharmony.inputmethodchoosedialog",
        "cn.openharmony.pasteboarddialog",
        "com.example.kikakeyboard",
        "com.ohos.UserFile.ExternalFileManager",
        "com.ohos.adminprovisioning",
        "com.ohos.amsdialog",
        "com.ohos.calendardata",
        "com.ohos.callui",
        "com.ohos.camera",
    };
    EXPECT_EQ(ERR_OK,
        OsAccountManager::CreateOsAccount("test", "test", OsAccountType::NORMAL, options, osAccountInfoOne));
    sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);
    auto bundleObj = samgr->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    ASSERT_NE(bundleObj, nullptr);
    auto bundleMgrProxy = iface_cast<AppExecFwk::IBundleMgr>(bundleObj);
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::vector<AppExecFwk::BundleInfo> bundleInfos;
    EXPECT_EQ(true, bundleMgrProxy->GetBundleInfos(
        OHOS::AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT, bundleInfos, osAccountInfoOne.GetLocalId()));
    std::vector<AppExecFwk::BundleInfo> user0BundleInfos;
    EXPECT_EQ(true,
        bundleMgrProxy->GetBundleInfos(OHOS::AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT, user0BundleInfos, 0));
    bool flag = true;
    for (auto j : options.disallowedHapList) {
        if (!CheckBundleName(bundleInfos, j)) {
            continue;
        }
        if (!CheckBundleName(user0BundleInfos, j)) {
            flag = false;
            break;
        }
    }
    EXPECT_EQ(flag, true);
    OsAccountManager::RemoveOsAccount(osAccountInfoOne.GetLocalId());
}