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

#include "account_bundle_manager.h"
#include "account_error_no.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string STRING_OWNER = "com.example.owner";

constexpr std::int32_t UID = 10000;
}  // namespace

class AccountBundleManagerModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;

    std::shared_ptr<AccountBundleManager> bundleManagerPtr_;
};

void AccountBundleManagerModuleTest::SetUpTestCase(void)
{}

void AccountBundleManagerModuleTest::TearDownTestCase(void)
{}

void AccountBundleManagerModuleTest::SetUp(void)
{
    bundleManagerPtr_ = DelayedSingleton<AccountBundleManager>::GetInstance();
}

void AccountBundleManagerModuleTest::TearDown(void)
{}

/**
 * @tc.number: AccountBundleManager_GetBundleName_0100
 * @tc.name: GetBundleName
 * @tc.desc: Get bundle name.
 */
HWTEST_F(AccountBundleManagerModuleTest, AccountBundleManager_GetBundleName_0100, Function | MediumTest | Level1)
{
    ASSERT_NE(bundleManagerPtr_, nullptr);

    std::string bundleName = "";
    ErrCode result = bundleManagerPtr_->GetBundleName(UID, bundleName);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_NAME);
}

/**
 * @tc.number: AccountBundleManager_GetBundleInfo_0100
 * @tc.name: GetBundleInfo
 * @tc.desc: Get bundle info.
 */
HWTEST_F(AccountBundleManagerModuleTest, AccountBundleManager_GetBundleInfo_0100, Function | MediumTest | Level1)
{
    ASSERT_NE(bundleManagerPtr_, nullptr);

    std::string bundleName = STRING_OWNER;
    AppExecFwk::BundleInfo bundleInfo;
    ErrCode result = bundleManagerPtr_->GetBundleInfo(bundleName, bundleInfo);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_GET_BUNDLE_INFO);
}
