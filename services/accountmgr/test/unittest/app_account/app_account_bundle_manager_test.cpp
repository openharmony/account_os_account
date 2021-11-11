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
#include "app_account_bundle_manager.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string STRING_OWNER = "com.example.owner";
}  // namespace

class AppAccountBundleManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;

    std::shared_ptr<AppAccountBundleManager> bundleManagerPtr_;
};

void AppAccountBundleManagerTest::SetUpTestCase(void)
{}

void AppAccountBundleManagerTest::TearDownTestCase(void)
{}

void AppAccountBundleManagerTest::SetUp(void)
{
    bundleManagerPtr_ = DelayedSingleton<AppAccountBundleManager>::GetInstance();
}

void AppAccountBundleManagerTest::TearDown(void)
{}

/**
 * @tc.number: AppAccountBundleManager_GetBundleName_0100
 * @tc.name: GetBundleName
 * @tc.desc: Get bundle name.
 */
HWTEST_F(AppAccountBundleManagerTest, AppAccountBundleManager_GetBundleName_0100, Function | MediumTest | Level1)
{
    EXPECT_NE(bundleManagerPtr_, nullptr);

    std::string bundleName = "";
    ErrCode result = bundleManagerPtr_->GetBundleName(bundleName);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(bundleName, STRING_OWNER);
}
