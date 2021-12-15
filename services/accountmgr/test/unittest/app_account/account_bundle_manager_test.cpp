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
#include "account_bundle_manager.h"
#undef private
#include "account_error_no.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string STRING_OWNER = "com.example.owner";

constexpr std::int32_t UID = 10000;
}  // namespace

class AccountBundleManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;

    std::shared_ptr<AccountBundleManager> bundleManagerPtr_;
};

void AccountBundleManagerTest::SetUpTestCase(void)
{}

void AccountBundleManagerTest::TearDownTestCase(void)
{}

void AccountBundleManagerTest::SetUp(void)
{
    bundleManagerPtr_ = DelayedSingleton<AccountBundleManager>::GetInstance();
}

void AccountBundleManagerTest::TearDown(void)
{}

/**
 * @tc.name: AccountBundleManager_GetBundleName_0100
 * @tc.desc: Get bundle name.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFR
 */
HWTEST_F(AccountBundleManagerTest, AccountBundleManager_GetBundleName_0100, Function | MediumTest | Level1)
{
    ASSERT_NE(bundleManagerPtr_, nullptr);

    std::string bundleName = "";
    ErrCode result = bundleManagerPtr_->GetBundleName(UID, bundleName);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(bundleName, STRING_OWNER);
}

/**
 * @tc.name: AccountBundleManager_GetBundleInfo_0100
 * @tc.desc: Get bundle info.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFR
 */
HWTEST_F(AccountBundleManagerTest, AccountBundleManager_GetBundleInfo_0100, Function | MediumTest | Level1)
{
    ASSERT_NE(bundleManagerPtr_, nullptr);

    std::string bundleName = STRING_OWNER;
    AppExecFwk::BundleInfo bundleInfo;
    ErrCode result = bundleManagerPtr_->GetBundleInfo(bundleName, bundleInfo);
    EXPECT_EQ(result, ERR_OK);
}
