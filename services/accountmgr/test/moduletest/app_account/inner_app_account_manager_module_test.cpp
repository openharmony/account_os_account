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
#include "app_account_control_manager.h"
#undef private
#include "iapp_account_control.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string STRING_NAME = "name";
const std::string STRING_EXTRA_INFO = "extra_info";
const std::string STRING_OWNER = "com.example.owner";
}  // namespace

class InnerAppAccountManagerModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;

    void DeleteKvStore(void);

    std::shared_ptr<IAppAccountControl> controlManagerPtr_;
};

void InnerAppAccountManagerModuleTest::SetUpTestCase(void)
{}

void InnerAppAccountManagerModuleTest::TearDownTestCase(void)
{}

void InnerAppAccountManagerModuleTest::SetUp(void)
{
    DeleteKvStore();
}

void InnerAppAccountManagerModuleTest::TearDown(void)
{
    DeleteKvStore();
}

void InnerAppAccountManagerModuleTest::DeleteKvStore(void)
{
    controlManagerPtr_ = AppAccountControlManager::GetInstance();
    ASSERT_NE(controlManagerPtr_, nullptr);

    auto dataStoragePtr = controlManagerPtr_->GetDataStorage();
    ASSERT_NE(dataStoragePtr, nullptr);

    ErrCode result = dataStoragePtr->DeleteKvStore();
    ASSERT_EQ(result, ERR_OK);

    dataStoragePtr = controlManagerPtr_->GetDataStorage(true);
    ASSERT_NE(dataStoragePtr, nullptr);

    result = dataStoragePtr->DeleteKvStore();
    ASSERT_EQ(result, ERR_OK);
}

/**
 * @tc.number: InnerAppAccountManager_AddAccount_0100
 * @tc.name: AddAccount
 * @tc.desc: Add an account with valid data.
 */
HWTEST_F(InnerAppAccountManagerModuleTest, InnerAppAccountManager_AddAccount_0100, Function | MediumTest | Level1)
{
    ACCOUNT_LOGI("InnerAppAccountManager_AddAccount_0100");
}
