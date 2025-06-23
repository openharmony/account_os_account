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
#define private public
#define protected public
#include "os_account_activate_lock_plugin_manager.h"
#undef protected
#undef private

namespace OHOS {
using namespace testing::ext;
using namespace OHOS::AccountSA;
namespace AccountSA {
using namespace testing;
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS;
using namespace AccountSA;
namespace {
constexpr char VERIFY_ACTIVATION_LOCK[] = "VerifyActivationLock";
}

class OsAccountActivateLockPluginManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    static int32_t MockVerifySuccess(std::function<int32_t(bool)> callback)
    {
        callback(true);
        return ERR_OK;
    }

    static int32_t MockVerifyError(std::function<int32_t(bool)>)
    {
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_LOCK_ERROR;
    }

    static int32_t MockVerifySuccessFalse(std::function<int32_t(bool)> callback)
    {
        callback(false);
        return ERR_OK;
    }
};

void OsAccountActivateLockPluginManagerTest::SetUpTestCase(void)
{
}

void OsAccountActivateLockPluginManagerTest::TearDownTestCase(void)
{}

void OsAccountActivateLockPluginManagerTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void OsAccountActivateLockPluginManagerTest::TearDown(void)
{}

/**
 * @tc.name: PluginVerifyActivationLockFunc_0001
 * @tc.desc: There is no corresponding function symbol in methodMap.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountActivateLockPluginManagerTest, PluginVerifyActivationLockFunc_0001, TestSize.Level3)
{
    bool isAllowed = false;
    OsAccountActivateLockPluginManager::GetInstance().methodMap_.clear();
    ErrCode ret = OsAccountActivateLockPluginManager::GetInstance().PluginVerifyActivationLockFunc(isAllowed);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_PLUGIN_NOT_EXIST_ERROR);
}

/**
 * @tc.name: PluginVerifyActivationLockFunc_0002
 * @tc.desc: There are keys in the methodMap but the function pointer is empty.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountActivateLockPluginManagerTest, PluginVerifyActivationLockFunc_0002, TestSize.Level3)
{
    bool isAllowed = false;
    OsAccountActivateLockPluginManager::GetInstance().methodMap_.clear();
    OsAccountActivateLockPluginManager::GetInstance().methodMap_[VERIFY_ACTIVATION_LOCK] = nullptr;

    ErrCode ret = OsAccountActivateLockPluginManager::GetInstance().PluginVerifyActivationLockFunc(isAllowed);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_PLUGIN_NOT_EXIST_ERROR);
}

/**
 * @tc.name: PluginVerifyActivationLockFunc_0003
 * @tc.desc: The plug-in function returns a non-success error code.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountActivateLockPluginManagerTest, PluginVerifyActivationLockFunc_0003, TestSize.Level3)
{
    bool isAllowed = false;
    OsAccountActivateLockPluginManager::GetInstance().methodMap_.clear();
    OsAccountActivateLockPluginManager::GetInstance().methodMap_[VERIFY_ACTIVATION_LOCK] =
        reinterpret_cast<int32_t*>(MockVerifyError);

    ErrCode ret = OsAccountActivateLockPluginManager::GetInstance().PluginVerifyActivationLockFunc(isAllowed);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_LOCK_ERROR);
}

/**
 * @tc.name: PluginVerifyActivationLockFunc_0004
 * @tc.desc: The plugin executes normally and returns true.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountActivateLockPluginManagerTest, PluginVerifyActivationLockFunc_0004, TestSize.Level3)
{
    bool isAllowed = false;
    OsAccountActivateLockPluginManager::GetInstance().methodMap_.clear();
    OsAccountActivateLockPluginManager::GetInstance().methodMap_[VERIFY_ACTIVATION_LOCK] =
        reinterpret_cast<int32_t*>(MockVerifySuccess);

    ErrCode ret = OsAccountActivateLockPluginManager::GetInstance().PluginVerifyActivationLockFunc(isAllowed);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(isAllowed);
}

/**
 * @tc.name: PluginVerifyActivationLockFunc_0005
 * @tc.desc: The plugin executes normally and returns false.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountActivateLockPluginManagerTest, PluginVerifyActivationLockFunc_0005, TestSize.Level3)
{
    bool isAllowed = true;
    OsAccountActivateLockPluginManager::GetInstance().methodMap_.clear();
    OsAccountActivateLockPluginManager::GetInstance().methodMap_[VERIFY_ACTIVATION_LOCK] =
        reinterpret_cast<int32_t*>(MockVerifySuccessFalse);

    ErrCode ret = OsAccountActivateLockPluginManager::GetInstance().PluginVerifyActivationLockFunc(isAllowed);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(isAllowed);
}
}
}