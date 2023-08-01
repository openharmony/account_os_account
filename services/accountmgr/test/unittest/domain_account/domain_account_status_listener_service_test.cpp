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

#include <cerrno>
#include <gtest/gtest.h>
#define private public
#include "domain_account_callback_service.h"
#include "domain_account_status_listener_service.h"
#include "status_listener_manager.h"
#undef private
using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
} // namespace

class DomainAccountStatusListenerManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DomainAccountStatusListenerManagerTest::SetUpTestCase(void)
{}

void DomainAccountStatusListenerManagerTest::TearDownTestCase(void)
{}

void DomainAccountStatusListenerManagerTest::SetUp(void)
{}

void DomainAccountStatusListenerManagerTest::TearDown(void)
{}

/**
 * @tc.name: DomainAccountStatusListenerManagerTest_InsertListenerToRecords_001
 * @tc.desc: listener is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountStatusListenerManagerTest, DomainAccountStatusListenerManagerTest_InsertListenerToRecords_001,
    TestSize.Level0)
{
    EXPECT_EQ(StatusListenerManager::GetInstance().InsertListenerToRecords(nullptr), ERR_ACCOUNT_COMMON_NULL_PTR_ERROR);
}

/**
 * @tc.name: DomainAccountStatusListenerManagerTest_InsertListenerToRecords_002
 * @tc.desc: listener is already exit.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountStatusListenerManagerTest, DomainAccountStatusListenerManagerTest_InsertListenerToRecords_002,
    TestSize.Level0)
{
    std::shared_ptr<DomainAccountCallback> callbackPtr = nullptr;
    auto callback = new (std::nothrow) DomainAccountCallbackService(callbackPtr);
    EXPECT_NE(callback, nullptr);
    StatusListenerManager::GetInstance().listenerAll_.insert(callback->AsObject());
    EXPECT_EQ(StatusListenerManager::GetInstance().InsertListenerToRecords(callback), ERR_OK);
}

/**
 * @tc.name: DomainAccountStatusListenerManagerTest_InsertListenerToRecords_003
 * @tc.desc: listener is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountStatusListenerManagerTest, DomainAccountStatusListenerManagerTest_InsertListenerToRecords_003,
    TestSize.Level0)
{
    EXPECT_EQ(StatusListenerManager::GetInstance().InsertListenerToRecords("test", "test", nullptr),
        ERR_ACCOUNT_COMMON_NULL_PTR_ERROR);
}

/**
 * @tc.name: DomainAccountStatusListenerManagerTest_InsertListenerToRecords_004
 * @tc.desc: listener is already exit.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountStatusListenerManagerTest, DomainAccountStatusListenerManagerTest_InsertListenerToRecords_004,
    TestSize.Level0)
{
    std::shared_ptr<DomainAccountCallback> callbackPtr = nullptr;
    auto callback = new (std::nothrow) DomainAccountCallbackService(callbackPtr);
    EXPECT_NE(callback, nullptr);
    std::set<std::string> set;
    set.insert("test&test");
    StatusListenerManager::GetInstance().listenerToAccount_[callback->AsObject()] = set;
    EXPECT_EQ(StatusListenerManager::GetInstance().InsertListenerToRecords("test", "test", callback), ERR_OK);
}

/**
 * @tc.name: DomainAccountStatusListenerManagerTest_RemoveListenerByInfoAndListener_001
 * @tc.desc: listener is not exit.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DomainAccountStatusListenerManagerTest,
    DomainAccountStatusListenerManagerTest_RemoveListenerByInfoAndListener_001, TestSize.Level0)
{
    EXPECT_EQ(StatusListenerManager::GetInstance().RemoveListenerByInfoAndListener("test", "test", nullptr), ERR_OK);
}