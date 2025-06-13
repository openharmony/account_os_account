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
#include "dlfcn.h"
#include "account_log_wrapper.h"
#define private public
#include "os_account_static_subscriber_manager.h"
#undef private

namespace OHOS {
namespace AccountSA {
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS;
using namespace AccountSA;
namespace {
constexpr int32_t TEST_ACCOUNT_ID = 101;
const std::string INVALID_SO_PATH = "invalid.z.so";
const std::string VALID_WITH_TARGET_SYMBOL_SO_PATH = "valid_with_target_symbol.z.so";
const std::string VALID_WITHOUT_TARGET_SYMBOL_SO_PATH = "valid_without_target_symbol.z.so";
}
#ifdef __cplusplus
extern "C" {
#endif
static bool g_withSymbol = true;
static bool g_withoutSymbol = false;
static void* g_ptrWithSymbol = &g_withSymbol;
static void* g_ptrWithoutSymbol = &g_withoutSymbol;

int dlclose(void *handle)
{
    if (handle == nullptr) {
        ACCOUNT_LOGI("Handle is null.");
        errno = 1;
        return -1;
    }
    errno = 0;
    return 0;
}

char *dlerror(void)
{
    if (errno == 0) {
        return nullptr;
    }
    errno = 0;
    return const_cast<char *>("Failed to dlopen or dlsym");
}

int32_t OnOsAccountStateChanged(const COsAccountStateData *stateData)
{
    if (stateData->state == OsAccountState::CREATING) {
        return 0;
    }
    return -1;
}

void *dlsym(void *__restrict handle, const char *__restrict symbol)
{
    if (handle != nullptr && *(reinterpret_cast<bool *>(handle))) {
        ACCOUNT_LOGI("Dlsym successfully, symbol:  %{public}s", symbol);
        return reinterpret_cast<void *>(OnOsAccountStateChanged);
    }
    ACCOUNT_LOGE("Invalid symbol: %{public}s", symbol);
    return nullptr;
}

void *dlopen(const char* path, int flag)
{
    if (strcmp(path, VALID_WITH_TARGET_SYMBOL_SO_PATH.c_str()) == 0) {
        ACCOUNT_LOGI("Dlopen successfully, path: %{public}s", VALID_WITH_TARGET_SYMBOL_SO_PATH.c_str());
        return g_ptrWithSymbol;
    }
    if (strcmp(path, VALID_WITHOUT_TARGET_SYMBOL_SO_PATH.c_str()) == 0) {
        ACCOUNT_LOGI("Dlopen successfully, path: %{public}s", VALID_WITHOUT_TARGET_SYMBOL_SO_PATH.c_str());
        return g_ptrWithoutSymbol;
    }
    ACCOUNT_LOGE("Dlopen failed");
    return nullptr;
}
#ifdef __cplusplus
}
#endif

class OsAccountStaticSubscriberManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
    void SetUp();
    void TearDown() {};
};

void OsAccountStaticSubscriberManagerTest::SetUp()
{
    OsAccountStaticSubscriberManager::GetInstance().staticSubscribers_.clear();
    OsAccountStaticSubscriberManager::GetInstance().state2Subscribers_.clear();
}

/**
 * @tc.name: Publish001
 * @tc.desc: Test when target subscriber set is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountStaticSubscriberManagerTest, Publish001, TestSize.Level1)
{
    auto& manager = OsAccountStaticSubscriberManager::GetInstance();
    EXPECT_EQ(manager.state2Subscribers_.find(OsAccountState::CREATED), manager.state2Subscribers_.end());
    EXPECT_EQ(ERR_OK, manager.Publish(TEST_ACCOUNT_ID, OsAccountState::CREATED, TEST_ACCOUNT_ID));
}

/**
 * @tc.name: Publish002
 * @tc.desc: Test when target subscriber set not empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountStaticSubscriberManagerTest, Publish002, TestSize.Level1)
{
    auto& manager = OsAccountStaticSubscriberManager::GetInstance();
    auto subscriber = std::make_shared<StaticSubscriber>();
    subscriber->handle = g_ptrWithSymbol;
    subscriber->callback = reinterpret_cast<void *>(OnOsAccountStateChanged);
    manager.state2Subscribers_[OsAccountState::CREATING] = { subscriber, nullptr };
    EXPECT_NE(manager.state2Subscribers_.find(OsAccountState::CREATING), manager.state2Subscribers_.end());
    EXPECT_EQ(ERR_OK, manager.Publish(TEST_ACCOUNT_ID, OsAccountState::CREATING, TEST_ACCOUNT_ID));
    manager.state2Subscribers_[OsAccountState::CREATED] = {};
    EXPECT_NE(manager.state2Subscribers_.find(OsAccountState::CREATED), manager.state2Subscribers_.end());
    EXPECT_EQ(ERR_OK, manager.Publish(TEST_ACCOUNT_ID, OsAccountState::CREATED, TEST_ACCOUNT_ID));
}

/**
 * @tc.name: PublishToSubscriber001
 * @tc.desc: Fail to publish with invalid parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountStaticSubscriberManagerTest, PublishToSubscriber001, TestSize.Level1)
{
    COsAccountStateData data;
    EXPECT_EQ(OsAccountStaticSubscriberManager::GetInstance().PublishToSubscriber(nullptr, data),
        ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    auto subscriber = std::make_shared<StaticSubscriber>();
    EXPECT_EQ(OsAccountStaticSubscriberManager::GetInstance().PublishToSubscriber(subscriber, data),
        ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: PublishToSubscriber002
 * @tc.desc: Publish successfully, but callback failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountStaticSubscriberManagerTest, PublishToSubscriber002, TestSize.Level1)
{
    COsAccountStateData data;
    data.state = OsAccountState::CREATED;
    auto subscriber = std::make_shared<StaticSubscriber>();
    subscriber->callback = reinterpret_cast<void *>(OnOsAccountStateChanged);
    EXPECT_EQ(OsAccountStaticSubscriberManager::GetInstance().PublishToSubscriber(subscriber, data), -1);
}

/**
 * @tc.name: PublishToSubscriber003
 * @tc.desc: Publish and callback successfully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountStaticSubscriberManagerTest, PublishToSubscriber003, TestSize.Level1)
{
    COsAccountStateData data;
    data.state = OsAccountState::CREATING;
    auto subscriber = std::make_shared<StaticSubscriber>();
    subscriber->callback = reinterpret_cast<void *>(OnOsAccountStateChanged);
    EXPECT_EQ(OsAccountStaticSubscriberManager::GetInstance().PublishToSubscriber(subscriber, data), ERR_OK);
}

/**
 * @tc.name: ParseStaticSubscriber001
 * @tc.desc: Parse invalid subscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountStaticSubscriberManagerTest, ParseStaticSubscriber001, TestSize.Level1)
{
    auto &manager = OsAccountStaticSubscriberManager::GetInstance();
    EXPECT_EQ(manager.ParseStaticSubscriber(INVALID_SO_PATH), nullptr);
    EXPECT_EQ(manager.ParseStaticSubscriber(VALID_WITHOUT_TARGET_SYMBOL_SO_PATH), nullptr);
}

/**
 * @tc.name: ParseStaticSubscriber002
 * @tc.desc: Parse duplicated subscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountStaticSubscriberManagerTest, ParseStaticSubscriber002, TestSize.Level1)
{
    auto &manager = OsAccountStaticSubscriberManager::GetInstance();
    auto subscriber = std::make_shared<StaticSubscriber>();
    manager.staticSubscribers_[VALID_WITH_TARGET_SYMBOL_SO_PATH] = subscriber;
    EXPECT_EQ(manager.ParseStaticSubscriber(VALID_WITH_TARGET_SYMBOL_SO_PATH), subscriber);
}

/**
 * @tc.name: ParseStaticSubscriber003
 * @tc.desc: Parse valid subscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountStaticSubscriberManagerTest, ParseStaticSubscriber003, TestSize.Level1)
{
    auto &manager = OsAccountStaticSubscriberManager::GetInstance();
    auto subscriber = manager.ParseStaticSubscriber(VALID_WITH_TARGET_SYMBOL_SO_PATH);
    EXPECT_NE(subscriber, nullptr);
    EXPECT_EQ(subscriber->callback, reinterpret_cast<void *>(OnOsAccountStateChanged));
}

/**
 * @tc.name: Init001
 * @tc.desc: Init subscriber with config
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountStaticSubscriberManagerTest, Init001, TestSize.Level1)
{
    auto &manager = OsAccountStaticSubscriberManager::GetInstance();
    EXPECT_EQ(manager.staticSubscribers_.size(), 0);
    std::map<OsAccountState, std::set<std::string>> config;
    manager.Init(config);
    EXPECT_EQ(manager.staticSubscribers_.size(), 0);
    config[OsAccountState::CREATING] = { VALID_WITH_TARGET_SYMBOL_SO_PATH, VALID_WITHOUT_TARGET_SYMBOL_SO_PATH};
    manager.Init(config);
    EXPECT_EQ(manager.staticSubscribers_.size(), 1);
    EXPECT_EQ(manager.state2Subscribers_.size(), 1);
    auto it = manager.state2Subscribers_.find(OsAccountState::CREATING);
    ASSERT_NE(it, manager.state2Subscribers_.end());
    EXPECT_EQ(it->second.size(), 1);
}
} // AccountSA
} // OHOS
