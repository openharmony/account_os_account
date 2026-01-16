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

#include "os_account_static_subscriber_manager.h"

#include <cinttypes>
#include <dlfcn.h>
#include <thread>
#include <pthread.h>
#include "account_constants.h"
#include "account_log_wrapper.h"
#include "account_hisysevent_adapter.h"
#ifdef HICOLLIE_ENABLE
#include "account_timer.h"
#include "xcollie/xcollie.h"
#endif // HICOLLIE_ENABLE

namespace OHOS {
namespace AccountSA {
namespace {
#ifdef _ARM64_
static const std::string ROOT_LIB_PATH = "/system/lib64/";
#else
static const std::string ROOT_LIB_PATH = "/system/lib/";
#endif
}

StaticSubscriber::~StaticSubscriber()
{
    callback = nullptr;
    if (handle != nullptr) {
        dlclose(handle);
        handle = nullptr;
    }
}

OsAccountStaticSubscriberManager::OsAccountStaticSubscriberManager()
{
    std::map<OsAccountState, std::set<std::string>> defaultConfig;
    defaultConfig[OsAccountState::CREATING] = { ROOT_LIB_PATH + "libtheme_manager_client.z.so" };
    Init(defaultConfig);
}

OsAccountStaticSubscriberManager &OsAccountStaticSubscriberManager::GetInstance()
{
    static OsAccountStaticSubscriberManager instance;
    return instance;
}

void OsAccountStaticSubscriberManager::Init(
    const std::map<OsAccountState, std::set<std::string>> &staticSubscriberConfig)
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto &it : staticSubscriberConfig) {
        std::set<std::shared_ptr<StaticSubscriber>> subscribers;
        for (const auto &path : it.second) {
            auto subscriber = ParseStaticSubscriber(path);
            if (subscriber != nullptr) {
                subscribers.insert(subscriber);
            }
        }
        if (!subscribers.empty()) {
            state2Subscribers_[it.first] = subscribers;
        }
    }
}

std::shared_ptr<StaticSubscriber> OsAccountStaticSubscriberManager::ParseStaticSubscriber(const std::string &path)
{
    auto subIt = staticSubscribers_.find(path);
    if (subIt != staticSubscribers_.end()) {
        ACCOUNT_LOGE("Subscriber already exists");
        return subIt->second;
    }
    void* handle = dlopen(path.c_str(), RTLD_LAZY);
    if (handle == nullptr) {
        auto errMsg = dlerror();
        ACCOUNT_LOGE("Failed to dlopen, path: %{public}s, error: %{public}s", path.c_str(), errMsg);
        REPORT_OS_ACCOUNT_FAIL(0, Constants::OPERATION_EVENT_PUBLISH, ERR_ACCOUNT_COMMON_DLOPEN_ERROR,
            "Failed to dlopen, path: " + path + ", error: " + (errMsg ? std::string(errMsg) : ""));
        return nullptr;
    }
    void *func = dlsym(handle, "OnOsAccountStateChanged");
    if (func == nullptr) {
        auto errMsg = dlerror();
        ACCOUNT_LOGE("Failed to dlsym, path: %{public}s, error=%{public}s", path.c_str(), errMsg);
        REPORT_OS_ACCOUNT_FAIL(0, Constants::OPERATION_EVENT_PUBLISH, ERR_ACCOUNT_COMMON_DLSYM_ERROR,
            "Failed to dlsym, path: " + path + ", error: " + (errMsg ? std::string(errMsg) : ""));
        dlclose(handle);
        handle = nullptr;
        return nullptr;
    }
    auto subscriber = std::make_shared<StaticSubscriber>();
    subscriber->path = path;
    subscriber->handle = handle;
    subscriber->callback = func;
    staticSubscribers_[path] = subscriber;
    ACCOUNT_LOGI("Parse static subscriber successfully, path: %{public}s", path.c_str());
    return subscriber;
}

ErrCode OsAccountStaticSubscriberManager::PublishToSubscriber(
    const std::shared_ptr<StaticSubscriber> &subscriber, const COsAccountStateData &data)
{
    if (subscriber == nullptr || subscriber->callback == nullptr) {
        ACCOUNT_LOGE("Invalid subscriber");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    ACCOUNT_LOGI(
        "State: %{public}d, fromId: %{public}d, toId: %{public}d, displayId: %{public}llu, subscriberPath: %{public}s",
        data.state, data.fromId, data.toId, static_cast<unsigned long long>(data.displayId), subscriber->path.c_str());
#ifdef HICOLLIE_ENABLE
    AccountTimer timer;
#endif
    // Callback will be invalid when the singleton destroyed (i.e. the process exits), so lock protection is not added,
    // otherwise it will increase performance overhead
    return (*reinterpret_cast<OnOsAccountStateChangedFunc>(subscriber->callback))(&data);
}

ErrCode OsAccountStaticSubscriberManager::Publish(int32_t fromId, OsAccountState state,
    int32_t toId, uint64_t displayId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = state2Subscribers_.find(state);
    if (it == state2Subscribers_.end()) {
        ACCOUNT_LOGI("No subscriber, state: %{public}d", state);
        return ERR_OK;
    }
    for (const std::shared_ptr<StaticSubscriber> &subscriber : it->second) {
        if (subscriber == nullptr) {
            ACCOUNT_LOGE("Subscriber is nullptr");
            continue;
        }
        auto task = [subscriber, state, fromId, toId, displayId] {
            COsAccountStateData data;
            data.fromId = fromId;
            data.state = state;
            data.toId = toId;
            data.displayId = displayId;

            ErrCode errCode = PublishToSubscriber(subscriber, data);
            if (errCode != ERR_OK) {
                ACCOUNT_LOGE("Failed to publish to subscriber, path=%{public}s, state=%{public}d, fromId=%{public}d, "
                    "toId=%{public}d, displayId=%{public}llu, errCode=%{public}d",
                    subscriber->path.c_str(), state, fromId, toId, static_cast<unsigned long long>(displayId), errCode);
                REPORT_OS_ACCOUNT_FAIL(data.toId, Constants::OPERATION_EVENT_PUBLISH, errCode,
                    "Failed to publish to subscriber, path=" + subscriber->path + ", state=" + std::to_string(state) +
                    ", fromId=" + std::to_string(fromId) + ", toId=" + std::to_string(toId) +
                    ", displayId=" + std::to_string(displayId));
            }
        };
        std::thread publishThread(task);
        pthread_setname_np(publishThread.native_handle(), "StaticPublish");
        publishThread.detach();
    }
    return ERR_OK;
}
} // AccountSA
} // OHOS
