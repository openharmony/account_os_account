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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OS_ACCOUNT_STATIC_SUBSCRIBER_MANAGER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OS_ACCOUNT_STATIC_SUBSCRIBER_MANAGER_H

#include <map>
#include <mutex>
#include "account_error_no.h"
#include "os_account_subscribe_info.h"

namespace OHOS {
namespace AccountSA {
struct StaticSubscriber {
    ~StaticSubscriber();
    std::string path;
    void *handle = nullptr;
    void *callback = nullptr;
};

class OsAccountStaticSubscriberManager {
public:
    static OsAccountStaticSubscriberManager& GetInstance();
    ErrCode Publish(int32_t fromId, OsAccountState state, int32_t toId);

private:
    OsAccountStaticSubscriberManager();
    ~OsAccountStaticSubscriberManager() = default;
    void Init(const std::map<OsAccountState, std::set<std::string>> &staticSubscriberConfig);
    std::shared_ptr<StaticSubscriber> ParseStaticSubscriber(const std::string &path);
    static ErrCode PublishToSubscriber(
        const std::shared_ptr<StaticSubscriber> &subscriber, const COsAccountStateData &data);
    DISALLOW_COPY_AND_MOVE(OsAccountStaticSubscriberManager);

private:
    std::mutex mutex_;
    std::map<std::string, std::shared_ptr<StaticSubscriber>> staticSubscribers_;
    std::map<OsAccountState, std::set<std::shared_ptr<StaticSubscriber>>> state2Subscribers_;
};
} // AccountSA
} // OHOS
#endif // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OS_ACCOUNT_STATIC_SUBSCRIBER_MANAGER_H
