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

#ifndef OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_CONSTRAINT_EVENT_LISTENER_H
#define OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_CONSTRAINT_EVENT_LISTENER_H

#include <map>
#include <set>
#include "ios_account.h"
#include "os_account_constraint_event_stub.h"
#include "os_account_constraint_subscriber.h"

namespace OHOS {
namespace AccountSA {
class OsAccountConstraintSubscriberManager : public OsAccountConstraintEventStub {
public:
    static OsAccountConstraintSubscriberManager& GetInstance();
    ErrCode OnConstraintChanged(int32_t localId, const std::set<std::string> &constraints, bool enable) override;
    ErrCode SubscribeOsAccountConstraints(const std::shared_ptr<OsAccountConstraintSubscriber> &subscriber,
        sptr<IOsAccount> &proxy);
    ErrCode UnsubscribeOsAccountConstraints(const std::shared_ptr<OsAccountConstraintSubscriber> &subscriber,
        sptr<IOsAccount> &proxy);
    void RestoreConstraintSubscriberRecords(sptr<IOsAccount> &proxy);

private:
    OsAccountConstraintSubscriberManager();
    ~OsAccountConstraintSubscriberManager() = default;
    DISALLOW_COPY_AND_MOVE(OsAccountConstraintSubscriberManager);
    bool HasSubscribed(const std::shared_ptr<OsAccountConstraintSubscriber> &subscriber);
    void InsertSubscriberRecord(const std::shared_ptr<OsAccountConstraintSubscriber> &subscriber);
    void RemoveSubscriberRecord(const std::shared_ptr<OsAccountConstraintSubscriber> &subscriber);

private:
    std::mutex mutex_;
    sptr<IOsAccount> proxy_;
    std::set<std::shared_ptr<OsAccountConstraintSubscriber>> subscriberSet_;
    std::set<std::string> constraintSet_;
    std::map<std::string, std::set<std::shared_ptr<OsAccountConstraintSubscriber>>> constraint2SubscriberMap_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_CONSTRAINT_EVENT_LISTENER_H
