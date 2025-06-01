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
#include "os_account_event_stub.h"
#include "os_account_contraint_subscriber.h"

namespace OHOS {
namespace AccountSA {
class OsAccountConstraintEventListener : public OsAccountConstraintEventStub {
public:
    static OsAccountConstraintEventListener* GetInstance();
    ErrCode OnConstraintChanged(int localId, const std::set<std::string> &constraints, bool enable) override;
    bool HasSubscribed(const std::shared_ptr<OsAccountConstraintSubscriber> &subscriber);
    bool IsNeedDataSync(const std::shared_ptr<OsAccountConstraintSubscriber> &subscriber);
    void InsertSubscriberRecord(const std::shared_ptr<OsAccountConstraintSubscriber> &subscriber);
    void RemoveSubscriberRecord(const std::shared_ptr<OsAccountConstraintSubscriber> &subscriber);
    void GetAllConstraintSubscribeInfos(OsAccountConstraintSubscribeInfo &osAccountConstraintSubscribeInfo);
private:
    OsAccountConstraintEventListener();
    ~OsAccountConstraintEventListener() = default;
    DISALLOW_COPY_AND_MOVE(OsAccountConstraintEventListener);
private:
    std::mutex mutex_;
    std::set<std::shared_ptr<OsAccountConstraintSubscriber>> subscriberSet_;
    std::set<std::string> constraintSet_;
    std::map<std::string, std::set<std::shared_ptr<OsAccountConstraintSubscriber>>> constraint2SubscriberMap_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_CONSTRAINT_EVENT_LISTENER_H
