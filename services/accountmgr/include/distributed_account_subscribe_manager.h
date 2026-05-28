/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_DISTRIBUTED_ACCOUNT_SUBSCRIBE_MANAGER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_DISTRIBUTED_ACCOUNT_SUBSCRIBE_MANAGER_H

#include <map>
#include <set>
#include "distributed_account_subscribe_callback.h"
#include "idistributed_account_event.h"
#include "idistributed_account_subscribe.h"
#include "singleton.h"

namespace OHOS {
namespace AccountSA {
class DistributedAccountSubscribeManager : public IDistributedAccountSubscribe {
public:
    static DistributedAccountSubscribeManager &GetInstance();
    ErrCode SubscribeDistributedAccountEvent(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type,
        const sptr<IRemoteObject> &eventListener) override;
    ErrCode UnsubscribeDistributedAccountEvent(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type,
        const sptr<IRemoteObject> &eventListener) override;
    ErrCode UnsubscribeDistributedAccountEvent(const sptr<IRemoteObject> &eventListener) override;
    ErrCode Publish(const int id, DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE subscribeType, int32_t subProfileId = -1) override;
    ErrCode SubscribeDistributedAccountSpaceEvents(const std::set<DistributedAccountSpaceEventType> &types,
        const sptr<IRemoteObject> &eventListener) override;
    ErrCode UnsubscribeDistributedAccountSpaceEvents(const std::set<DistributedAccountSpaceEventType> &types,
        const sptr<IRemoteObject> &eventListener) override;
    ErrCode Publish(DistributedAccountSpaceEventType eventType, int32_t localId,
        int32_t distributedAccountId, int32_t previousDistributedAccountId = -1) override;

private:
    DistributedAccountSubscribeManager();
    ~DistributedAccountSubscribeManager() = default;
    DISALLOW_COPY_AND_MOVE(DistributedAccountSubscribeManager);
    bool OnAccountsChanged(const sptr<IDistributedAccountEvent> &eventProxy,
        const int id, DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE subscribeType, const int32_t subProfileId);
    bool OnSpaceAccountsChanged(const sptr<IDistributedAccountEvent> &eventProxy,
        const DistributedAccountSpaceEventData &eventData);
    DistributedSubscribeRecordPtr FindSubscribeRecordByEventListener(const sptr<IRemoteObject> &eventListener);
    std::vector<sptr<IRemoteObject>> GetSubscribersToNotify(
        DistributedAccountSpaceEventType eventType, int32_t eventLocalId);

private:
    sptr<IRemoteObject::DeathRecipient> subscribeDeathRecipient_;
    std::mutex subscribeRecordMutex_;
    std::vector<DistributedSubscribeRecordPtr> subscribeRecords_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_DISTRIBUTED_ACCOUNT_SUBSCRIBE_MANAGER_H
