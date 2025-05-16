/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_FRAMEWORKS_OHOSACCOUNT_NATIVE_INCLUDE_DISTRUBUTED_ACCOUNT_EVENT_SERVICE_H
#define OS_ACCOUNT_FRAMEWORKS_OHOSACCOUNT_NATIVE_INCLUDE_DISTRUBUTED_ACCOUNT_EVENT_SERVICE_H

#include "distributed_account_event_stub.h"
#include <set>
#include <map>

namespace OHOS {
namespace AccountSA {
class DistributedAccountEventService : public DistributedAccountEventStub {
public:
    explicit DistributedAccountEventService();
    ~DistributedAccountEventService() override;
    bool IsTypeExist(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type,
        const std::shared_ptr<DistributedAccountSubscribeCallback> &callback);
    void AddType(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type,
        const std::shared_ptr<DistributedAccountSubscribeCallback> &callback);
    void DeleteType(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type,
        const std::shared_ptr<DistributedAccountSubscribeCallback> &callback);
    void GetAllType(std::set<DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE> &typeList);
    int32_t GetCallbackSize();

    void OnAccountsChanged(const DistributedAccountEventData &eventData) override;
    static DistributedAccountEventService *GetInstance();

private:
    std::mutex mapLock_;
    std::map<std::shared_ptr<DistributedAccountSubscribeCallback>,
        std::set<DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE>> callbackMap_;

    std::map<DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE,
        std::set<std::shared_ptr<DistributedAccountSubscribeCallback>>> TypeMap_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_FRAMEWORKS_OHOSACCOUNT_NATIVE_INCLUDE_DISTRUBUTED_ACCOUNT_EVENT_SERVICE_H
