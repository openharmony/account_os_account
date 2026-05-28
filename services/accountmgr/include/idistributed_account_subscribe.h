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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_IDISTRIBUTED_ACCOUNT_SUBSCRIBE_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_IDISTRIBUTED_ACCOUNT_SUBSCRIBE_H

#include "account_error_no.h"
#include "distributed_account_subscribe_callback.h"
#include "iremote_object.h"

namespace OHOS {
namespace AccountSA {
struct DistributedSubscribeRecord {
    sptr<IRemoteObject> eventListener_;
    std::set<DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE> types_;
    std::set<DistributedAccountSpaceEventType> spaceTypes_;
    int32_t localId_ = -1;
    bool isSaCall_ = false;

    DistributedSubscribeRecord() : eventListener_(nullptr), localId_(-1), isSaCall_(false)
    {}
    DistributedSubscribeRecord(sptr<IRemoteObject> eventListener, int32_t localId = -1, bool isSaCall = false)
        : eventListener_(eventListener), localId_(localId), isSaCall_(isSaCall)
    {}

    void AddSpaceTypes(const std::set<DistributedAccountSpaceEventType> &newTypes);
    void RemoveSpaceTypes(const std::set<DistributedAccountSpaceEventType> &types);
};

using DistributedSubscribeRecordPtr = std::shared_ptr<DistributedSubscribeRecord>;

class IDistributedAccountSubscribe {
public:
    virtual ErrCode SubscribeDistributedAccountEvent(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type,
        const sptr<IRemoteObject> &eventListener) = 0;
    virtual ErrCode UnsubscribeDistributedAccountEvent(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type,
        const sptr<IRemoteObject> &eventListener) = 0;
    virtual ErrCode UnsubscribeDistributedAccountEvent(const sptr<IRemoteObject> &eventListener) = 0;
    virtual ErrCode SubscribeDistributedAccountSpaceEvents(const std::set<DistributedAccountSpaceEventType> &types,
        const sptr<IRemoteObject> &eventListener) = 0;
    virtual ErrCode UnsubscribeDistributedAccountSpaceEvents(const std::set<DistributedAccountSpaceEventType> &types,
        const sptr<IRemoteObject> &eventListener) = 0;
    virtual ErrCode Publish(const int id, DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE subscribeType,
        int32_t subProfileId = -1) = 0;

    virtual ErrCode Publish(DistributedAccountSpaceEventType eventType, int32_t localId,
        int32_t distributedAccountId, int32_t previousDistributedAccountId = -1) = 0;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_IDISTRIBUTED_ACCOUNT_SUBSCRIBE_H
