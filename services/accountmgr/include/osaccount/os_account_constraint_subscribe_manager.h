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

#ifndef OS_ACCOUNT_CONSTRAINT_SUBSCRIBE_MANAGER_H
#define OS_ACCOUNT_CONSTRAINT_SUBSCRIBE_MANAGER_H

#include <map>
#include <set>
#include "ios_account_subscribe.h"

namespace OHOS {
namespace AccountSA {
class OsAccountConstraintSubscribeManager {
public:
    static OsAccountConstraintSubscribeManager &GetInstance();
    ErrCode SubscribeOsAccountConstraints(int32_t localId, const std::set<std::string> &constraints,
        const sptr<IRemoteObject> &eventListener);
    ErrCode SubscribeOsAccountConstraints(const std::set<std::string> &constraints,
        const sptr<IRemoteObject> &eventListener);
    ErrCode UnsubscribeOsAccountConstraints(const std::set<std::string> &constraints,
        const sptr<IRemoteObject> &eventListener);
    ErrCode UnsubscribeOsAccountConstraints(int32_t localId, const std::set<std::string> &constraints,
        const sptr<IRemoteObject> &eventListener);
    ErrCode UnsubscribeOsAccountConstraints(const sptr<IRemoteObject> &eventListener);
    void Publish(int32_t localId, const std::set<std::string> &constraints, const bool isEnabled);

private:
    OsAccountConstraintSubscribeManager();
    ~OsAccountConstraintSubscribeManager() = default;
    DISALLOW_COPY_AND_MOVE(OsAccountConstraintSubscribeManager);
    void RemoveConstraintFromSubscribeRecord(const OsAccountConstraintSubscribeRecordPtr &recordPtr,
        const std::set<std::string> &constraints);
    void InsertSubscribeRecord(const OsAccountConstraintSubscribeRecordPtr &recordPtr);
    void PublishToSubscriber(const OsAccountConstraintSubscribeRecordPtr &recordPtr, int32_t localId,
        const std::set<std::string> &constraints, bool isEnabled);

private:
    std::mutex mutex_;
    sptr<IRemoteObject::DeathRecipient> subscribeDeathRecipient_;
    std::set<OsAccountConstraintSubscribeRecordPtr> constraintRecords_;
    std::map<sptr<IRemoteObject>, int32_t> userListenerMap_;
    std::map<std::string, std::set<OsAccountConstraintSubscribeRecordPtr>> constraint2RecordMap_;
};
} // AccountSA
} // OHOS
#endif //OS_ACCOUNT_CONSTRAINT_SUBSCRIBE_MANAGER_H