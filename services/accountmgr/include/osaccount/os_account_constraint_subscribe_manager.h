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
#include "ios_account_event.h"
#include "ios_account_subscribe.h"

namespace OHOS {
namespace AccountSA {
class OsAccountConstraintSubscribeManager : public IConstraintSubscribe  {
public:
    static OsAccountConstraintSubscribeManager &GetInstance();
    ErrCode SubscribeConstraints(const std::set<std::string> &constraints,
        const sptr<IRemoteObject> &eventListener) override;
    ErrCode UnsubscribeConstraints(const std::set<std::string> &constraints,
        const sptr<IRemoteObject> &eventListener) override;
    ErrCode UnsubscribeConstraints(const sptr<IRemoteObject> &eventListener) override;
    void Publish(int32_t localId, const std::set<std::string> &oldConstraints,
        const std::set<std::string> &newConstraints, const bool enable) override;

private:
    OsAccountConstraintSubscribeManager();
    ~OsAccountConstraintSubscribeManager() = default;
    DISALLOW_COPY_AND_MOVE(OsAccountConstraintSubscribeManager);
    void Publish(int32_t localId, const std::set<std::string> &constraints, const bool enable);
    void RemoveSubscribeRecord(const ConstraintRecordPtr &recordPtr,
        const std::set<std::string> &constraints);
    void InsertSubscribeRecord(const ConstraintRecordPtr &recordPtr);
    void PublishToSubsriber(const ConstraintRecordPtr &recordPtr, int32_t localId,
        const std::set<std::string> &constraints, bool enable);

private:
    std::mutex mutex_;
    sptr<IRemoteObject::DeathRecipient> subscribeDeathRecipient_;
    std::set<ConstraintRecordPtr> constraintRecords_;
    std::map<std::string, std::set<ConstraintRecordPtr>> constraint2RecordMap_;
};
} // AccountSA
} // OHOS
#endif //OS_ACCOUNT_CONSTRAINT_SUBSCRIBE_MANAGER_H