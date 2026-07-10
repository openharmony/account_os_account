/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OS_ACCOUNT_SUB_PROFILE_SUBSCRIBE_MANAGER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OS_ACCOUNT_SUB_PROFILE_SUBSCRIBE_MANAGER_H

#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <vector>
#include "ios_account_sub_profile_event.h"
#include "os_account_sub_profile_subscribe_callback.h"

namespace OHOS {
namespace AccountSA {

struct OsAccountSubProfileSubscribeRecord {
    sptr<IRemoteObject> eventListener_;
    std::set<OsAccountSubProfileEventType> types_;
    int32_t localId_ = -1;
    bool isNotifyAllUsers_ = false;

    OsAccountSubProfileSubscribeRecord() : eventListener_(nullptr), localId_(-1), isNotifyAllUsers_(false) {}
    OsAccountSubProfileSubscribeRecord(sptr<IRemoteObject> eventListener, int32_t localId = -1,
        bool isNotifyAllUsers = false)
        : eventListener_(eventListener), localId_(localId), isNotifyAllUsers_(isNotifyAllUsers) {}

    void AddTypes(const std::set<OsAccountSubProfileEventType> &newTypes);
    void RemoveTypes(const std::set<OsAccountSubProfileEventType> &types);
};

using OsAccountSubProfileSubscribeRecordPtr = std::shared_ptr<OsAccountSubProfileSubscribeRecord>;

class OsAccountSubProfileSubscribeManager {
public:
    static OsAccountSubProfileSubscribeManager& GetInstance();

    ErrCode SubscribeOsAccountSubProfileEvents(
        const std::set<OsAccountSubProfileEventType> &types,
        const sptr<IRemoteObject> &eventListener);

    ErrCode UnsubscribeOsAccountSubProfileEvents(
        const std::set<OsAccountSubProfileEventType> &types,
        const sptr<IRemoteObject> &eventListener);

    ErrCode UnsubscribeOsAccountSubProfileEvents(
        const sptr<IRemoteObject> &eventListener);

    ErrCode Publish(
        OsAccountSubProfileEventType eventType,
        int32_t localId,
        int32_t subProfileId,
        int32_t previousSubProfileId = -1);

private:
    OsAccountSubProfileSubscribeManager();
    ~OsAccountSubProfileSubscribeManager() = default;
    DISALLOW_COPY_AND_MOVE(OsAccountSubProfileSubscribeManager);

    bool OnSubProfileChanged(
        const sptr<IOsAccountSubProfileEvent> &eventProxy,
        const SubProfileEventData &eventData);

    OsAccountSubProfileSubscribeRecordPtr FindSubscribeRecordByEventListener(
        const sptr<IRemoteObject> &eventListener);

    std::vector<sptr<IRemoteObject>> GetSubscribersToNotify(
        OsAccountSubProfileEventType eventType, int32_t eventLocalId);

    sptr<IRemoteObject::DeathRecipient> subscribeDeathRecipient_;
    std::mutex subscribeRecordMutex_;
    std::vector<OsAccountSubProfileSubscribeRecordPtr> subscribeRecords_;
};

}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OS_ACCOUNT_SUB_PROFILE_SUBSCRIBE_MANAGER_H
