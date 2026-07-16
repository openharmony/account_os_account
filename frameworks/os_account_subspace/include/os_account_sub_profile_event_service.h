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

#ifndef OS_ACCOUNT_FRAMEWORKS_OS_ACCOUNT_SUBSPACE_INCLUDE_OS_ACCOUNT_SUB_PROFILE_EVENT_SERVICE_H
#define OS_ACCOUNT_FRAMEWORKS_OS_ACCOUNT_SUBSPACE_INCLUDE_OS_ACCOUNT_SUB_PROFILE_EVENT_SERVICE_H

#include <map>
#include <mutex>
#include <set>
#include "os_account_sub_profile_event_stub.h"
#include "os_account_sub_profile_subscribe_callback.h"

namespace OHOS {
namespace AccountSA {

class OsAccountSubProfileEventService : public OsAccountSubProfileEventStub {
public:
    static OsAccountSubProfileEventService* GetInstance();

    void AddTypes(const std::set<OsAccountSubProfileEventType>& types,
        const std::shared_ptr<OsAccountSubProfileSubscribeCallback> &callback);
    void DeleteCallback(const std::shared_ptr<OsAccountSubProfileSubscribeCallback> &callback);
    void GetTypesToRemove(const std::shared_ptr<OsAccountSubProfileSubscribeCallback> &callback,
        std::set<OsAccountSubProfileEventType> &removedTypes);
    void GetAllType(std::set<OsAccountSubProfileEventType> &typeList);
    bool IsAllTypeExist(const std::set<OsAccountSubProfileEventType>& types,
        const std::shared_ptr<OsAccountSubProfileSubscribeCallback> &callback);
    int32_t GetCallbackSize();

    ErrCode OnSubProfileChanged(const SubProfileEventData &eventData) override;

private:
    OsAccountSubProfileEventService();
    ~OsAccountSubProfileEventService() override;

    std::mutex mapLock_;

    std::map<std::shared_ptr<OsAccountSubProfileSubscribeCallback>,
             std::set<OsAccountSubProfileEventType>> callbackMap_;

    std::map<OsAccountSubProfileEventType,
             std::set<std::shared_ptr<OsAccountSubProfileSubscribeCallback>>> typeMap_;
};

}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_FRAMEWORKS_OS_ACCOUNT_SUBSPACE_INCLUDE_OS_ACCOUNT_SUB_PROFILE_EVENT_SERVICE_H
