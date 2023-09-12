/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_STATUS_LISTENER_MANAGER_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_STATUS_LISTENER_MANAGER_H

#include <map>
#include <mutex>
#include <set>
#include <vector>

#include "domain_account_common.h"
#include "idomain_account_callback.h"

namespace OHOS {
namespace AccountSA {
class StatusListenerManager {
private:
    virtual ~StatusListenerManager();
    StatusListenerManager();
    DISALLOW_COPY_AND_MOVE(StatusListenerManager);

public:
    static StatusListenerManager& GetInstance();
    ErrCode InsertListenerToRecords(const sptr<IRemoteObject> &listener);
    ErrCode RemoveListenerByListener(const sptr<IRemoteObject> &listener);
    void NotifyEventAsync(const DomainAccountEventData &report);

private:
    void DomainAccountEventParcel(const DomainAccountEventData &report, Parcel &parcel);

    std::mutex mutex_;
    std::set<sptr<IRemoteObject>> listenerAll_;
    sptr<IRemoteObject::DeathRecipient> listenerDeathRecipient_;
};
} // namespace AccountSA
} // namespace OHOS
#endif // OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_STATUS_LISTENER_MANAGER_H
