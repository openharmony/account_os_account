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

#ifndef OS_ACCOUNT_FRAMEWORKS_OHOSACCOUNT_NATIVE_INCLUDE_DISTRUBUTED_ACCOUNT_EVENT_PROXY_H
#define OS_ACCOUNT_FRAMEWORKS_OHOSACCOUNT_NATIVE_INCLUDE_DISTRUBUTED_ACCOUNT_EVENT_PROXY_H

#include "idistributed_account_event.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace AccountSA {
class DistributedAccountEventProxy : public IRemoteProxy<IDistributedAccountEvent> {
public:
    explicit DistributedAccountEventProxy(const sptr<IRemoteObject> &object);
    ~DistributedAccountEventProxy() override;

    void OnAccountsChanged(const DistributedAccountEventData &eventData) override;

private:
    ErrCode SendRequest(DistributedAccountEventInterfaceCode code, MessageParcel &data, MessageParcel &reply);

private:
    static inline BrokerDelegator<DistributedAccountEventProxy> delegator_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_FRAMEWORKS_OHOSACCOUNT_NATIVE_INCLUDE_DISTRUBUTED_ACCOUNT_EVENT_PROXY_H
