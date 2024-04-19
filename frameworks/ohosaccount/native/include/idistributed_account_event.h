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

#ifndef OS_ACCOUNT_FRAMEWORKS_OHOSACCOUNT_NATIVE_INCLUDE_IDISTRIBUTED_ACCOUNT_EVENT_H
#define OS_ACCOUNT_FRAMEWORKS_OHOSACCOUNT_NATIVE_INCLUDE_IDISTRIBUTED_ACCOUNT_EVENT_H

#include "account_error_no.h"
#include "accountmgr_service_ipc_interface_code.h"
#include "distributed_account_subscribe_callback.h"
#include "iremote_broker.h"

namespace OHOS {
namespace AccountSA {
class IDistributedAccountEvent : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.accountfwk.IDistributedAccountEvent");

    virtual void OnAccountsChanged(const DistributedAccountEventData &eventData) = 0;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_FRAMEWORKS_OHOSACCOUNT_NATIVE_INCLUDE_IDISTRIBUTED_ACCOUNT_EVENT_H
