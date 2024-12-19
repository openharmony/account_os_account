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

#ifndef OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_OS_ACCOUNT_STATE_REPLY_CALLBACK_H
#define OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_OS_ACCOUNT_STATE_REPLY_CALLBACK_H

#include "ios_account_state_reply_callback.h"
#include "accountmgr_service_ipc_interface_code.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace AccountSA {
class OsAccountStateReplyCallback : public IRemoteProxy<IOsAccountStateReplyCallback> {
public:
    explicit OsAccountStateReplyCallback(const sptr<IRemoteObject> &object);
    ~OsAccountStateReplyCallback() override = default;

    void OnComplete() override;

private:
    ErrCode SendRequest(
        StateReplyCallbackInterfaceCode code, MessageParcel &data, MessageParcel &reply);

private:
    static inline BrokerDelegator<OsAccountStateReplyCallback> delegator_;
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_OS_ACCOUNT_STATE_REPLY_CALLBACK_H
