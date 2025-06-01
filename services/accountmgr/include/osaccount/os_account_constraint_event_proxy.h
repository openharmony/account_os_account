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

#ifndef OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_CONSTRAINT_EVENT_PROXY_H
#define OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_CONSTRAINT_EVENT_PROXY_H

#include "ios_account_event.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace AccountSA {
class OsAccountConstraintEventProxy : public IRemoteProxy<IConstraintEvent> {
public:
    explicit OsAccountConstraintEventProxy(const sptr<IRemoteObject> &object);
    ~OsAccountConstraintEventProxy() override;

    ErrCode OnConstraintChanged(int localId, const std::set<std::string> &constraints, bool enable) override;

private:
    ErrCode SendRequest(ConstraintEventInterfaceCode code, MessageParcel &data, MessageParcel &reply);

private:
    static inline BrokerDelegator<OsAccountConstraintEventProxy> delegator_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_CONSTRAINT_EVENT_PROXY_H
