/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_EVENT_PROXY_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_EVENT_PROXY_H

#include "iapp_account_event.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace AccountSA {
class AppAccountEventProxy : public IRemoteProxy<IAppAccountEvent> {
public:
    explicit AppAccountEventProxy(const sptr<IRemoteObject> &object);
    ~AppAccountEventProxy() override;

    void OnAccountsChanged(const std::vector<AppAccountInfo> &accounts) override;

private:
    ErrCode SendRequest(IAppAccountEvent::Message code, MessageParcel &data, MessageParcel &reply);

    template<typename T>
    bool WriteParcelableVector(const std::vector<T> &parcelableVector, Parcel &data);

private:
    static inline BrokerDelegator<AppAccountEventProxy> delegator_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_EVENT_PROXY_H
