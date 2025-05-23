/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_AUTHENTICATOR_CALLBACK_PROXY_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_AUTHENTICATOR_CALLBACK_PROXY_H

#include "iapp_account_authenticator_callback.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace AccountSA {
class AppAccountAuthenticatorCallbackProxy : public IRemoteProxy<IAppAccountAuthenticatorCallback> {
public:
    explicit AppAccountAuthenticatorCallbackProxy(const sptr<IRemoteObject> &object);
    ~AppAccountAuthenticatorCallbackProxy() override;

    void OnResult(int32_t resultCode, const AAFwk::Want &result) override;
    void OnRequestRedirected(AAFwk::Want &request) override;
    void OnRequestContinued() override;

private:
    ErrCode SendRequest(AppAccountAuthenticatorCallbackInterfaceCode code, MessageParcel &data, MessageParcel &reply);

private:
    static inline BrokerDelegator<AppAccountAuthenticatorCallbackProxy> delegator_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_AUTHENTICATOR_CALLBACK_PROXY_H
