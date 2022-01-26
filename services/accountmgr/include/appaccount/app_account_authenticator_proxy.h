/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_AUTHENTICATOR_PROXY_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_AUTHENTICATOR_PROXY_H

#include "iapp_account_authenticator.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace AccountSA {
class AppAccountAuthenticatorProxy : public IRemoteProxy<IAppAccountAuthenticator> {
public:
    explicit AppAccountAuthenticatorProxy(const sptr<IRemoteObject> &object);
    virtual ~AppAccountAuthenticatorProxy() override;

    virtual ErrCode AddAccountImplicitly(const std::string &authType, const std::string &callerBundleName,
        const AAFwk::WantParams &options, const sptr<IRemoteObject> &callback) override;
    virtual ErrCode Authenticate(
        const std::string &name, const std::string &authType, const std::string &callerBundleName,
        const AAFwk::WantParams &options, const sptr<IRemoteObject> &callback) override;

private:
    ErrCode SendRequest(IAppAccountAuthenticator::Message code, MessageParcel &data, MessageParcel &reply);

private:
    static inline BrokerDelegator<AppAccountAuthenticatorProxy> delegator_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_AUTHENTICATOR_PROXY_H
