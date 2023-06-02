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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APP_ACCOUNT_AUTHENTICATION_EXTENSION_PROXY_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APP_ACCOUNT_AUTHENTICATION_EXTENSION_PROXY_H

#include <string>
#include "account_error_no.h"
#include "iapp_account_authentication_extension.h"
#include "iremote_proxy.h"
#include "want.h"

namespace OHOS {
namespace AccountSA {
class AppAccountAuthenticationExtensionProxy : public IRemoteProxy<IAppAccountAuthenticationExtension> {
public:
    explicit AppAccountAuthenticationExtensionProxy(const sptr<IRemoteObject> &object);
    ~AppAccountAuthenticationExtensionProxy() override;
    ErrCode StartAuthentication(const AuthenticationRequest &request) override;

private:
    ErrCode SendRequest(IAppAccountAuthenticationExtension::Message code, MessageParcel &data, MessageParcel &reply);

private:
    static inline BrokerDelegator<AppAccountAuthenticationExtensionProxy> delegator_;
};
} // namespace AccountSA
} // namespace OHOS
#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APP_ACCOUNT_AUTHENTICATION_EXTENSION_PROXY_H