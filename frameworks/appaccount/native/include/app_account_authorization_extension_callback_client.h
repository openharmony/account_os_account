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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_AUTHORIZATION_EXTENSION_CALLBACK_CLIENT_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_AUTHORIZATION_EXTENSION_CALLBACK_CLIENT_H

#include "app_account_authorization_extension_callback.h"
#include "app_account_authorization_extension_callback_proxy.h"

namespace OHOS {
namespace AccountSA {
class AppAccountAuthorizationExtensionCallbackClient : public AppAccountAuthorizationExtensionCallback {
public:
    explicit AppAccountAuthorizationExtensionCallbackClient(
        const sptr<IAppAccountAuthorizationExtensionCallback> &proxy);
    virtual ~AppAccountAuthorizationExtensionCallbackClient();
    void OnResult(const AsyncCallbackError &businessError, const AAFwk::WantParams &parameters) override;
    void OnRequestRedirected(const AAFwk::Want &request) override;

private:
    sptr<IAppAccountAuthorizationExtensionCallback> proxy_;
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_AUTHORIZATION_EXTENSION_CALLBACK_CLIENT_H