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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_IAPP_ACCOUNT_AUTHENTICATOR_CALLBACK_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_IAPP_ACCOUNT_AUTHENTICATOR_CALLBACK_H

#include "iremote_broker.h"
#include "want.h"

namespace OHOS {
namespace AccountSA {
class IAppAccountAuthenticatorCallback : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.accountfwk.IAppAccountAuthenticatorCallback");

    virtual void OnResult(int32_t resultCode, const AAFwk::Want &result) = 0;
    virtual void OnRequestRedirected(AAFwk::Want &request) = 0;
    virtual void OnRequestContinued() = 0;

    enum class Message {
        ACCOUNT_RESULT = 0,
        ACCOUNT_REQUEST_REDIRECTED,
        ACCOUNT_REQUEST_CONTINUED,
    };
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_IAPP_ACCOUNT_AUTHENTICATOR_CALLBACK_H
