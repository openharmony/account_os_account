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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_AUTHORIZATION_EXTENSION_STUB_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_AUTHORIZATION_EXTENSION_STUB_H

#include <map>
#include "iapp_account_authorization_extension.h"
#include "iremote_stub.h"

namespace OHOS {
namespace AccountSA {
class AppAccountAuthorizationExtensionStub : public IRemoteStub<IAppAccountAuthorizationExtension> {
public:
    using MessageProcFunction = ErrCode (AppAccountAuthorizationExtensionStub::*)(
        MessageParcel &data, MessageParcel &reply);

    AppAccountAuthorizationExtensionStub();
    ~AppAccountAuthorizationExtensionStub() override;
    int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    ErrCode ProcStartAuthorization(MessageParcel &data, MessageParcel &reply);

private:
    std::map<uint32_t, MessageProcFunction> messageProcMap_;

    DISALLOW_COPY_AND_MOVE(AppAccountAuthorizationExtensionStub);
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_AUTHORIZATION_EXTENSION_STUB_H
