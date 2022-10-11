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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_AUTHENTICATOR_STUB_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_AUTHENTICATOR_STUB_H

#include "iapp_account_authenticator.h"
#include "iremote_stub.h"

namespace OHOS {
namespace AccountSA {
class AppAccountAuthenticatorStub : public IRemoteStub<IAppAccountAuthenticator> {
public:
    using MessageProcFunction = ErrCode (AppAccountAuthenticatorStub::*)(MessageParcel &data, MessageParcel &reply);
    AppAccountAuthenticatorStub();
    ~AppAccountAuthenticatorStub() override;
    int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    ErrCode ProcAddAccountImplicitly(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcAuthenticate(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcVerifyCredential(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcCheckAccountLabels(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSetProperties(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcIsAccountRemovable(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcCreateAccountImplicitly(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcAuth(MessageParcel &data, MessageParcel &reply);

private:
    static const std::map<uint32_t, MessageProcFunction> funcMap_;
    DISALLOW_COPY_AND_MOVE(AppAccountAuthenticatorStub);
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_AUTHENTICATOR_STUB_H
