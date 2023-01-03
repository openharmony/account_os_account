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

#ifndef OS_ACCOUNT_SERVICES_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_AUTH_CALLBACK_STUB_H
#define OS_ACCOUNT_SERVICES_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_AUTH_CALLBACK_STUB_H

#include <map>
#include "account_error_no.h"
#include "idomain_auth_callback.h"
#include "iremote_stub.h"

namespace OHOS {
namespace AccountSA {
class DomainAuthCallbackStub : public IRemoteStub<IDomainAuthCallback> {
public:
    using DomainAuthCallbackStubFunc = ErrCode (DomainAuthCallbackStub::*)(MessageParcel &data, MessageParcel &reply);
    DomainAuthCallbackStub();
    ~DomainAuthCallbackStub();
    int32_t OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    ErrCode ProcOnResult(MessageParcel &data, MessageParcel &reply);

private:
    static const std::map<uint32_t, DomainAuthCallbackStubFunc> stubFuncMap_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif // OS_ACCOUNT_SERVICES_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_AUTH_CALLBACK_STUB_H
