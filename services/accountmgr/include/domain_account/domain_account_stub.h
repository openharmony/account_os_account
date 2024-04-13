/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SERVICES_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_STUB_H
#define OS_ACCOUNT_SERVICES_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_STUB_H

#include <map>
#include "account_error_no.h"
#include "idomain_account.h"
#include "iremote_stub.h"

namespace OHOS {
namespace AccountSA {
class DomainAccountStub : public IRemoteStub<IDomainAccount> {
public:
    using DomainAccountStubFunc = ErrCode (DomainAccountStub::*)(MessageParcel &data, MessageParcel &reply);
    DomainAccountStub();
    ~DomainAccountStub();
    int32_t OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

public:
    ErrCode CheckPermission(DomainAccountInterfaceCode code, int32_t uid);
    ErrCode ProcRegisterPlugin(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcUnregisterPlugin(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcAuth(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcAuthUser(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcAuthWithPopup(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetAccountStatus(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcHasDomainAccount(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcUpdateAccountToken(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcIsAuthenticationExpired(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcSetAuthenticationExpiryThreshold(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetDomainAccessToken(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetDomainAccountInfo(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcUpdateAccountInfo(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcUnregisterAccountStatusListener(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcRegisterAccountStatusListener(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcAddServerConfig(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcRemoveServerConfig(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetAccountServerConfig(MessageParcel &data, MessageParcel &reply);

private:
    std::map<DomainAccountInterfaceCode, DomainAccountStubFunc> stubFuncMap_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif // OS_ACCOUNT_SERVICES_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_STUB_H
