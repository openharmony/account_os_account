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

#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_PLUGIN_STUB_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_PLUGIN_STUB_H

#include <map>
#include "idomain_account_plugin.h"
#include "iremote_stub.h"

namespace OHOS {
namespace AccountSA {
class DomainAccountPluginStub : public IRemoteStub<IDomainAccountPlugin> {
public:
    using MessageProcFunction = ErrCode (DomainAccountPluginStub::*)(MessageParcel &data, MessageParcel &reply);

    DomainAccountPluginStub();
    ~DomainAccountPluginStub() override;
    int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    ErrCode ProcAuth(MessageParcel &data, MessageParcel &reply);
    ErrCode ProcGetAuthProperty(MessageParcel &data, MessageParcel &reply);

private:
    static const std::map<uint32_t, MessageProcFunction> messageProcMap_;

    DISALLOW_COPY_AND_MOVE(DomainAccountPluginStub);
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_PLUGIN_STUB_H
