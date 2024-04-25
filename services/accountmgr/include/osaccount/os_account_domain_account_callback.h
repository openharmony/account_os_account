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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_DOMAIN_DOMAIN_ACCOUNT_CALLBACK_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_DOMAIN_DOMAIN_ACCOUNT_CALLBACK_H

#include "domain_account_common.h"
#include "domain_account_callback.h"
#include "domain_account_callback_stub.h"
#include "idomain_account_callback.h"
#include "ios_account_control.h"
#include "os_account_info.h"

namespace OHOS {
namespace AccountSA {
class CheckAndCreateDomainAccountCallback final : public DomainAccountCallbackStub {
public:
    CheckAndCreateDomainAccountCallback(const OsAccountType &type, const DomainAccountInfo &domainAccountInfo_,
        const sptr<IDomainAccountCallback> &callback, const CreateOsAccountForDomainOptions &accountOptions);
    void OnResult(const int32_t errCode, Parcel &parcel) override;

private:
    OsAccountType type_;
    DomainAccountInfo domainAccountInfo_;
    CreateOsAccountForDomainOptions accountOptions_;
    sptr<IDomainAccountCallback> innerCallback_ = nullptr;
};

class BindDomainAccountCallback final : public DomainAccountCallback {
public:
    BindDomainAccountCallback(std::shared_ptr<IOsAccountControl> &osAccountControl,
        const DomainAccountInfo &domainAccountInfo, const OsAccountInfo &osAccountInfo,
        const sptr<IDomainAccountCallback> &callback);
    void OnResult(const int32_t errCode, Parcel &parcel) override;

private:
    std::shared_ptr<IOsAccountControl> osAccountControl_;
    DomainAccountInfo domainAccountInfo_;
    OsAccountInfo osAccountInfo_;
    sptr<IDomainAccountCallback> innerCallback_ = nullptr;
};
} // namespace AccountSA
} // namespace OHOS
#endif // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_DOMAIN_DOMAIN_ACCOUNT_CALLBACK_H
