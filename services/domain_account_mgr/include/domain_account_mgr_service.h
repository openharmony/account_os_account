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

#ifndef OS_ACCOUNT_SERVICES_DOMAIN_ACCOUNT_MGR_INCLUDE_ACCOUNT_SERVICE_H
#define OS_ACCOUNT_SERVICES_DOMAIN_ACCOUNT_MGR_INCLUDE_ACCOUNT_SERVICE_H

#include "domain_account_mgr_stub.h"
#include "singleton.h"
#include "system_ability.h"

namespace OHOS {
namespace AccountSA {
class DomainAccountMgrService : public SystemAbility,
                                public DomainAccountMgrStub,
                                public DelayedRefSingleton<DomainAccountMgrService> {
public:
    DomainAccountMgrService();
    ~DomainAccountMgrService();
    DISALLOW_COPY_AND_MOVE(DomainAccountMgrService);
    DECLARE_SYSTEM_ABILITY(DomainAccountMgrService);
    bool CheckAccountValidity() override;
    bool AuthAccount() override;
};
}  // namespace AccountSA
}  // namespace OHOS
#endif // OS_ACCOUNT_SERVICES_DOMAIN_ACCOUNT_MGR_INCLUDE_ACCOUNT_SERVICE_H
