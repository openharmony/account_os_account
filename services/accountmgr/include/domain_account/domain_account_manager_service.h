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

#ifndef OS_ACCOUNT_SERVICES_DOMAIN_ACCOUNT_INCLUDE_ACCOUNT_ACCOUNT_MANAGER_SERVICE_H
#define OS_ACCOUNT_SERVICES_DOMAIN_ACCOUNT_INCLUDE_ACCOUNT_ACCOUNT_MANAGER_SERVICE_H

#include <mutex>
#include "domain_account_stub.h"
#include "os_account_info.h"

namespace OHOS {
namespace AccountSA {
class DomainAccountManagerService : public DomainAccountStub {
public:
    DomainAccountManagerService();
    ~DomainAccountManagerService() override;
    ErrCode RegisterPlugin(const sptr<IDomainAccountPlugin> &plugin) override;
    ErrCode UnregisterPlugin() override;
    ErrCode Auth(const DomainAccountInfo &info, const std::vector<uint8_t> &password,
        const sptr<IDomainAuthCallback> &callback) override;
    ErrCode AuthUser(int32_t userId, const std::vector<uint8_t> &password,
        const sptr<IDomainAuthCallback> &callback) override;

private:
    std::mutex mutex_;
    sptr<IDomainAccount> plugin_;
};
}  // namespace AccountSA
}  // namespace OHOS
#endif // OS_ACCOUNT_SERVICES_DOMAIN_ACCOUNT_INCLUDE_ACCOUNT_ACCOUNT_MANAGER_SERVICE_H
