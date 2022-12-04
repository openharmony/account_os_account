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

#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_CLIENT_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_CLIENT_H

#include <mutex>
#include "account_error_no.h"
#include "domain_account_plugin.h"
#include "idomain_account.h"
#include "singleton.h"

namespace OHOS {
namespace AccountSA {
class DomainAccountClient : public DelayedRefSingleton<DomainAccountClient> {
public:
    ErrCode RegisterPlugin(const std::shared_ptr<DomainAccountPlugin> &plugin);
    ErrCode UnregisterPlugin();
    ErrCode Auth(const DomainAccountInfo &info, const std::vector<uint8_t> &password,
        const std::shared_ptr<DomainAuthCallback> &callback);
    ErrCode AuthUser(int32_t userId, const std::vector<uint8_t> &password,
        const std::shared_ptr<DomainAuthCallback> &callback);

private:
    class DomainAccountDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        DomainAccountDeathRecipient() = default;
        ~DomainAccountDeathRecipient() = default;
        void OnRemoteDied(const wptr<IRemoteObject>& remote) override;

    private:
        DISALLOW_COPY_AND_MOVE(DomainAccountDeathRecipient);
    };
    sptr<IDomainAccount> GetDomainAccountProxy();
    void ResetDomainAccountProxy(const wptr<IRemoteObject>& remote);

private:
    std::mutex mutex_;
    sptr<IDomainAccount> proxy_ = nullptr;
    sptr<DomainAccountDeathRecipient> deathRecipient_ = nullptr;
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_CLIENT_H