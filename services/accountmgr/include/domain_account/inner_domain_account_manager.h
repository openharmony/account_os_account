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

#ifndef OS_ACCOUNT_SERVICES_DOMAIN_ACCOUNT_INCLUDE_INNER_DOMAIN_ACCOUNT_MANAGER_H
#define OS_ACCOUNT_SERVICES_DOMAIN_ACCOUNT_INCLUDE_INNER_DOMAIN_ACCOUNT_MANAGER_H

#include <mutex>
#include "domain_account_plugin_death_recipient.h"
#include "domain_account_plugin_proxy.h"
#include "domain_auth_callback.h"
#include "event_handler.h"
#include "os_account_info.h"
#include "singleton.h"

namespace OHOS {
namespace AccountSA {
class InnerDomainAccountManager : public DelayedSingleton<InnerDomainAccountManager> {
public:
    ErrCode RegisterPlugin(const sptr<IDomainAccountPlugin> &plugin);
    void UnregisterPlugin();
    ErrCode Auth(const DomainAccountInfo &info, const std::vector<uint8_t> &password,
        const std::shared_ptr<DomainAuthCallback> &callback);
    ErrCode Auth(const DomainAccountInfo &info, const std::vector<uint8_t> &password,
        const sptr<IDomainAuthCallback> &callback);
    ErrCode AuthUser(int32_t userId, const std::vector<uint8_t> &password,
        const sptr<IDomainAuthCallback> &callback);
    ErrCode GetAuthProperty(const DomainAccountInfo &info, DomainAuthProperty &property);
    bool IsPluginAvailable();

private:
    ErrCode StartAuth(const sptr<IDomainAccountPlugin> &plugin, const DomainAccountInfo &info,
        const std::vector<uint8_t> &password, const sptr<IDomainAuthCallback> &callback);
    std::shared_ptr<AppExecFwk::EventHandler> GetEventHandler();
    sptr<IRemoteObject::DeathRecipient> GetDeathRecipient();

private:
    std::mutex mutex_;
    std::shared_ptr<AppExecFwk::EventHandler> handler_;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_;
    sptr<IDomainAccountPlugin> plugin_;
};
}  // namespace AccountSA
}  // namespace OHOS
#endif // OS_ACCOUNT_SERVICES_DOMAIN_ACCOUNT_INCLUDE_INNER_DOMAIN_ACCOUNT_MANAGER_H
