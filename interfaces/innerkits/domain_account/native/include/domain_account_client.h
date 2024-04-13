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

/**
 * @addtogroup DomainAccount
 * @{
 *
 * @brief Provides domain account management.
 *
 * Provides the capability to manage domain accounts.
 *
 * @since 10.0
 * @version 10.0
 */

/**
 * @file domain_account_client.h
 *
 * @brief Declares domain account manager interfaces.
 *
 * @since 10.0
 * @version 10.0
 */
#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_CLIENT_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_CLIENT_H

#include <map>
#include <mutex>
#include <set>
#include "account_error_no.h"
#include "domain_account_callback.h"
#include "domain_account_plugin.h"
#include "idomain_account_plugin.h"
#include "domain_account_status_listener.h"
#include "domain_account_status_listener_manager.h"
#include "domain_account_callback_service.h"
#include "get_access_token_callback.h"
#include "idomain_account.h"
#include "want.h"

namespace OHOS {
namespace AccountSA {
class DomainAccountClient {
public:
    /**
     * Gets the instance of DomainAccountClient.
     *
     * @return the instance of DomainAccountClient.
     */
    static DomainAccountClient &GetInstance();

    /**
     * @brief Registers the domain plugin, which provides the capabilities for domain authentication.
     * @permission ohos.permission.MANAGE_LOCAL_ACCOUNTS
     * @param plugin - Indicates the domain plugin.
     * @return error code, see account_error_no.h
     */
    ErrCode RegisterPlugin(const std::shared_ptr<DomainAccountPlugin> &plugin);

    /**
     * @brief Unregisters domain plugin.
     * @permission ohos.permission.MANAGE_LOCAL_ACCOUNTS
     * @return error code, see account_error_no.h
     */
    ErrCode UnregisterPlugin();

    /**
     * @brief Authenticates the specified domain account with a credential.
     * @permission ohos.permission.ACCESS_USER_AUTH_INTERNAL
     * @param domainAccountInfo - Indicates the domain account information.
     * @param password - Indicates the credential for authentication.
     * @param callback - Indicates the callback for getting the authentication result.
     * @return error code, see account_error_no.h
     */
    ErrCode Auth(const DomainAccountInfo &info, const std::vector<uint8_t> &password,
        const std::shared_ptr<DomainAccountCallback> &callback);

    /**
     * @brief Authenticates a domain account bound with the specified userId with a credential.
     * @permission ohos.permission.ACCESS_USER_AUTH_INTERNAL
     * @param domainAccountInfo - Indicates the domain account information.
     * @param password - Indicates the credential for authentication.
     * @param callback - Indicates the callback for getting the authentication result.
     * @return error code, see account_error_no.h
     */
    ErrCode AuthUser(int32_t userId, const std::vector<uint8_t> &password,
        const std::shared_ptr<DomainAccountCallback> &callback);

    /**
     * @brief Authenticates the domain account bound to the specified OS account with a popup.
     * @permission ohos.permission.ACCESS_USER_AUTH_INTERNAL
     * @param localId - Indicates the local ID of the specified OS account.
     * @param callback - Indicates the callback for getting the authentication result.
     * @return error code, see account_error_no.h
     */
    ErrCode AuthWithPopup(int32_t userId, const std::shared_ptr<DomainAccountCallback> &callback);

    /**
     * @brief Checks whether the specified domain account exists.
     * @permission ohos.permission.MANAGE_LOCAL_ACCOUNTS
     * @param domainAccountInfo - Indicates the domain account information.
     * @param callback - Indicates the callback for checking whether the specified domain account exists.
     * @return error code, see account_error_no.h
     */
    ErrCode HasAccount(const DomainAccountInfo &info, const std::shared_ptr<DomainAccountCallback> &callback);
    ErrCode UpdateAccountToken(const DomainAccountInfo &info, const std::vector<uint8_t> &token);
    ErrCode IsAuthenticationExpired(const DomainAccountInfo &info, bool &isExpired);
    ErrCode SetAccountPolicy(const DomainAccountPolicy &policy);
    ErrCode GetAccessToken(const DomainAccountInfo &info, const AAFwk::WantParams &parameters,
        const std::shared_ptr<GetAccessTokenCallback> &callback);
    ErrCode GetAccountStatus(const DomainAccountInfo &info, DomainAccountStatus &status);
    ErrCode GetDomainAccountInfo(const DomainAccountInfo &info, const std::shared_ptr<DomainAccountCallback> &callback);
    ErrCode UpdateAccountInfo(const DomainAccountInfo &oldAccountInfo, const DomainAccountInfo &newAccountInfo);
    ErrCode RegisterAccountStatusListener(const std::shared_ptr<DomainAccountStatusListener> &listener);
    ErrCode UnregisterAccountStatusListener(const std::shared_ptr<DomainAccountStatusListener> &listener);
    friend std::function<void(int32_t, const std::string &)> callbackFunc();

    ErrCode AddServerConfig(const std::string &parameters, DomainServerConfig &config);
    ErrCode RemoveServerConfig(const std::string &configId);
    ErrCode GetAccountServerConfig(const DomainAccountInfo &info, DomainServerConfig &config);

private:
    DomainAccountClient();
    ~DomainAccountClient() = default;
    void RestoreListenerRecords();
    void RestorePlugin();
    DISALLOW_COPY_AND_MOVE(DomainAccountClient);

private:
    class DomainAccountDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        DomainAccountDeathRecipient() = default;
        ~DomainAccountDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject>& remote) override;

    private:
        DISALLOW_COPY_AND_MOVE(DomainAccountDeathRecipient);
    };
    sptr<IDomainAccount> GetDomainAccountProxy();
    void ResetDomainAccountProxy(const wptr<IRemoteObject> &remote);
    ErrCode AuthProxyInit(const std::shared_ptr<DomainAccountCallback> &callback,
        sptr<DomainAccountCallbackService> &callbackService, sptr<IDomainAccount> &proxy);

private:
    std::mutex mutex_;
    std::mutex recordMutex_;
    sptr<IDomainAccount> proxy_ = nullptr;
    sptr<DomainAccountDeathRecipient> deathRecipient_ = nullptr;
    sptr<IDomainAccountPlugin> pluginService_ = nullptr;
    sptr<IDomainAccountCallback> callback_ = nullptr;
    std::shared_ptr<DomainAccountStatusListenerManager> listenerManager_ = nullptr;
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_CLIENT_H