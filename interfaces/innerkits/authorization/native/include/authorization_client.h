/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef AUTHORIZATION_INNERKITS_AUTHORIZATION_INCLUDE_AUTHORIZATION_CLIENT_H
#define AUTHORIZATION_INNERKITS_AUTHORIZATION_INCLUDE_AUTHORIZATION_CLIENT_H

#include <string>
#include <vector>
#include "authorization_callback.h"
#include "authorization_callback_service.h"
#include "authorization_common.h"
#include "iauthorization.h"
#include "admin_authorization_callback_service.h"

namespace OHOS {
namespace AccountSA {

class AuthRemoteObjectStub;
/**
 * @brief Client for accessing authorization service.
 *
 * This class provides methods to acquire authorization and manage
 * the connection with the authorization service.
 */
class AuthorizationClient {
public:
    /**
     * @brief Gets the instance of AuthorizationClient.
     *
     * @return the instance of AuthorizationClient.
     */
    static AuthorizationClient &GetInstance();

    /**
     * @brief Acquires an authorization for the target privilege.
     *
     * This method initiates an authorization request for the specified privilege.
     * The result will be delivered through the provided callback.
     *
     * @param privilege The privilege to authorize
     * @param options The authorization options (challenge, interaction allowed, etc.)
     * @param callback The callback to receive authorization result
     * @return ERR_OK on success, error code on failure
     */
    ErrCode AcquireAuthorization(const std::string &privilege, const AcquireAuthorizationOptions &options,
        const std::shared_ptr<AuthorizationCallback> &callback);

    /**
     * @brief Releases an authorization for the target privilege.
     *
     * @param privilege The privilege to authorize
     * @return ERR_OK on success, error code on failure
     */
    ErrCode ReleaseAuthorization(const std::string &privilege);

    /**
     * @brief Registers the authorization application remote object.
     *
     * @return ERR_OK on success, error code on failure
     */
    ErrCode RegisterAuthAppRemoteObject();

    /**
     * @brief Unregisters the authorization application remote object.
     *
     * @return ERR_OK on success, error code on failure
     */
    ErrCode UnRegisterAuthAppRemoteObject();

    /**
     * Check an authorization for the target privilege.
     */
    ErrCode CheckAuthorization(const std::string &privilege, bool &isAuthorized);

    /**
     * Check an authorization for the target privilege with pid.
     */
    ErrCode CheckAuthorization(const std::string &privilege, int32_t pid, bool &isAuthorized);

    /**
     * Check an authorization for the target privilege and verify the token.
     */
    ErrCode CheckAuthorizationToken(const std::vector<uint8_t> &token,
        const std::string &privilege, int32_t pid, CheckAuthorizationResult &result);

    /**
     * @brief Acquires authorization for the specified admin account.
     *
     * This method is used by business processes to request admin authorization
     * from the account service. The caller needs to specify the admin account name
     * and challenge value, and the authorization result will be returned asynchronously
     * through the callback.
     *
     * Flow:
     * 1. Business process calls this interface to initiate admin authorization request
     * 2. Account SA verifies if the account type is admin
     * 3. Account SA calls UserIAM for identity authentication
     * 4. After successful authentication, Account SA calls TA to issue authorization token
     * 5. Returns authorization result through callback (contains token or error code)
     *
     * @param adminName The admin account name
     * @param challenge The challenge value for authorization verification
     * @param callback The callback object to receive authorization result
     * @return ERR_OK if request is successfully initiated, error code on failure
     */
    ErrCode AcquireAdminAuthorization(const std::string &adminName, std::vector<uint8_t> &challenge,
        const std::shared_ptr<AdminAuthorizationCallback> &callback, const std::string &privilege = "");

private:
    AuthorizationClient();
    ~AuthorizationClient();
    DISALLOW_COPY_AND_MOVE(AuthorizationClient);
    void EraseAuthCallBack();

#ifdef SUPPORT_AUTHORIZATION
    bool CheckCallbackService(const std::string &privilege,
        const std::shared_ptr<AuthorizationCallback> &callback);
    sptr<AuthRemoteObjectStub> GetOrCreateRequestRemoteObject();
    /**
     * @brief Death recipient for monitoring authorization service death.
     */
    class AuthorizationDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        AuthorizationDeathRecipient() = default;
        ~AuthorizationDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject>& remote) override;

    private:
        DISALLOW_COPY_AND_MOVE(AuthorizationDeathRecipient);
    };

    sptr<IAuthorization> GetAuthorizationProxy();
    void ResetAuthorizationProxy(const wptr<IRemoteObject> &remote);

    /// Mutex for protecting authorization proxy access
    std::mutex mutex_;
    /// Proxy to the authorization service
    sptr<IAuthorization> proxy_ = nullptr;
    /// Death recipient for monitoring authorization service
    sptr<AuthorizationDeathRecipient> deathRecipient_ = nullptr;
    /// Recursive mutex for protecting callback service access
    std::recursive_mutex callbackMutex_;
    /// Callback service for handling authorization events
    sptr<AuthorizationCallbackService> callbackService_ = nullptr;
#endif
};
}
}
#endif // AUTHORIZATION_INNERKITS_AUTHORIZATION_INCLUDE_AUTHORIZATION_CLIENT_H
