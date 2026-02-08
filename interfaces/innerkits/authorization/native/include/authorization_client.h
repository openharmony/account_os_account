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
        const std::shared_ptr<AuthorizationCallback> &callback, AuthorizationResult &authorizationResult);

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