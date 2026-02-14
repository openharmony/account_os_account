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

#ifndef OS_ACCOUNT_SERVICES_AUTHORIZATION_INCLUDE_INNER_AUTHORIZATION_MANAGER_H
#define OS_ACCOUNT_SERVICES_AUTHORIZATION_INCLUDE_INNER_AUTHORIZATION_MANAGER_H

#include "authorization_common.h"
#include "connect_ability_callback_stub.h"
#include "iauthorization_callback.h"
#include "ios_account_control.h"
#include "privileges_map.h"
#include "tee_auth_adapter.h"

namespace OHOS {
namespace AccountSA {
/**
 * @brief Function type for handling authorization result callback.
 *
 * This function type defines the signature for callbacks that handle
 * the result of an authorization request.
 *
 * @param resultCode The result code from the authorization service
 * @param result The authorization result containing token and status
 * @param accountId The account ID associated with the authorization
 * @return ERR_OK on success, error code on failure
 */
using AcquireOnResultfunc = std::function<ErrCode(int32_t, AuthorizationResult &, int32_t)>;

/**
 * @brief Callback for UI extension connection results.
 *
 * This class handles the callback when a UI extension connection
 * completes, forwarding the result to the registered callback function.
 */
class ConnectAbilityCallback : public ConnectAbilityCallbackStub {
public:
    /**
     * @brief Constructor.
     * @param info The connection ability information
     * @param func The callback function to invoke on result
     * @param result The authorization result to return
     */
    ConnectAbilityCallback(ConnectAbilityInfo &info, AcquireOnResultfunc func,
        const AuthorizationResult &result);

    /**
     * @brief Called when UI extension connection completes with result.
     *
     * @param resultCode The result code from UI extension
     * @param iamToken The IAM token from authorization service
     * @param accountId The account ID
     * @param iamResultCode The authorization result code
     * @return ERR_OK on success
     */
    ErrCode OnResult(int32_t resultCode, const std::vector<uint8_t> &iamToken, int32_t accountId,
        int32_t iamResultCode) override;

private:
    /// The callback function to invoke
    AcquireOnResultfunc func_ = nullptr;
    /// The authorization result to return
    AuthorizationResult result_;
    /// The connection ability information
    ConnectAbilityInfo info_;
};

/**
 * @brief Inner manager for authorization operations.
 *
 * This class provides the core implementation for authorization operations,
 * including privilege verification, token management, and UI extension
 * connection handling.
 */
class InnerAuthorizationManager {
public:
    /**
     * @brief Gets the singleton instance of InnerAuthorizationManager.
     * @return Reference to the singleton instance
     */
    static InnerAuthorizationManager &GetInstance();

    /**
     * @brief Acquires authorization for a privilege.
     *
     * This method performs the actual authorization process, including
     * privilege validation, TEE communication, and token generation.
     *
     * @param pdef The privilege definition to authorize
     * @param options Authorization options (challenge, interaction allowed, etc.)
     * @param config OS account configuration
     * @param authorizationResultCallback Callback to receive authorization result
     * @param requestRemoteObj Remote object of the requesting application
     * @return ERR_OK on success, error code on failure
     */
    ErrCode AcquireAuthorization(const PrivilegeBriefDef &pdef, const AcquireAuthorizationOptions &options,
        const OsAccountConfig &config, const sptr<IRemoteObject> &authorizationResultCallback,
        const sptr<IRemoteObject> &requestRemoteObj);

    /**
     * @brief Updates authorization information after successful authorization.
     *
     * @param iamToken The IAM token from authorization service
     * @param accountId The account ID
     * @param callingUid The UID of the calling process
     * @return ERR_OK on success, error code on failure
     */
    ErrCode UpdateAuthInfo(const std::vector<uint8_t> &iamToken, int32_t accountId, int32_t callingUid);

    /**
     * @brief Applies TA authorization and updates privilege cache.
     *
     * This method verifies the account type, communicates with the TEE
     * to obtain authorization token, and updates the privilege cache.
     *
     * @param iamToken The IAM token from authorization service
     * @param accountId The account ID
     * @param tokenResult Output token application result
     * @param info The connection ability information
     * @return Pair of error code and authorization result code
     */
    std::pair<ErrCode, AuthorizationResultCode> ApplyTaAuthorization(const std::vector<uint8_t> &iamToken,
        int32_t accountId, ApplyUserTokenResult &tokenResult, ConnectAbilityInfo &info);

    /**
     * @brief Check privilege from privilege cache.
     * @param privilegeId The privilege id
     * @param pid  The process id
     * @param isAuthorized The result of check privilegeId and pid
     * @return ERR_OK on success, error code on failure
     */
    ErrCode CheckAuthorization(const uint32_t privilegeId,
        const int32_t pid, bool &isAuthorized);

    /**
     * @brief verify token to TA.
     * @param token The authorization token for authentication
     * @param pid The process id
     * @param privilegeId he privilege id
     * @param challenge The challenge in the token
     * @param iamToken The iamToken in the token
     * @return Pair of error code and authorization result code
     */
    ErrCode VerifyToken(const std::vector<uint8_t> &token, const std::string &privilege,
        const uint32_t pid, std::vector<uint8_t> &challenge, std::vector<uint8_t> &iamToken);

    /**
     * @brief Death recipient for monitoring application death.
     *
     * This inner class monitors the death of the calling application
     * and performs necessary cleanup.
     */
    class AppDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        AppDeathRecipient() = default;
        ~AppDeathRecipient() override = default;

        /**
         * @brief Called when the remote object dies.
         * @param remote The wptr to the dead remote object
         */
        void OnRemoteDied(const wptr<IRemoteObject>& remote) override;

    private:
        DISALLOW_COPY_AND_MOVE(AppDeathRecipient);
    };

private:
    /**
     * @brief Private constructor for singleton pattern.
     */
    InnerAuthorizationManager();

    /**
     * @brief Private destructor.
     */
    ~InnerAuthorizationManager();

    /**
     * @brief Verifies that the account is an admin account.
     * @param accountId The account ID to verify
     * @return Pair of error code and authorization result code
     */
    std::pair<ErrCode, AuthorizationResultCode> VerifyAdminAccount(int32_t accountId);

    /**
     * @brief Calls TA authorization interface to get token.
     * @param iamToken The IAM token
     * @param accountId The account ID
     * @param tokenResult Output token application result
     * @param info The connection ability information
     * @return ERR_OK on success, error code on failure
     */
    ErrCode CallTaAuthorization(const std::vector<uint8_t> &iamToken, int32_t accountId,
        ApplyUserTokenResult &tokenResult, ConnectAbilityInfo &info);

    /**
     * @brief Updates privilege cache with granted token.
     * @param info The connection ability information
     * @param tokenResult The token application result
     * @return ERR_OK on success, error code on failure
     */
    ErrCode UpdatePrivilegeCache(ConnectAbilityInfo &info, ApplyUserTokenResult &tokenResult);

    /**
     * @brief Initializes ConnectAbilityInfo from privilege definition and options.
     * @param pdef The privilege definition
     * @param options The authorization options
     * @param config The OS account configuration
     * @param info Output connect ability information
     */
    void InitializeConnectAbilityInfo(const PrivilegeBriefDef &pdef, const AcquireAuthorizationOptions &options,
        const OsAccountConfig &config, ConnectAbilityInfo &info);

    /**
     * @brief Starts UI extension connection for user interaction.
     * @param info The connect ability information
     * @param uiAbilityName The UI extension ability name
     * @param callback The authorization callback
     * @param result The authorization result
     * @param requestRemoteObj The requesting application remote object
     * @return ERR_OK on success, error code on failure
     */
    ErrCode StartUIExtensionConnection(const ConnectAbilityInfo &info, const std::string &uiAbilityName,
        const sptr<IAuthorizationCallback> &callback, const AuthorizationResult &result,
        const sptr<IRemoteObject> &requestRemoteObj);

    /**
     * @brief Starts service extension connection.
     * @param info The connect ability information
     * @param serviceAbilityName The service extension ability name
     * @param callback The authorization callback
     * @param result The authorization result
     * @param requestRemoteObj The requesting application remote object
     * @return ERR_OK on success, error code on failure
     */
    ErrCode StartServiceExtensionConnection(ConnectAbilityInfo &info, const std::string &serviceAbilityName,
        sptr<IAuthorizationCallback> &callback, AuthorizationResult &result,
        const sptr<IRemoteObject> &requestRemoteObj);

    DISALLOW_COPY_AND_MOVE(InnerAuthorizationManager);
};
}
}
#endif // OS_ACCOUNT_SERVICES_AUTHORIZATION_INCLUDE_INNER_AUTHORIZATION_MANAGER_H
