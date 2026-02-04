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

#ifndef OS_ACCOUNT_SERVICES_AUTHORIZATION_INCLUDE_SERVICE_EXTENSION_CONNECT_H
#define OS_ACCOUNT_SERVICES_AUTHORIZATION_INCLUDE_SERVICE_EXTENSION_CONNECT_H

#include <atomic>
#include <string>
#include <mutex>
#include <condition_variable>
#include "ability_connection.h"
#include "iauthorization_callback.h"

namespace OHOS {
namespace AccountSA {
/**
 * @brief Manages UI extension connections for authorization.
 *
 * This singleton class handles the connection lifecycle between the
 * authorization service and UI extensions, including connection
 * establishment, result handling, and cleanup.
 */
class SessionAbilityConnection {
public:
    /**
     * @brief Gets the singleton instance.
     * @return Reference to the singleton instance
     */
    static SessionAbilityConnection &GetInstance();

    /**
     * @brief Connects to a UI extension for user interaction.
     *
     * @param info The connection ability information
     * @param callback The callback to receive authorization result
     * @param authorizationResult Output authorization result
     * @return ERR_OK on success, error code on failure
     */
    ErrCode SessionConnectExtension(const ConnectAbilityInfo &info, sptr<IAuthorizationCallback> &callback,
        AuthorizationResult &authorizationResult);

    /**
     * @brief Gets connection information for a calling UID.
     *
     * @param callingUid The UID of the calling process
     * @param info Output connection ability information
     */
    void GetConnectInfo(int32_t callingUid, ConnectAbilityInfo &info);

    /**
     * @brief Saves authorization result after successful authorization.
     *
     * @param errCode The result code from authorization service
     * @param iamToken The IAM token
     * @param accountId The account ID
     * @param remainValidityTime Remaining validity time of the token
     * @return ERR_OK on success, error code on failure
     */
    ErrCode SaveAuthorizationResult(ErrCode errCode, AuthorizationResultCode &resultCode,
        const std::vector<uint8_t> &iamToken, int32_t remainValidityTime);

    /**
     * @brief Checks if there is an active service connection.
     * @return true if connected, false otherwise
     */
    bool HasServiceConnect();

    /**
     * @brief Disconnects the UI extension.
     */
    void SessionDisconnectExtension();

    /**
     * @brief Registers the authorization application remote object.
     *
     * @param callingUid The UID of the calling process
     * @param authAppRemoteObj The remote object to register
     * @return ERR_OK on success, error code on failure
     */
    ErrCode RegisterAuthAppRemoteObject(int32_t callingUid, const sptr<IRemoteObject> &authAppRemoteObj);

    /**
     * @brief Unregisters the authorization application remote object.
     *
     * @param callingUid The UID of the calling process
     * @return ERR_OK on success, error code on failure
     */
    ErrCode UnRegisterAuthAppRemoteObject(int32_t callingUid);

    /**
     * @brief Callback handler for authorization result.
     *
     * This method is called when the authorization process completes,
     * updating the stored authorization result.
     *
     * @param errCode The result code from authorization service
     * @param resultCode The authorization result code (default: AUTHORIZATION_SUCCESS)
     * @return ERR_OK on success, error code on failure
     */
    ErrCode CallbackOnResult(int32_t errCode,
        AuthorizationResultCode resultCode = AuthorizationResultCode::AUTHORIZATION_SUCCESS);

    /**
     * @brief Death recipient for monitoring authorization application death.
     *
     * This inner class monitors the death of the authorization application
     * and performs necessary cleanup operations.
     */
    class AppDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        /**
         * @brief Constructor.
         * @param bundleName The bundle name of the authorization application
         */
        explicit AppDeathRecipient(std::string &bundleName)
        {
            bundleName_ = bundleName;
        }

        ~AppDeathRecipient() override = default;

        /**
         * @brief Called when the remote object dies.
         * @param remote The wptr to the dead remote object
         */
        void OnRemoteDied(const wptr<IRemoteObject>& remote) override;

    private:
        /// Bundle name of the authorization application
        std::string bundleName_;
        DISALLOW_COPY_AND_MOVE(AppDeathRecipient);
    };

    /**
     * @brief Death recipient for monitoring authorization app death.
     *
     * This inner class monitors the death of the authorization app
     * and performs necessary cleanup operations.
     */
    class AuthAppDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        AuthAppDeathRecipient() = default;
        ~AuthAppDeathRecipient() override = default;

        /**
         * @brief Called when the remote object dies.
         * @param remote The wptr to the dead remote object
         */
        void OnRemoteDied(const wptr<IRemoteObject>& remote) override;

    private:
        DISALLOW_COPY_AND_MOVE(AuthAppDeathRecipient);
    };

    /**
     * @brief Stub class for ability connection.
     *
     * This class implements the ability connection stub interface,
     * handling connection callbacks from the ability framework.
     */
    class SessionAbilityConnectionStub : public AAFwk::AbilityConnectionStub {
    public:
        /**
         * @brief Constructor.
         * @param info The connection ability information
         */
        explicit SessionAbilityConnectionStub(const ConnectAbilityInfo &info);

        /**
         * @brief Destructor.
         */
        virtual ~SessionAbilityConnectionStub() = default;

        /**
         * @brief Called when ability connection completes.
         * @param element The element name of the ability
         * @param remoteObject The remote object
         * @param resultCode The result code of the connection
         */
        void OnAbilityConnectDone(const AppExecFwk::ElementName &element,
            const sptr<IRemoteObject> &remoteObject, int32_t resultCode) override;

        /**
         * @brief Called when ability disconnection completes.
         * @param element The element name of the ability
         * @param resultCode The result code of the disconnection
         */
        void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int32_t resultCode) override;

        /**
         * @brief Generates connection parameters.
         * @param parameters Output string containing connection parameters
         * @return true if successful, false otherwise
         */
        bool GenerateParameters(std::string &parameters);

    private:
        /**
         * @brief Validates ability connection result.
         * @param resultCode The result code of the connection
         * @return true if valid, false otherwise
         */
        bool ValidateConnectionResult(int32_t resultCode);

        /**
         * @brief Sends connection request to remote object.
         * @param remoteObject The remote object to send request to
         * @return ERR_OK on success, error code on failure
         */
        ErrCode SendConnectionRequest(const sptr<IRemoteObject> &remoteObject);

        /// The connection ability information
        ConnectAbilityInfo info_;
        /// The local ID for the connection
        int32_t localId_ = -1;
    };

private:
    /**
     * @brief Private constructor for singleton pattern.
     */
    explicit SessionAbilityConnection() = default;

    /**
     * @brief Private destructor.
     */
    ~SessionAbilityConnection() = default;

    /**
     * @brief Creates and adds death recipient for callback.
     * @param callback The authorization callback
     * @return ERR_OK on success, error code on failure
     */
    ErrCode CreateCallbackDeathRecipient(const sptr<IAuthorizationCallback> &callback);

    /**
     * @brief Creates ability connection stub and connects to service extension.
     * @param info The connection ability information
     * @param callback The authorization callback
     * @param authorizationResult The authorization result
     * @return ERR_OK on success, error code on failure
     */
    ErrCode CreateStubAndConnect(const ConnectAbilityInfo &info,
        const sptr<IAuthorizationCallback> &callback, const AuthorizationResult &authorizationResult);

    DISALLOW_COPY_AND_MOVE(SessionAbilityConnection);

    ErrCode errCode_ = ERR_OK;
    /// The authorization callback to receive results
    sptr<IAuthorizationCallback> callback_;
    /// The cached authorization result
    AuthorizationResult authResult_;
    /// The connection ability information
    ConnectAbilityInfo info_;
    /// Mutex for protecting access to connection state
    std::recursive_mutex mutex_;
    /// Stub for ability connection
    sptr<SessionAbilityConnectionStub> abilityConnectionStub_;
    /// Remote object of the authorization app
    sptr<IRemoteObject> authAppRemoteObj_;
    /// UID of the authorization app
    int32_t authAppUid_ = -1;
    /// The local ID for the connection
    int32_t localId_ = -1;
    /// Flag indicating whether authorization callback is registered
    std::atomic<bool> hasAuthCallback_ = false;
};
}
}

#endif // OS_ACCOUNT_SERVICES_AUTHORIZATION_INCLUDE_SERVICE_EXTENSION_CONNECT_H
