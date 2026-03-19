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

#ifndef OS_ACCOUNT_SERVICES_AUTHORIZATION_INCLUDE_OSACCOUNT_AUTHORIZATION_MANAGER_SERVICE_H
#define OS_ACCOUNT_SERVICES_AUTHORIZATION_INCLUDE_OSACCOUNT_AUTHORIZATION_MANAGER_SERVICE_H

#include <memory>
#include <stdint.h>
#include <sys/types.h>
#include "account_permission_manager.h"
#include "authorization_callback.h"
#include "authorization_common.h"
#include "authorization_stub.h"
#include "iadmin_authorization_callback.h"
#include "iauthorization_callback.h"
#include "ios_account_control.h"
#include "privileges_map.h"

namespace OHOS {
namespace AccountSA {
/**
 * @brief Service implementation for authorization management.
 *
 * This class implements the authorization service that handles
 * authorization requests from applications, including privilege
 * verification, user interaction, and token generation.
 */
class AuthorizationManagerService : public AuthorizationStub {
public:
    /**
     * @brief Constructor.
     */
    AuthorizationManagerService();

    /**
     * @brief Destructor.
     */
    ~AuthorizationManagerService() override;

    /**
     * @brief Acquires authorization for a specific privilege.
     *
     * This method initiates the authorization process for the requested privilege,
     * which may involve user interaction through a UI extension.
     *
     * @param privilege The privilege to authorize
     * @param options Authorization options (challenge, interaction allowed, etc.)
     * @param authorizationResultCallback Callback to receive authorization result
     * @param requestRemoteObj Remote object of the requesting application
     * @return ERR_OK on success, error code on failure
     */
    ErrCode AcquireAuthorization(const std::string &privilege, const AcquireAuthorizationOptions &options,
        const sptr<IRemoteObject> &authorizationResultCallback, const sptr<IRemoteObject> &requestRemoteObj) override;

    /**
     * @brief Releases authorization for a specific privilege.
     *
     * @param privilege The privilege to authorize
     * @return ERR_OK on success, error code on failure
     */
    ErrCode ReleaseAuthorization(const std::string &privilege) override;

    /**
     * @brief Registers the authorization application remote object.
     *
     * @param authAppRemoteObj The remote object to register
     * @return ERR_OK on success, error code on failure
     */
    ErrCode RegisterAuthAppRemoteObject(const sptr<IRemoteObject> &authAppRemoteObj) override;

    /**
     * @brief Unregisters the authorization application remote object.
     *
     * @return ERR_OK on success, error code on failure
     */
    ErrCode UnRegisterAuthAppRemoteObject() override;

    /**
     * @brief Check authorization for a specific privilege.
     * @param privilege The privilege to authorize
     * @param isAuthorized The result check privilege
     * @return ERR_OK on success, error code on failure
     */
    ErrCode CheckAuthorization(const std::string &privilege, bool &isAuthorized) override;

    /**
     * @brief Check authorization for a specific privilege.
     * @param privilege The privilege to authorize
     * @param pid The process id
     * @param isAuthorized The result check privilege
     * @return ERR_OK on success, error code on failure
     */
    ErrCode CheckAuthorization(const std::string &privilege, int32_t pid, bool &isAuthorized) override;

    /**
     * @brief Check authorization for a specific privilege and verify token.
     * @param token The token to verify
     * @param privilege The privilege to authorize
     * @param pid The process id
     * @param result The result of check
     * @return ERR_OK on success, error code on failure
     */
    ErrCode CheckAuthorizationToken(const std::vector<uint8_t> &token, const std::string &privilege, int32_t pid,
        CheckAuthorizationResult &result) override;

    /**
     * @brief Acquires authorization for the specified admin account.
     *
     * This method implements the server-side admin authorization logic, including:
     * 1. Permission verification (token type must be SHELL, requires ACCESS_USER_AUTH_INTERNAL permission)
     * 2. Find the account with the specified name and verify if it is admin type
     * 3. Call UserIAM for user authentication
     * 4. After successful authentication, call TA to issue authorization token
     * 5. Return authorization result through callback
     *
     * @param adminName The admin account name
     * @param challenge The challenge value for authorization verification
     * @param callback The callback object to receive authorization result
     * @return ERR_OK if request is successfully processed, error code on failure
     */
    ErrCode AcquireAdminAuthorization(const std::string &adminName, const std::vector<uint8_t> &challenge,
        const sptr<IRemoteObject> &callback) override;

private:
    ErrCode ValidateAdminAuthParams(const std::string &adminName, const sptr<IRemoteObject> &callback,
        sptr<IAdminAuthorizationCallback> &callbackProxy);
    ErrCode VerifyAdminAuthPermission();
    ErrCode FindAccountIdByName(const std::string &adminNameName, int32_t &accountId);

    ErrCode CheckSystemAppAndPermission(int32_t localId);
    ErrCode ValidateChallengeAndContext(const AcquireAuthorizationOptions &options, int32_t localId);
    ErrCode CheckCallbackAndConnections(const sptr<IAuthorizationCallback> &callback,
        const AcquireAuthorizationOptions &options, int32_t localId, AuthorizationResult &authorizationResult);
    ErrCode GetPrivilegeDefinition(AuthorizationResult &authorizationResult, PrivilegeBriefDef &def, int32_t localId);
    ErrCode HandleWhenReuse(AuthorizationResult &authorizationResult, const AcquireAuthorizationOptions &options,
        const sptr<IAuthorizationCallback> &callback, int32_t localId);

    /// OS account configuration
    OsAccountConfig config_;
};
}
}
#endif // OS_ACCOUNT_SERVICES_AUTHORIZATION_INCLUDE_OSACCOUNT_AUTHORIZATION_MANAGER_SERVICE_H