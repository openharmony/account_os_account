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
#include "ios_account_control.h"

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

private:
    /// OS account configuration
    OsAccountConfig config_;
};
}
}
#endif // OS_ACCOUNT_SERVICES_AUTHORIZATION_INCLUDE_OSACCOUNT_AUTHORIZATION_MANAGER_SERVICE_H