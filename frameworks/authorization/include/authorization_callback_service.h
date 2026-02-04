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

#ifndef AUTHORIZATION_FRAMEWORKS_AUTHORIZATION_INCLUDE_AUTHORIZATION_CALLBACK_SERVICE_H
#define AUTHORIZATION_FRAMEWORKS_AUTHORIZATION_INCLUDE_AUTHORIZATION_CALLBACK_SERVICE_H

#include "authorization_callback_stub.h"
#include "authorization_callback.h"
#include "authorization_common.h"

namespace OHOS {
namespace AccountSA {
/**
 * @brief Service implementation for authorization callback.
 *
 * This class acts as a wrapper around the inner AuthorizationCallback,
 * providing IPC stub functionality and cleanup capabilities.
 * It is used in the authorization flow to handle callbacks from the
 * authorization service and manage UI extension lifecycle.
 */
class AuthorizationCallbackService : public AuthorizationCallbackStub {
public:
    /**
     * @brief Constructor for AuthorizationCallbackService.
     * @param callback The inner authorization callback to forward events to
     * @param afterOnResult The cleanup function to call after OnResult completes
     */
    AuthorizationCallbackService(const std::shared_ptr<AuthorizationCallback> &callback,
        std::function<void()> afterOnResult);

    /**
     * @brief Destructor.
     */
    ~AuthorizationCallbackService() override;

    /**
     * @brief Handle authorization result callback.
     *
     * This method is called when the authorization process completes,
     * forwarding the result to the inner callback and executing cleanup.
     *
     * @param resultCode The result code from authorization service
     * @param result The authorization result containing token and other information
     * @return ERR_OK on success
     */
    ErrCode OnResult(int32_t resultCode, const AccountSA::AuthorizationResult& result) override;

    /**
     * @brief Handle connect ability callback for UI extension.
     *
     * This method is called when the authorization service needs to
     * create a UI extension for user interaction.
     *
     * @param info The connection ability information containing bundle name and ability name
     * @param callback The callback remote object for communication
     * @return ERR_OK on success
     */
    ErrCode OnConnectAbility(const AccountSA::ConnectAbilityInfo &info,
        const sptr<IRemoteObject> &callback) override;

private:
    /// The inner authorization callback to forward events to
    std::shared_ptr<AuthorizationCallback> innerCallback_ = nullptr;

    /// Cleanup function to call after OnResult completes
    std::function<void()> afterOnResult_ = nullptr;

    DISALLOW_COPY_AND_MOVE(AuthorizationCallbackService);
};
}
}
#endif // AUTHORIZATION_FRAMEWORKS_AUTHORIZATION_INCLUDE_AUTHORIZATION_CALLBACK_SERVICE_H