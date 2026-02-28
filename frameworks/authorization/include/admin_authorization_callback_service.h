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

#ifndef AUTHORIZATION_FRAMEWORKS_AUTHORIZATION_INCLUDE_ADMIN_AUTHORIZATION_CALLBACK_SERVICE_H
#define AUTHORIZATION_FRAMEWORKS_AUTHORIZATION_INCLUDE_ADMIN_AUTHORIZATION_CALLBACK_SERVICE_H

#include "admin_authorization_callback_stub.h"
#include "authorization_common.h"

namespace OHOS {
namespace AccountSA {
/**
 * @brief service implemention for admin authorization callback.
 *
 * This class acts as a wrapper aound the inner AdminAuthorizationCallback,
 * providing IPC stub functionality and cleanup capaibilities.
 * It is used in the authorization flow to handle callbacks from the
 * authorization service and manage UI extension lifecycle.
 */
class AdminAuthorizationCallbackService : public AdminAuthorizationCallbackStub {
public:
    /**
     * @brief Constructor for AdminAuthorizationCallback.
     * @param callback The inner authorization callback to forward events to
     */
    explicit AdminAuthorizationCallbackService(const std::shared_ptr<AdminAuthorizationCallback> &callback);

    /**
     * @brief Destructor.
     */
    ~AdminAuthorizationCallbackService() override = default;

    /**
     * @brief Handle connect ability callback for UI extension.
     *
     * This method is called when the authorization service needs to
     * create a UI extension for user interaction.
     *
     * @param authResult The result code from authorization service
     * @return ERR_OK on success
     */
    ErrCode OnResult(const AdminAuthorizationResult &authResult) override;

private:
    /// The inner authorization callback to forward events to
    std::shared_ptr<AdminAuthorizationCallback> innerCallback_ = nullptr;

    DISALLOW_COPY_AND_MOVE(AdminAuthorizationCallbackService);
};
}
} // namespace AccountSA
#endif // AUTHORIZATION_FRAMEWORKS_AUTHORIZATION_INCLUDE_ADMIN_AUTHORIZATION_CALLBACK_SERVICE_H
