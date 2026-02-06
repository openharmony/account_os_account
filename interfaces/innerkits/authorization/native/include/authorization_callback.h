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

#ifndef AUTHORIZATION_INNERKITS_AUTHORIZATION_INCLUDE_AUTHORIZATION_CALLBACK_H
#define AUTHORIZATION_INNERKITS_AUTHORIZATION_INCLUDE_AUTHORIZATION_CALLBACK_H

#include <cstdint>
#include <iremote_broker.h>
#include <string_ex.h>
#include "authorization_common.h"

namespace OHOS {
namespace AccountSA {
/**
 * @brief Callback interface for authorization events.
 *
 * This class defines the callback interface that authorization clients
 * must implement to receive authorization results and handle UI extension
 * connections for user interaction.
 */
class AuthorizationCallback {
public:
    /**
     * @brief Called when authorization result is available.
     *
     * This method is invoked when the authorization process completes,
     * either successfully or with an error.
     *
     * @param resultCode The result code from authorization service
     * @param result The authorization result containing token and other information
     * @return ERR_OK on success
     */
    virtual ErrCode OnResult(int32_t resultCode, const AccountSA::AuthorizationResult& result) = 0;

    /**
     * @brief Called when UI extension connection is needed.
     *
     * This method is invoked when the authorization service requires
     * user interaction through a UI extension.
     *
     * @param info The connection ability information containing bundle name and ability name
     * @param callback The callback remote object for communication
     * @return ERR_OK on success
     */
    virtual ErrCode OnConnectAbility(const AccountSA::ConnectAbilityInfo &info,
        const sptr<IRemoteObject> &callback) = 0;
};
}
}
#endif // AUTHORIZATION_INNERKITS_AUTHORIZATION_INCLUDE_AUTHORIZATION_CALLBACK_H