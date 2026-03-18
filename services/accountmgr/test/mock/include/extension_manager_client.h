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

#ifndef OS_ACCOUNT_SERVICE_MOCK_EXTENSION_MANAGER_CLIENT_H
#define OS_ACCOUNT_SERVICE_MOCK_EXTENSION_MANAGER_CLIENT_H

#include <iremote_broker.h>
#include <singleton.h>
#include "want.h"

namespace OHOS {
namespace AAFwk {

/**
 * @class MockExtensionManagerClient
 * Mock class for ExtensionManagerClient used in unit tests.
 */
class ExtensionManagerClient {
public:
    static ExtensionManagerClient &GetInstance();

    /**
     * ConnectServiceExtensionAbility, connect session with service extension ability.
     *
     * @param want, Special want for service extension type's ability.
     * @param connect, Callback used to notify caller the result of connecting or disconnecting.
     * @param callerToken, caller ability token.
     * @param userId, User ID.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode ConnectServiceExtensionAbility(
        const Want &want,
        const sptr<IRemoteObject> &connect,
        const sptr<IRemoteObject> &callerToken,
        int32_t userId = -1);

    /**
     * DisconnectAbility, disconnect session with service ability.
     *
     * @param connect, Callback used to notify caller the result of connecting or disconnecting.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode DisconnectAbility(const sptr<IRemoteObject> &connect);
private:
    ExtensionManagerClient() = default;
    ~ExtensionManagerClient() = default;
    DISALLOW_COPY_AND_MOVE(ExtensionManagerClient);
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICE_MOCK_EXTENSION_MANAGER_CLIENT_H
