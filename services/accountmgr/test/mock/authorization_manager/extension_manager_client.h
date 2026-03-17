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

#ifndef MOCK_EXTENSION_MANAGER_CLIENT_H
#define MOCK_EXTENSION_MANAGER_CLIENT_H

#include "iremote_object.h"
#include "want.h"

namespace OHOS {
namespace AAFwk {
class ExtensionManagerClient {
public:
    static ExtensionManagerClient& GetInstance();
    int32_t ConnectServiceExtensionAbility(const Want &want, const sptr<IRemoteObject> &connect,
        const sptr<IRemoteObject> &token, int32_t userId);
    int32_t DisconnectAbility(const sptr<IRemoteObject> &connect);
public:
    int32_t connectResult_ = 0;
    int32_t disconnectResult_ = 0;
};
}
}

#endif // MOCK_EXTENSION_MANAGER_CLIENT_H