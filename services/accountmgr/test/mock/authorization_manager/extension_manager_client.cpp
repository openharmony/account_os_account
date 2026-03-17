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

#include "extension_manager_client.h"

namespace OHOS {
namespace AAFwk {
ExtensionManagerClient& ExtensionManagerClient::GetInstance()
{
    static ExtensionManagerClient instance;
    return instance;
}

int32_t ExtensionManagerClient::ConnectServiceExtensionAbility(const Want &want, const sptr<IRemoteObject> &connect,
    const sptr<IRemoteObject> &token, int32_t userId)
{
    int32_t temp = connectResult_;
    connectResult_ = 0;
    return temp;
}
int32_t ExtensionManagerClient::DisconnectAbility(const sptr<IRemoteObject> &connect)
{
    int32_t temp = disconnectResult_;
    disconnectResult_ = 0;
    return temp;
}
}
}