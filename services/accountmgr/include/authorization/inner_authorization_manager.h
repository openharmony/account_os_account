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

namespace OHOS {
namespace AccountSA {
class ConnectAbilityCallback : public ConnectAbilityCallbackStub {
public:
    ConnectAbilityCallback(int32_t callingPid, const sptr<IRemoteObject> &authorizationResultCallback,
        const AuthorizationResult &result);
    ErrCode OnResult(int32_t resultCode, const std::vector<uint8_t> &iamToken) override;
private:
    sptr<IRemoteObject> authorizationResultCallback_ = nullptr;
    AuthorizationResult result_;
    int32_t callingPid_ = -1;
};

class InnerAuthorizationManager {
public:
    static InnerAuthorizationManager &GetInstance();
    ErrCode AcquireAuthorization(const std::string &privilege, const AcquireAuthorizationOptions &options,
        const sptr<IRemoteObject> &authorizationResultCallback);
private:
    InnerAuthorizationManager();
    ~InnerAuthorizationManager();
    DISALLOW_COPY_AND_MOVE(InnerAuthorizationManager);
};
}
}
#endif // OS_ACCOUNT_SERVICES_AUTHORIZATION_INCLUDE_INNER_AUTHORIZATION_MANAGER_H