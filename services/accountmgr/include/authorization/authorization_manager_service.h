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

namespace OHOS {
namespace AccountSA {
class AuthorizationManagerService : public AuthorizationStub {
public:
    AuthorizationManagerService();
    ~AuthorizationManagerService() override;
    ErrCode AcquireAuthorization(const std::string &privilege, const AcquireAuthorizationOptions &options,
        const sptr<IRemoteObject> &authorizationResultCallback) override;
};
}
}
#endif // OS_ACCOUNT_SERVICES_AUTHORIZATION_INCLUDE_OSACCOUNT_AUTHORIZATION_MANAGER_SERVICE_H