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

#ifndef AUTHORIZATION_INNERKITS_AUTHORIZATIONT_INCLUDE_AUTHORIZATION_CLIENT_H
#define AUTHORIZATION_INNERKITS_AUTHORIZATIONT_INCLUDE_AUTHORIZATION_CLIENT_H

#include <string>
#include <vector>
#include "authorization_callback.h"
#include "authorization_common.h"
#include "iauthorization.h"

namespace OHOS {
namespace AccountSA {
class AuthorizationClient {
public:
    /**
     * Gets the instance of AuthorizationClient.
     *
     * @return the instance of AuthorizationClient.
     */
    static AuthorizationClient &GetInstance();

    /**
     * Acuqires an authorization for the target privilege.
     */
    ErrCode AcquireAuthorization(const std::string &privilege, const AcquireAuthorizationOptions &options,
        const std::shared_ptr<AuthorizationResultCallback> &callback);

private:
#ifdef SUPPORT_AUTHORIZATION
    class AuthorizationDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        AuthorizationDeathRecipient() = default;
        ~AuthorizationDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject>& remote) override;

    private:
        DISALLOW_COPY_AND_MOVE(AuthorizationDeathRecipient);
    };
    sptr<IAuthorization> GetAuthorizationProxy();
    void ResetAuthorizationProxy(const wptr<IRemoteObject> &remote);
#endif

private:
    AuthorizationClient();
    ~AuthorizationClient() = default;
    DISALLOW_COPY_AND_MOVE(AuthorizationClient);
private:
#ifdef SUPPORT_AUTHORIZATION
    std::mutex mutex_;
    sptr<IAuthorization> proxy_ = nullptr;
    sptr<AuthorizationDeathRecipient> deathRecipient_ = nullptr;
#endif
};
}
}
#endif // AUTHORIZATION_INNERKITS_AUTHORIZATIONT_INCLUDE_AUTHORIZATION_CLIENT_H