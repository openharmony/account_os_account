/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_AUTHENTICATOR_SESSION_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_AUTHENTICATOR_SESSION_H

#include <string>
#include "ability_connect_callback_stub.h"
#include "app_account_authenticator_session_manager.h"
#include "app_account_control_manager.h"
#include "iremote_proxy.h"
#include "iapp_account_authenticator.h"
#include "iapp_account_authenticator_callback.h"
#include "want.h"

namespace OHOS {
namespace AccountSA {
class AppAccountAuthenticatorSession;

class SessionClientDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit SessionClientDeathRecipient(const std::string &sessionId);
    virtual ~SessionClientDeathRecipient() = default;

    virtual void OnRemoteDied(const wptr<IRemoteObject> &remote);

private:
    std::string sessionId_;
};

class SessionServerDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit SessionServerDeathRecipient(const std::string &sessionId);
    virtual ~SessionServerDeathRecipient() = default;

    virtual void OnRemoteDied(const wptr<IRemoteObject> &remote);

private:
    std::string sessionId_;
};

class SessionConnection : public AAFwk::AbilityConnectionStub {
public:
    explicit SessionConnection(const std::string &sessionId);
    virtual ~SessionConnection();

    void OnAbilityConnectDone(
        const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int32_t resultCode) override;
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode) override;

private:
    std::string sessionId_;
};

class AppAccountAuthenticatorSession {
public:
    AppAccountAuthenticatorSession(AuthenticatorAction action, const AuthenticatorSessionRequest &request);
    virtual ~AppAccountAuthenticatorSession();
    virtual ErrCode Open();
    virtual void Close();
    virtual void GetRequest(AuthenticatorSessionRequest &request) const;
    std::string GetSessionId() const;
    void OnAbilityConnectDone(
        const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int32_t resultCode);
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode);
    void OnServerDied();
    int32_t OnResult(int32_t resultCode, const AAFwk::Want &result) const;
    int32_t OnRequestRedirected(AAFwk::Want &request) const;
    int32_t OnRequestContinued() const;
    ErrCode GetAuthenticatorCallback(const AuthenticatorSessionRequest &request, sptr<IRemoteObject> &callback) const;
    ErrCode AddClientDeathRecipient();

protected:
    AuthenticatorAction action_;
    AuthenticatorSessionRequest request_;
    std::string sessionId_;
    bool isOpened_ = false;

private:
    void Init();
    void CloseSelf() const;
    int32_t UpdateAuthInfo(const AAFwk::Want &result) const;
    int32_t OnAuthenticateDone(const AAFwk::Want &result) const;
    int32_t OnAddAccountImplicitlyDone(const AAFwk::Want &result) const;

private:
    sptr<SessionConnection> conn_ = nullptr;
    sptr<SessionClientDeathRecipient> clientDeathRecipient_ = nullptr;
    sptr<SessionServerDeathRecipient> serverDeathRecipient_ = nullptr;
    sptr<IAppAccountAuthenticatorCallback> authenticatorCb_ = nullptr;
    sptr<IAppAccountAuthenticator> authenticatorProxy_ = nullptr;
    std::shared_ptr<AppAccountControlManager> controlManager_ = nullptr;
    std::shared_ptr<AppAccountAuthenticatorManager> authenticatorMgr_ = nullptr;
    int32_t userId_;
    pid_t ownerUid_;
    bool isInitialized_ = false;
    bool isConnected_ = false;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_AUTHENTICATOR_SESSION_H
