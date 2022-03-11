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
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "iremote_proxy.h"
#include "iapp_account_authenticator.h"
#include "iapp_account_authenticator_callback.h"
#include "want.h"

namespace OHOS {
namespace AccountSA {
class AppAccountAuthenticatorSession;
namespace {
class ClientDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    ClientDeathRecipient(AppAccountAuthenticatorSession *session);
    virtual ~ClientDeathRecipient() = default;

    virtual void OnRemoteDied(const wptr<IRemoteObject> &remote);
    void SetSession(AppAccountAuthenticatorSession *session);
private:
    AppAccountAuthenticatorSession *session_;
};

class ServerDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    ServerDeathRecipient(AppAccountAuthenticatorSession *session);
    virtual ~ServerDeathRecipient() = default;

    virtual void OnRemoteDied(const wptr<IRemoteObject> &remote);
    void SetSession(AppAccountAuthenticatorSession *session);
private:
    AppAccountAuthenticatorSession *session_;
};

class SessionConnection : public AAFwk::AbilityConnectionStub {
public:
    SessionConnection(AppAccountAuthenticatorSession *session);
    virtual ~SessionConnection();

    void OnAbilityConnectDone(
        const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int32_t resultCode) override;
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode) override;
    void SetSession(AppAccountAuthenticatorSession *session);
private:
    AppAccountAuthenticatorSession *session_;
};
}

class AppAccountAuthenticatorSession {
public:
    AppAccountAuthenticatorSession(const std::string &action, const OAuthRequest &request);
    ~AppAccountAuthenticatorSession();
    void Init();
    ErrCode Open();
    ErrCode Close();
    void OnAbilityConnectDone(
        const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int32_t resultCode);
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode);
    void OnClientDied();
    void OnServerDied();
    int32_t OnResult(int32_t resultCode, const AAFwk::Want &result) const;
    int32_t OnRequestRedirected(AAFwk::Want &request) const;
    std::string GetSessionId() const;
    void GetRequest(OAuthRequest &request) const;
    ErrCode GetAuthenticatorCallback(const OAuthRequest &request, sptr<IRemoteObject> &callback) const;
private:
    sptr<AppExecFwk::IBundleMgr> GetBundleMgrProxy();
    int32_t UpdateAuthInfo(const AAFwk::Want &result) const;
    int32_t OnAuthenticateDone(const AAFwk::Want &result) const;
    int32_t OnAddAccountImplicitlyDone(const AAFwk::Want &result) const;
private:
    std::string action_;
    std::string sessionId_;
    OAuthRequest request_;
    sptr<SessionConnection> conn_ = nullptr;
    sptr<ClientDeathRecipient> clientDeathRecipient_ = nullptr;
    sptr<ServerDeathRecipient> serverDeathRecipient_ = nullptr;
    sptr<IAppAccountAuthenticatorCallback> authenticatorCb_ = nullptr;
    sptr<IAppAccountAuthenticator> authenticatorProxy_ = nullptr;
    std::shared_ptr<AppAccountAuthenticatorSessionManager> sessionManager_ = nullptr;
    std::shared_ptr<AppAccountControlManager> controlManager_ = nullptr;
    std::shared_ptr<AppAccountAuthenticatorManager> authenticatorMgr_ = nullptr;
    pid_t ownerUid_;
    bool isInitialized_ = false;
    bool isOpened_ = false;
    bool isConnected_ = false;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_AUTHENTICATOR_SESSION_H