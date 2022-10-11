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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_AUTHENTICATOR_SESSION_MANAGER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_AUTHENTICATOR_SESSION_MANAGER_H

#include "application_state_observer_stub.h"
#include "app_account_common.h"
#include "app_account_info.h"
#include "app_mgr_interface.h"
#include "app_mgr_proxy.h"
#include "iapp_account_authenticator_callback.h"
#include "iremote_object.h"
#include "singleton.h"
#include "want_params.h"

namespace OHOS {
namespace AccountSA {
class AppAccountAuthenticatorSession;
class AppAccountCheckLabelsSession;
class AppAccountAuthenticatorSessionManager;

class SessionAppStateObserver : public AppExecFwk::ApplicationStateObserverStub {
public:
    explicit SessionAppStateObserver();
    virtual ~SessionAppStateObserver() = default;

    void OnAbilityStateChanged(const AppExecFwk::AbilityStateData &abilityStateData) override;
};

class AppAccountAuthenticatorSessionManager : public DelayedSingleton<AppAccountAuthenticatorSessionManager> {
public:
    AppAccountAuthenticatorSessionManager();
    virtual ~AppAccountAuthenticatorSessionManager();

    ErrCode AddAccountImplicitly(const AuthenticatorSessionRequest &request);
    ErrCode Authenticate(const AuthenticatorSessionRequest &request);
    ErrCode CreateAccountImplicitly(const AuthenticatorSessionRequest &request);
    ErrCode Auth(const AuthenticatorSessionRequest &request);
    ErrCode GetAuthenticatorCallback(const AuthenticatorSessionRequest &request, sptr<IRemoteObject> &callback);
    ErrCode VerifyCredential(const AuthenticatorSessionRequest &request);
    ErrCode CheckAccountLabels(const AuthenticatorSessionRequest &request);
    ErrCode IsAccountRemovable(const AuthenticatorSessionRequest &request);
    ErrCode SelectAccountsByOptions(
        const std::vector<AppAccountInfo> accounts, const AuthenticatorSessionRequest &request);
    ErrCode SetAuthenticatorProperties(const AuthenticatorSessionRequest &request);
    void OnAbilityStateChanged(const AppExecFwk::AbilityStateData &abilityStateData);
    void Init();
    void CloseSession(const std::string &sessionId);
    ErrCode OpenSession(const std::shared_ptr<AppAccountAuthenticatorSession> &session);
    std::shared_ptr<AppAccountAuthenticatorSession> GetSession(const std::string &sessionId);
    void OnSessionServerDied(const std::string &sessionId);
    void OnSessionAbilityConnectDone(const std::string &sessionId, const AppExecFwk::ElementName &element,
        const sptr<IRemoteObject> &remoteObject, int32_t resultCode);
    void OnSessionAbilityDisconnectDone(
        const std::string &sessionId, const AppExecFwk::ElementName &element, int resultCode);
    void OnSessionResult(const std::string &sessionId, int32_t resultCode, const AAFwk::Want &result);
    void OnSessionRequestRedirected(const std::string &sessionId, AAFwk::Want &request);
    void OnSessionRequestContinued(const std::string &sessionId);

private:
    void RegisterApplicationStateObserver();
    void UnregisterApplicationStateObserver();

private:
    std::mutex mutex_;
    sptr<AppExecFwk::IAppMgr> iAppMgr_;
    sptr<SessionAppStateObserver> appStateObserver_;
    std::map<std::string, std::shared_ptr<AppAccountAuthenticatorSession>> sessionMap_;
    std::map<std::string, std::set<std::string>> abilitySessions_;
    bool isInitialized_ = false;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_AUTHENTICATOR_SESSION_MANAGER_H
