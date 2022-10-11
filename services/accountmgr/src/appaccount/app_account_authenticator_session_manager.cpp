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

#include "app_account_authenticator_session_manager.h"

#include "account_log_wrapper.h"
#include "app_account_authenticator_session.h"
#include "app_account_check_labels_session.h"
#include "app_mgr_constants.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AccountSA {
namespace {
constexpr size_t SESSION_MAX_NUM = 256;
}

SessionAppStateObserver::SessionAppStateObserver()
{}

void SessionAppStateObserver::OnAbilityStateChanged(const AppExecFwk::AbilityStateData &abilityStateData)
{
    auto sessionManager = AppAccountAuthenticatorSessionManager::GetInstance();
    if (sessionManager != nullptr) {
        sessionManager->OnAbilityStateChanged(abilityStateData);
    }
}

AppAccountAuthenticatorSessionManager::AppAccountAuthenticatorSessionManager()
{}

AppAccountAuthenticatorSessionManager::~AppAccountAuthenticatorSessionManager()
{
    UnregisterApplicationStateObserver();
    sessionMap_.clear();
    abilitySessions_.clear();
}

void AppAccountAuthenticatorSessionManager::RegisterApplicationStateObserver()
{
    if (appStateObserver_ != nullptr) {
        return;
    }
    appStateObserver_ = new (std::nothrow) SessionAppStateObserver();
    if (appStateObserver_ == nullptr) {
        ACCOUNT_LOGE("failed to create SessionAppStateObserver instance");
        return;
    }
    sptr<ISystemAbilityManager> samgrClient = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrClient == nullptr) {
        ACCOUNT_LOGE("failed to system ability manager");
        return;
    }
    iAppMgr_ = iface_cast<AppExecFwk::IAppMgr>(samgrClient->GetSystemAbility(APP_MGR_SERVICE_ID));
    if (iAppMgr_ == nullptr) {
        appStateObserver_ = nullptr;
        ACCOUNT_LOGE("failed to get ability manager service");
        return;
    }
    iAppMgr_->RegisterApplicationStateObserver(appStateObserver_);
}

void AppAccountAuthenticatorSessionManager::UnregisterApplicationStateObserver()
{
    if (iAppMgr_) {
        iAppMgr_->RegisterApplicationStateObserver(appStateObserver_);
    }
    iAppMgr_ = nullptr;
    appStateObserver_ = nullptr;
}

ErrCode AppAccountAuthenticatorSessionManager::AddAccountImplicitly(const AuthenticatorSessionRequest &request)
{
    auto session = std::make_shared<AppAccountAuthenticatorSession>(ADD_ACCOUNT_IMPLICITLY, request);
    return OpenSession(session);
}

ErrCode AppAccountAuthenticatorSessionManager::CreateAccountImplicitly(const AuthenticatorSessionRequest &request)
{
    auto session = std::make_shared<AppAccountAuthenticatorSession>(CREATE_ACCOUNT_IMPLICITLY, request);
    return OpenSession(session);
}

ErrCode AppAccountAuthenticatorSessionManager::Authenticate(const AuthenticatorSessionRequest &request)
{
    auto session = std::make_shared<AppAccountAuthenticatorSession>(AUTHENTICATE, request);
    return OpenSession(session);
}

ErrCode AppAccountAuthenticatorSessionManager::Auth(const AuthenticatorSessionRequest &request)
{
    auto session = std::make_shared<AppAccountAuthenticatorSession>(AUTH, request);
    return OpenSession(session);
}

ErrCode AppAccountAuthenticatorSessionManager::VerifyCredential(const AuthenticatorSessionRequest &request)
{
    auto session = std::make_shared<AppAccountAuthenticatorSession>(VERIFY_CREDENTIAL, request);
    return OpenSession(session);
}

ErrCode AppAccountAuthenticatorSessionManager::CheckAccountLabels(const AuthenticatorSessionRequest &request)
{
    auto session = std::make_shared<AppAccountAuthenticatorSession>(CHECK_ACCOUNT_LABELS, request);
    return OpenSession(session);
}

ErrCode AppAccountAuthenticatorSessionManager::IsAccountRemovable(const AuthenticatorSessionRequest &request)
{
    auto session = std::make_shared<AppAccountAuthenticatorSession>(IS_ACCOUNT_REMOVABLE, request);
    return OpenSession(session);
}

ErrCode AppAccountAuthenticatorSessionManager::SelectAccountsByOptions(
    const std::vector<AppAccountInfo> accounts, const AuthenticatorSessionRequest &request)
{
    auto session = std::make_shared<AppAccountCheckLabelsSession>(accounts, request);
    OpenSession(session);
    return session->CheckLabels();
}

ErrCode AppAccountAuthenticatorSessionManager::SetAuthenticatorProperties(const AuthenticatorSessionRequest &request)
{
    auto session = std::make_shared<AppAccountAuthenticatorSession>(SET_AUTHENTICATOR_PROPERTIES, request);
    return OpenSession(session);
}

ErrCode AppAccountAuthenticatorSessionManager::OpenSession(
    const std::shared_ptr<AppAccountAuthenticatorSession> &session)
{
    if (session == nullptr) {
        ACCOUNT_LOGE("failed to create AppAccountAuthenticatorSession");
        return ERR_APPACCOUNT_SERVICE_OAUTH_SERVICE_EXCEPTION;
    }
    std::string sessionId = session->GetSessionId();
    ErrCode result = ERR_OK;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (sessionMap_.size() == SESSION_MAX_NUM) {
            ACCOUNT_LOGD("app account mgr service is busy");
            return ERR_APPACCOUNT_SERVICE_OAUTH_BUSY;
        }
        result = session->Open();
        if (result != ERR_OK) {
            ACCOUNT_LOGE("failed to open session, result: %{public}d.", result);
            return result;
        }
        if (sessionMap_.size() == 0) {
            RegisterApplicationStateObserver();
        }
        sessionMap_.emplace(sessionId, session);
        AuthenticatorSessionRequest request;
        session->GetRequest(request);
        std::string key = request.callerAbilityName + std::to_string(request.callerUid);
        auto it = abilitySessions_.find(key);
        if (it != abilitySessions_.end()) {
            it->second.emplace(sessionId);
        } else {
            std::set<std::string> sessionSet;
            sessionSet.emplace(sessionId);
            abilitySessions_.emplace(key, sessionSet);
        }
    }
    session->AddClientDeathRecipient();
    return ERR_OK;
}

std::shared_ptr<AppAccountAuthenticatorSession> AppAccountAuthenticatorSessionManager::GetSession(
    const std::string &sessionId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessionMap_.find(sessionId);
    if (it == sessionMap_.end()) {
        return nullptr;
    }
    return it->second;
}

ErrCode AppAccountAuthenticatorSessionManager::GetAuthenticatorCallback(
    const AuthenticatorSessionRequest &request, sptr<IRemoteObject> &callback)
{
    callback = nullptr;
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessionMap_.find(request.sessionId);
    if ((it == sessionMap_.end()) || (it->second == nullptr)) {
        ACCOUNT_LOGE("failed to find a session by id=%{private}s.", request.sessionId.c_str());
        return ERR_APPACCOUNT_SERVICE_OAUTH_SESSION_NOT_EXIST;
    }
    return it->second->GetAuthenticatorCallback(request, callback);
}

void AppAccountAuthenticatorSessionManager::OnAbilityStateChanged(const AppExecFwk::AbilityStateData &abilityStateData)
{
    if (abilityStateData.abilityState != static_cast<int32_t>(AppExecFwk::AbilityState::ABILITY_STATE_TERMINATED)) {
        return;
    }
    std::string key = abilityStateData.abilityName + std::to_string(abilityStateData.uid);
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = abilitySessions_.find(key);
    if (it == abilitySessions_.end()) {
        return;
    }
    for (auto sessionId : it->second) {
        auto sessionIt = sessionMap_.find(sessionId);
        if (sessionIt != sessionMap_.end()) {
            ACCOUNT_LOGI("session{id=%{private}s} will be cleared", sessionId.c_str());
            sessionMap_.erase(sessionIt);
        }
    }
    abilitySessions_.erase(it);
}

void AppAccountAuthenticatorSessionManager::OnSessionServerDied(const std::string &sessionId)
{
    auto session = GetSession(sessionId);
    if (session != nullptr) {
        session->OnServerDied();
    }
}

void AppAccountAuthenticatorSessionManager::OnSessionAbilityConnectDone(const std::string &sessionId,
    const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int32_t resultCode)
{
    auto session = GetSession(sessionId);
    if (session != nullptr) {
        session->OnAbilityConnectDone(element, remoteObject, resultCode);
    }
}

void AppAccountAuthenticatorSessionManager::OnSessionAbilityDisconnectDone(
    const std::string &sessionId, const AppExecFwk::ElementName &element, int resultCode)
{
    auto session = GetSession(sessionId);
    if (session != nullptr) {
        session->OnAbilityDisconnectDone(element, resultCode);
    }
}

void AppAccountAuthenticatorSessionManager::OnSessionResult(
    const std::string &sessionId, int32_t resultCode, const AAFwk::Want &result)
{
    auto session = GetSession(sessionId);
    if (session != nullptr) {
        session->OnResult(resultCode, result);
    }
}

void AppAccountAuthenticatorSessionManager::OnSessionRequestRedirected(
    const std::string &sessionId, AAFwk::Want &request)
{
    auto session = GetSession(sessionId);
    if (session != nullptr) {
        session->OnRequestRedirected(request);
    }
}

void AppAccountAuthenticatorSessionManager::OnSessionRequestContinued(const std::string &sessionId)
{
    auto session = GetSession(sessionId);
    if (session != nullptr) {
        session->OnRequestContinued();
    }
}

void AppAccountAuthenticatorSessionManager::CloseSession(const std::string &sessionId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessionMap_.find(sessionId);
    if (it == sessionMap_.end()) {
        ACCOUNT_LOGI("session not exist, sessionId=%{private}s", sessionId.c_str());
        return;
    }
    AuthenticatorSessionRequest request;
    it->second->GetRequest(request);
    std::string key = request.callerAbilityName + std::to_string(request.callerUid);
    auto asIt = abilitySessions_.find(key);
    if (asIt != abilitySessions_.end()) {
        asIt->second.erase(sessionId);
    }
    sessionMap_.erase(it);
    if (sessionMap_.size() == 0) {
        iAppMgr_->UnregisterApplicationStateObserver(appStateObserver_);
    }
}
}  // namespace AccountSA
}  // namespace OHOS
