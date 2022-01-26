/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "app_account_data_storage.h"
#include "app_account_info.h"
#include "iapp_account_event.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "ohos_account_kits.h"
#include "singleton.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AccountSA {
namespace {
    constexpr int32_t ABILITY_STATE_TERMINATED = 4;
}
AppAccountAuthenticatorSessionManager::AppAccountAuthenticatorSessionManager()
{
    ACCOUNT_LOGI("enter");
    Init();
}

AppAccountAuthenticatorSessionManager::~AppAccountAuthenticatorSessionManager()
{
    ACCOUNT_LOGI("enter");
    if (!isInitialized_) {
        return;
    }
    for (auto it = sessionMap_.begin(); it != sessionMap_.end(); ++it) {
        it->second->Close();
    }
    sessionMap_.clear();
    iAppMgr_->UnregisterApplicationStateObserver(this);
    iAppMgr_ = nullptr;
}

void AppAccountAuthenticatorSessionManager::Init()
{
    ACCOUNT_LOGI("enter");
    if (isInitialized_) {
        ACCOUNT_LOGI("app account session manager has been initialized");
        return;
    }
    sessionMap_.clear();
    sptr<ISystemAbilityManager> samgrClient = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrClient == nullptr) {
        ACCOUNT_LOGE("failed to system ability manager");
        return;
    }
    iAppMgr_ = iface_cast<AppExecFwk::IAppMgr>(
        samgrClient->GetSystemAbility(APP_MGR_SERVICE_ID));
    if (iAppMgr_ == nullptr) {
        ACCOUNT_LOGE("failed to get ability manager service");
        return;
    }
    iAppMgr_->RegisterApplicationStateObserver(this);
    isInitialized_ = true;
}

ErrCode AppAccountAuthenticatorSessionManager::AddAccountImplicitly(const OAuthRequest &request)
{
    ACCOUNT_LOGI("enter");
    return OpenSession(Constants::OAUTH_ACTION_ADD_ACCOUNT_IMPLICITLY, request);
}

ErrCode AppAccountAuthenticatorSessionManager::Authenticate(const OAuthRequest &request)
{
    ACCOUNT_LOGI("enter");
    return OpenSession(Constants::OAUTH_ACTION_AUTHENTICATE, request);
}

ErrCode AppAccountAuthenticatorSessionManager::OpenSession(const std::string &action, const OAuthRequest &request)
{
    ACCOUNT_LOGI("enter");
    if (!isInitialized_) {
        Init();
    }
    AAFwk::Want errResult;
    errResult.SetParam(Constants::KEY_NAME, request.name);
    errResult.SetParam(Constants::KEY_AUTH_TYPE, request.authType);
    std::lock_guard<std::mutex> lock(mutex_);
    if (sessionMap_.size() == SESSION_MAX_NUM) {
        ACCOUNT_LOGE("app account mgr service is busy");
        if ((request.callback != nullptr) && (request.callback->AsObject() != nullptr)) {
            request.callback->OnResult(ERR_JS_OAUTH_SERVICE_BUSY, errResult);
        }
        return ERR_APPACCOUNT_SERVICE_OAUTH_BUSY;
    }
    auto session = std::make_shared<AppAccountAuthenticatorSession>(action, request);
    if (session == nullptr) {
        if ((request.callback != nullptr) && (request.callback->AsObject() != nullptr)) {
            request.callback->OnResult(ERR_JS_APP_ACCOUNT_SERVICE_EXCEPTION, errResult);
        }
        return ERR_APPACCOUNT_SERVICE_OAUTH_SERVICE_EXCEPTION;
    }
    std::string sessionId = session->GetSessionId();
    sessionMap_.emplace(sessionId, session);
    auto it = abilitySessions_.find(request.callerAbilityName);
    if (it != abilitySessions_.end()) {
        it->second.emplace(sessionId);
    } else {
        std::set<std::string> sessionSet;
        sessionSet.emplace(sessionId);
        abilitySessions_.emplace(request.callerAbilityName, sessionSet);
    }
    return session->Open();
}

ErrCode AppAccountAuthenticatorSessionManager::GetAuthenticatorCallback(
    const OAuthRequest &request, sptr<IRemoteObject> &callback)
{
    ACCOUNT_LOGI("enter");
    if (!isInitialized_) {
        Init();
    }
    callback = nullptr;
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessionMap_.find(request.sessionId);
    if ((it == sessionMap_.end()) || (it->second == nullptr)) {
        ACCOUNT_LOGE("failed to find a session by id=%{public}s.", request.sessionId.c_str());
        return ERR_APPACCOUNT_SERVICE_OAUTH_SESSION_NOT_EXIST;
    }
    return it->second->GetAuthenticatorCallback(request, callback);
}

void AppAccountAuthenticatorSessionManager::OnAbilityStateChanged(const AppExecFwk::AbilityStateData &abilityStateData)
{
    ACCOUNT_LOGI("enter");
    if (abilityStateData.abilityState != ABILITY_STATE_TERMINATED) {
        return;
    }
    ACCOUNT_LOGI("ability terminated: %{public}s, pid: %{public}d, uid: %{public}d",
        abilityStateData.abilityName.c_str(), abilityStateData.pid, abilityStateData.uid);
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = abilitySessions_.find(abilityStateData.abilityName);
    if (it == abilitySessions_.end()) {
        return;
    }
    for (auto sessionId : it->second) {
        ACCOUNT_LOGI("session{id=%{public}s} has been cleared", sessionId.c_str());
        auto sessionIt = sessionMap_.find(sessionId);
        if ((sessionIt != sessionMap_.end()) && (sessionIt->second->Close() == ERR_OK)) {
            sessionMap_.erase(sessionIt);
        }
    }
    abilitySessions_.erase(it);
}

void AppAccountAuthenticatorSessionManager::CloseSession(const std::string &sessionId)
{
    ACCOUNT_LOGI("enter");
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessionMap_.find(sessionId);
    if (it == sessionMap_.end()) {
        ACCOUNT_LOGI("session not exist, sessionId=%{public}s", sessionId.c_str());
        return;
    }
    OAuthRequest request;
    it->second->GetRequest(request);
    if (it->second->Close() != ERR_OK) {
        return;
    }
    sessionMap_.erase(it);
    auto asIt = abilitySessions_.find(request.callerAbilityName);
    if (asIt != abilitySessions_.end()) {
        asIt->second.erase(sessionId);
    }
}
}  // namespace AccountSA
}  // namespace OHOS
