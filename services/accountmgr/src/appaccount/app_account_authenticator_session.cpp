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

#include "app_account_authenticator_session.h"

#include "ability_manager_adapter.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "app_account_authenticator_callback.h"
#include "app_account_authenticator_manager.h"
#include "app_account_common.h"
#include "bundle_manager_adapter.h"
#include "iservice_registry.h"
#include "want.h"

namespace OHOS {
namespace AccountSA {
SessionClientDeathRecipient::SessionClientDeathRecipient(AppAccountAuthenticatorSession *session) : session_(session)
{
    ACCOUNT_LOGI("enter");
}

void SessionClientDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    ACCOUNT_LOGI("enter");
    if (session_ != nullptr) {
        session_->OnClientDied();
    }
}

void SessionClientDeathRecipient::SetSession(AppAccountAuthenticatorSession *session)
{
    ACCOUNT_LOGI("enter");
    session_ = session;
}

SessionServerDeathRecipient::SessionServerDeathRecipient(AppAccountAuthenticatorSession *session) : session_(session)
{
    ACCOUNT_LOGI("enter");
}

void SessionServerDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    ACCOUNT_LOGI("enter");
    if (session_ != nullptr) {
        session_->OnServerDied();
    }
}

void SessionServerDeathRecipient::SetSession(AppAccountAuthenticatorSession *session)
{
    ACCOUNT_LOGI("enter");
    session_ = session;
}

SessionConnection::SessionConnection(AppAccountAuthenticatorSession *session) : session_(session)
{
    ACCOUNT_LOGI("enter");
}

SessionConnection::~SessionConnection()
{
    ACCOUNT_LOGI("enter");
}

void SessionConnection::OnAbilityConnectDone(
    const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode)
{
    ACCOUNT_LOGI("enter");
    if (session_ != nullptr) {
        session_->OnAbilityConnectDone(element, remoteObject, resultCode);
    }
}

void SessionConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode)
{
    ACCOUNT_LOGI("enter");
    if (session_ != nullptr) {
        session_->OnAbilityDisconnectDone(element, resultCode);
    }
}

void SessionConnection::SetSession(AppAccountAuthenticatorSession *session)
{
    ACCOUNT_LOGI("enter");
    session_ = session;
}

AppAccountAuthenticatorSession::AppAccountAuthenticatorSession(const std::string &action, const OAuthRequest &request)
    : action_(action), request_(request)
{
    ACCOUNT_LOGI("enter");
    Init();
}

AppAccountAuthenticatorSession::~AppAccountAuthenticatorSession()
{
    ACCOUNT_LOGI("enter");
    clientDeathRecipient_->SetSession(nullptr);
    serverDeathRecipient_->SetSession(nullptr);
    conn_->SetSession(nullptr);
    if ((authenticatorProxy_ != nullptr) && (authenticatorProxy_->AsObject() != nullptr)) {
        authenticatorProxy_->AsObject()->RemoveDeathRecipient(serverDeathRecipient_);
    }
    authenticatorProxy_ = nullptr;
    if ((request_.callback != nullptr) && (request_.callback->AsObject() != nullptr)) {
        request_.callback->AsObject()->RemoveDeathRecipient(clientDeathRecipient_);
    }
    request_.callback = nullptr;
    if (isConnected_) {
        AAFwk::AbilityManagerAdapter::GetInstance()->DisconnectAbility(conn_);
    }
    authenticatorCb_ = nullptr;
    clientDeathRecipient_ = nullptr;
    serverDeathRecipient_ = nullptr;
    sessionManager_ = nullptr;
    controlManager_ = nullptr;
    authenticatorMgr_ = nullptr;
}

void AppAccountAuthenticatorSession::Init()
{
    ACCOUNT_LOGI("enter");
    if (isInitialized_) {
        ACCOUNT_LOGE("session has been initialized");
        return;
    }

    conn_ = new (std::nothrow) SessionConnection(this);
    clientDeathRecipient_ = new (std::nothrow) SessionClientDeathRecipient(this);
    serverDeathRecipient_ = new (std::nothrow) SessionServerDeathRecipient(this);
    authenticatorCb_ = new (std::nothrow) AppAccountAuthenticatorCallback(this);
    sessionManager_ = AppAccountAuthenticatorSessionManager::GetInstance();
    controlManager_ = AppAccountControlManager::GetInstance();
    authenticatorMgr_ = AppAccountAuthenticatorManager::GetInstance();
    if ((conn_ == nullptr) || (clientDeathRecipient_ == nullptr)
        || (serverDeathRecipient_ == nullptr) || (authenticatorCb_ == nullptr) || (sessionManager_ == nullptr)
        || (controlManager_ == nullptr) || (authenticatorMgr_ == nullptr)) {
        conn_ = nullptr;
        clientDeathRecipient_ = nullptr;
        serverDeathRecipient_ = nullptr;
        authenticatorCb_ = nullptr;
        sessionManager_ = nullptr;
        controlManager_ = nullptr;
        authenticatorMgr_ = nullptr;
        return;
    }
    sessionId_ = std::to_string(reinterpret_cast<int64_t>(this));
    if ((request_.callback != nullptr) && (request_.callback->AsObject() != nullptr)) {
        request_.callback->AsObject()->AddDeathRecipient(clientDeathRecipient_);
    }
    userId_ = request_.callerUid / UID_TRANSFORM_DIVISOR;
    ownerUid_ = BundleManagerAdapter::GetInstance()->GetUidByBundleName(request_.owner, userId_);
    isInitialized_ = true;
}

ErrCode AppAccountAuthenticatorSession::Open()
{
    ACCOUNT_LOGI("enter");
    if (isOpened_) {
        ACCOUNT_LOGE("session has been opened");
        return ERR_APPACCOUNT_SERVICE_OAUTH_SERVICE_EXCEPTION;
    }
    if (!isInitialized_) {
        ACCOUNT_LOGE("session has not been initialized");
        return ERR_APPACCOUNT_SERVICE_OAUTH_SERVICE_EXCEPTION;
    }
    AuthenticatorInfo info;
    ErrCode errCode = authenticatorMgr_->GetAuthenticatorInfo(request_, info);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGI("authenticator not exist, owner: %{public}s, ownerUid: %{public}d",
            request_.owner.c_str(), ownerUid_);
        return errCode;
    }
    AAFwk::Want want;
    want.SetElementName(request_.owner, info.abilityName);
    errCode = AAFwk::AbilityManagerAdapter::GetInstance()->ConnectAbility(want, conn_, nullptr, userId_);
    if (errCode == ERR_OK) {
        isOpened_ = true;
    }
    ACCOUNT_LOGI("end");
    return errCode;
}

void AppAccountAuthenticatorSession::OnAbilityConnectDone(
    const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode)
{
    ACCOUNT_LOGI("enter");
    isConnected_ = true;
    AAFwk::Want errResult_;
    authenticatorProxy_ = iface_cast<IAppAccountAuthenticator>(remoteObject);
    if ((!authenticatorProxy_) || (!authenticatorProxy_->AsObject())) {
        ACCOUNT_LOGE("failed to cast app account authenticator proxy");
        OnResult(ERR_JS_OAUTH_SERVICE_EXCEPTION, errResult_);
        return;
    }
    authenticatorProxy_->AsObject()->AddDeathRecipient(serverDeathRecipient_);
    if (action_ == Constants::OAUTH_ACTION_AUTHENTICATE) {
        resultCode = authenticatorProxy_->Authenticate(request_.name, request_.authType, request_.callerBundleName,
            request_.options.GetParams(), authenticatorCb_->AsObject());
    } else if (action_ == Constants::OAUTH_ACTION_ADD_ACCOUNT_IMPLICITLY) {
        resultCode = authenticatorProxy_->AddAccountImplicitly(
            request_.authType, request_.callerBundleName, request_.options.GetParams(), authenticatorCb_->AsObject());
    } else {
        ACCOUNT_LOGE("unsupport action: %{public}s", action_.c_str());
        OnResult(ERR_JS_OAUTH_UNSUPPORT_ACTION, errResult_);
        return;
    }
    if (resultCode != ERR_OK) {
        OnResult(ERR_JS_OAUTH_SERVICE_EXCEPTION, errResult_);
    }
}

void AppAccountAuthenticatorSession::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode)
{
    ACCOUNT_LOGI("enter");
    isConnected_ = false;
}

void AppAccountAuthenticatorSession::OnClientDied()
{
    request_.callback = nullptr;
    if (isConnected_) {
        AAFwk::AbilityManagerAdapter::GetInstance()->DisconnectAbility(conn_);
    }
    sessionManager_->CloseSession(sessionId_);
}

void AppAccountAuthenticatorSession::OnServerDied()
{
    AAFwk::Want result;
    OnResult(ERR_JS_OAUTH_SERVICE_EXCEPTION, result);
}

int32_t AppAccountAuthenticatorSession::OnResult(int32_t resultCode, const AAFwk::Want &result) const
{
    ACCOUNT_LOGI("enter");
    if (resultCode == ERR_JS_SUCCESS) {
        if (action_ == Constants::OAUTH_ACTION_AUTHENTICATE) {
            resultCode = OnAuthenticateDone(result);
        } else if (action_ == Constants::OAUTH_ACTION_ADD_ACCOUNT_IMPLICITLY) {
            resultCode = OnAddAccountImplicitlyDone(result);
        } else {
            resultCode = ERR_JS_OAUTH_UNSUPPORT_ACTION;
        }
    }
    if ((request_.callback != nullptr) && (request_.callback->AsObject() != nullptr)) {
        request_.callback->OnResult(resultCode, result);
    }
    if (isConnected_) {
        AAFwk::AbilityManagerAdapter::GetInstance()->DisconnectAbility(conn_);
    }
    sessionManager_->CloseSession(sessionId_);
    return resultCode;
}

int32_t AppAccountAuthenticatorSession::OnRequestRedirected(AAFwk::Want &newRequest) const
{
    ACCOUNT_LOGI("enter");
    AAFwk::Want errResult_;
    AppExecFwk::ElementName element = newRequest.GetElement();
    if (element.GetBundleName() != request_.owner) {
        ACCOUNT_LOGE("invalid response");
        OnResult(ERR_JS_INVALID_RESPONSE, errResult_);
        return ERR_JS_SUCCESS;
    }
    if ((!request_.callback) || (!request_.callback->AsObject())) {
        ACCOUNT_LOGI("app account callback is nullptr");
        if (isConnected_) {
            AAFwk::AbilityManagerAdapter::GetInstance()->DisconnectAbility(conn_);
        }
        sessionManager_->CloseSession(sessionId_);
        return ERR_JS_SUCCESS;
    }
    if (action_ == Constants::OAUTH_ACTION_AUTHENTICATE) {
        newRequest.SetParam(Constants::KEY_NAME, request_.name);
    }
    newRequest.SetParam(Constants::KEY_ACTION, action_);
    newRequest.SetParam(Constants::KEY_SESSION_ID, sessionId_);
    newRequest.SetParam(Constants::KEY_AUTH_TYPE, request_.authType);
    newRequest.SetParam(Constants::KEY_CALLER_BUNDLE_NAME, request_.callerBundleName);
    newRequest.SetParam(Constants::KEY_CALLER_PID, request_.callerPid);
    newRequest.SetParam(Constants::KEY_CALLER_UID, request_.callerUid);
    request_.callback->OnRequestRedirected(newRequest);
    return ERR_JS_SUCCESS;
}

int32_t AppAccountAuthenticatorSession::UpdateAuthInfo(const AAFwk::Want &result) const
{
    std::string name = result.GetStringParam(Constants::KEY_NAME);
    std::string authType = result.GetStringParam(Constants::KEY_AUTH_TYPE);
    std::string token = result.GetStringParam(Constants::KEY_TOKEN);
    AppAccountInfo info(name, request_.owner);
    ErrCode errCode = ERR_OK;
    controlManager_->AddAccount(name, "", ownerUid_, request_.owner, info);
    if (!token.empty()) {
        OAuthRequest request = {
            .name = name,
            .authType = authType,
            .token = token,
            .callerBundleName = request_.owner,
            .callerUid = ownerUid_
        };
        errCode = controlManager_->SetOAuthToken(request);
    }
    if (authType == request_.authType) {
        OAuthRequest request = {
            .name = name,
            .authType = authType,
            .token = token,
            .bundleName = request_.callerBundleName,
            .callerBundleName = request_.owner,
            .isTokenVisible = true,
            .callerUid = ownerUid_
        };
        errCode = controlManager_->SetOAuthTokenVisibility(request);
    }
    return ConvertToJSErrCode(errCode);
}

int32_t AppAccountAuthenticatorSession::OnAuthenticateDone(const AAFwk::Want &result) const
{
    std::string name = result.GetStringParam(Constants::KEY_NAME);
    if (name != request_.name) {
        return ERR_JS_INVALID_RESPONSE;
    }
    return UpdateAuthInfo(result);
}

int32_t AppAccountAuthenticatorSession::OnAddAccountImplicitlyDone(const AAFwk::Want &result) const
{
    std::string name = result.GetStringParam(Constants::KEY_NAME);
    if (name.empty()) {
        return ERR_JS_INVALID_RESPONSE;
    }
    return UpdateAuthInfo(result);
}

void AppAccountAuthenticatorSession::GetRequest(OAuthRequest &request) const
{
    request = request_;
}

ErrCode AppAccountAuthenticatorSession::GetAuthenticatorCallback(
    const OAuthRequest &request, sptr<IRemoteObject> &callback) const
{
    ACCOUNT_LOGI("enter");
    callback = nullptr;
    if ((request.callerUid != ownerUid_) || (request.callerBundleName != request_.owner)) {
        ACCOUNT_LOGE("fail to get authenticator callback for permission denied");
        return ERR_APPACCOUNT_SERVICE_PERMISSION_DENIED;
    }
    if (!authenticatorCb_) {
        ACCOUNT_LOGE("session has not been initialized");
        return ERR_APPACCOUNT_SERVICE_OAUTH_AUTHENTICATOR_CALLBACK_NOT_EXIST;
    }
    callback = authenticatorCb_->AsObject();
    return ERR_OK;
}

std::string AppAccountAuthenticatorSession::GetSessionId() const
{
    return sessionId_;
}
}  // namespace AccountSA
}  // namespace OHOS
