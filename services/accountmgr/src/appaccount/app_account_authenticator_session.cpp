/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include <pthread.h>
#include <thread>
#include "ability_manager_adapter.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "app_account_authenticator_callback.h"
#include "app_account_authenticator_manager.h"
#include "app_account_common.h"
#include "bundle_manager_adapter.h"
#include "iservice_registry.h"

namespace OHOS {
namespace AccountSA {
namespace {
const char THREAD_AUTH_SESSION[] = "authSession";
ErrCode ConvertToAccountErrCode(ErrCode idlErrCode, int32_t funcResult)
{
    if (idlErrCode == ERR_OK) {
        return funcResult;
    }
    if (idlErrCode == ERR_INVALID_VALUE) {
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    } else if (idlErrCode == ERR_INVALID_DATA) {
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    } else {
        return ERR_APPACCOUNT_KIT_SEND_REQUEST;
    }
}
}

SessionClientDeathRecipient::SessionClientDeathRecipient(const std::string &sessionId) : sessionId_(sessionId)
{}

void SessionClientDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    (void)remote;
    AppAccountAuthenticatorSessionManager::GetInstance().CloseSession(sessionId_);
}

SessionServerDeathRecipient::SessionServerDeathRecipient(const std::string &sessionId) : sessionId_(sessionId)
{}

void SessionServerDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    (void)remote;
    AppAccountAuthenticatorSessionManager::GetInstance().OnSessionServerDied(sessionId_);
}

SessionConnection::SessionConnection(const std::string &sessionId) : sessionId_(sessionId)
{}

SessionConnection::~SessionConnection()
{}

void SessionConnection::OnAbilityConnectDone(
    const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int32_t resultCode)
{
    AppAccountAuthenticatorSessionManager::GetInstance().OnSessionAbilityConnectDone(
        sessionId_, element, remoteObject, resultCode);
}

void SessionConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode)
{
    AppAccountAuthenticatorSessionManager::GetInstance().OnSessionAbilityDisconnectDone(
        sessionId_, element, resultCode);
}

AppAccountAuthenticatorSession::AppAccountAuthenticatorSession(
    AuthenticatorAction action, const AuthenticatorSessionRequest &request)
    : action_(action), request_(request)
{
    Init();
}

AppAccountAuthenticatorSession::~AppAccountAuthenticatorSession()
{
    if (isOpened_) {
        Close();
    }
}

void AppAccountAuthenticatorSession::Init()
{
    if (isInitialized_) {
        ACCOUNT_LOGE("session has been initialized");
        return;
    }

    sessionId_ = std::to_string(reinterpret_cast<int64_t>(this));
    conn_ = new (std::nothrow) SessionConnection(sessionId_);
    clientDeathRecipient_ = new (std::nothrow) SessionClientDeathRecipient(sessionId_);
    serverDeathRecipient_ = new (std::nothrow) SessionServerDeathRecipient(sessionId_);
    authenticatorCb_ = new (std::nothrow) AppAccountAuthenticatorCallback(sessionId_);
    if ((conn_ == nullptr) || (clientDeathRecipient_ == nullptr)
        || (serverDeathRecipient_ == nullptr) || (authenticatorCb_ == nullptr)) {
        conn_ = nullptr;
        clientDeathRecipient_ = nullptr;
        serverDeathRecipient_ = nullptr;
        authenticatorCb_ = nullptr;
        return;
    }
    userId_ = request_.callerUid / UID_TRANSFORM_DIVISOR;
    ownerUid_ = BundleManagerAdapter::GetInstance()->GetUidByBundleName(request_.owner, userId_);
    isInitialized_ = true;
}

ErrCode AppAccountAuthenticatorSession::Open()
{
    if (isOpened_) {
        ACCOUNT_LOGD("session has been opened");
        return ERR_APPACCOUNT_SERVICE_OAUTH_SERVICE_EXCEPTION;
    }
    if (!isInitialized_) {
        ACCOUNT_LOGD("session has not been initialized");
        return ERR_APPACCOUNT_SERVICE_OAUTH_SERVICE_EXCEPTION;
    }
    AuthenticatorInfo info;
    ErrCode errCode = AppAccountAuthenticatorManager::GetAuthenticatorInfo(request_.owner, userId_, info);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("authenticator not exist, owner: %{public}s, errCode: %{public}d.",
            request_.owner.c_str(), errCode);
        return errCode;
    }
    AAFwk::Want want;
    want.SetElementName(request_.owner, info.abilityName);
    auto task = [want, this] {
        AbilityManagerAdapter::GetInstance()->ConnectAbility(want, this->conn_, nullptr, this->userId_);
    };
    std::thread taskThread(task);
    pthread_setname_np(taskThread.native_handle(), THREAD_AUTH_SESSION);
    taskThread.detach();
    isOpened_ = true;
    return ERR_OK;
}

void AppAccountAuthenticatorSession::Close()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if ((authenticatorProxy_ != nullptr) && (authenticatorProxy_->AsObject() != nullptr)) {
        authenticatorProxy_->AsObject()->RemoveDeathRecipient(serverDeathRecipient_);
    }
    if ((request_.callback != nullptr) && (request_.callback->AsObject() != nullptr)) {
        request_.callback->AsObject()->RemoveDeathRecipient(clientDeathRecipient_);
    }
    if (isConnected_) {
        AbilityManagerAdapter::GetInstance()->DisconnectAbility(conn_);
    }
    isOpened_ = false;
}

void AppAccountAuthenticatorSession::CloseSelf() const
{
    AppAccountAuthenticatorSessionManager::GetInstance().CloseSession(sessionId_);
}

ErrCode AppAccountAuthenticatorSession::AddClientDeathRecipient()
{
    if (!isOpened_) {
        return ERR_APPACCOUNT_SERVICE_OAUTH_SERVICE_EXCEPTION;
    }
    if ((request_.callback == nullptr) || (request_.callback->AsObject() == nullptr)) {
        return ERR_OK;
    }
    bool result = request_.callback->AsObject()->AddDeathRecipient(clientDeathRecipient_);
    if (!result) {
        return ERR_APPACCOUNT_SERVICE_OAUTH_SERVICE_EXCEPTION;
    }
    return ERR_OK;
}

void AppAccountAuthenticatorSession::OnAbilityConnectDone(
    const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int32_t resultCode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    isConnected_ = true;
    AAFwk::Want errResult;
    authenticatorProxy_ = iface_cast<IAppAccountAuthenticator>(remoteObject);
    if ((!authenticatorProxy_) || (!authenticatorProxy_->AsObject())) {
        OnResult(ERR_JS_ACCOUNT_AUTHENTICATOR_SERVICE_EXCEPTION, errResult);
        return;
    }
    authenticatorProxy_->AsObject()->AddDeathRecipient(serverDeathRecipient_);
    AppAccountAuthenticatorStringInfo stringInfo(request_.name, request_.authType, request_.callerBundleName);
    OnAbilityConnectInner(stringInfo, resultCode, errResult);
    if (resultCode != ERR_OK) {
        OnResult(ERR_JS_ACCOUNT_AUTHENTICATOR_SERVICE_EXCEPTION, errResult);
    }
}

void AppAccountAuthenticatorSession::OnAbilityConnectInner(const AppAccountAuthenticatorStringInfo &stringInfo,
    int32_t &resultCode, AAFwk::Want &errResult)
{
    int32_t funcResult = 0;
    switch (action_) {
        case ADD_ACCOUNT_IMPLICITLY:
            resultCode = authenticatorProxy_->AddAccountImplicitly(request_.authType, request_.callerBundleName,
                request_.options.GetParams(), authenticatorCb_->AsObject(), funcResult);
            resultCode = ConvertToAccountErrCode(resultCode, funcResult);
            break;
        case AUTHENTICATE:
            resultCode = authenticatorProxy_->Authenticate(stringInfo, request_.options.GetParams(),
                authenticatorCb_->AsObject(), funcResult);
            resultCode = ConvertToAccountErrCode(resultCode, funcResult);
            break;
        case CREATE_ACCOUNT_IMPLICITLY:
            resultCode = authenticatorProxy_->CreateAccountImplicitly(request_.createOptions,
                authenticatorCb_->AsObject(), funcResult);
            resultCode = ConvertToAccountErrCode(resultCode, funcResult);
            break;
        case AUTH:
            resultCode = authenticatorProxy_->Auth(
                request_.name, request_.authType, request_.options.GetParams(), authenticatorCb_->AsObject(),
                funcResult);
            resultCode = ConvertToAccountErrCode(resultCode, funcResult);
            break;
        case VERIFY_CREDENTIAL:
            resultCode = authenticatorProxy_->VerifyCredential(
                request_.name, request_.verifyCredOptions, authenticatorCb_->AsObject(), funcResult);
            resultCode = ConvertToAccountErrCode(resultCode, funcResult);
            break;
        case CHECK_ACCOUNT_LABELS:
            resultCode = authenticatorProxy_->CheckAccountLabels(
                request_.name, request_.labels, authenticatorCb_->AsObject(), funcResult);
            resultCode = ConvertToAccountErrCode(resultCode, funcResult);
            break;
        case SET_AUTHENTICATOR_PROPERTIES:
            resultCode = authenticatorProxy_->SetProperties(request_.setPropOptions, authenticatorCb_->AsObject(),
                funcResult);
            resultCode = ConvertToAccountErrCode(resultCode, funcResult);
            break;
        case IS_ACCOUNT_REMOVABLE:
            resultCode = authenticatorProxy_->IsAccountRemovable(request_.name, authenticatorCb_->AsObject(),
                funcResult);
            resultCode = ConvertToAccountErrCode(resultCode, funcResult);
            break;
        default:
            ACCOUNT_LOGE("unsupported action: %{public}d", action_);
            OnResult(ERR_JS_ACCOUNT_AUTHENTICATOR_SERVICE_EXCEPTION, errResult);
            return;
    }
}

void AppAccountAuthenticatorSession::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode)
{
    isConnected_ = false;
}

void AppAccountAuthenticatorSession::OnServerDied()
{
    AAFwk::Want result;
    OnResult(ERR_JS_ACCOUNT_AUTHENTICATOR_SERVICE_EXCEPTION, result);
}

int32_t AppAccountAuthenticatorSession::OnResult(int32_t resultCode, const AAFwk::Want &result) const
{
    if (resultCode == ERR_JS_SUCCESS) {
        switch (action_) {
            case ADD_ACCOUNT_IMPLICITLY:
                resultCode = OnAddAccountImplicitlyDone(result);
                break;
            case AUTHENTICATE:
                resultCode = OnAuthenticateDone(result);
                break;
            default:
                break;
        }
    }
    if ((request_.callback != nullptr) && (request_.callback->AsObject() != nullptr)) {
        request_.callback->OnResult(resultCode, result);
    }
    if (isConnected_) {
        AbilityManagerAdapter::GetInstance()->DisconnectAbility(conn_);
    }
    CloseSelf();
    return resultCode;
}

int32_t AppAccountAuthenticatorSession::OnRequestRedirected(AAFwk::Want &newRequest) const
{
    AAFwk::Want errResult;
    AppExecFwk::ElementName element = newRequest.GetElement();
    if (element.GetBundleName() != request_.owner) {
        ACCOUNT_LOGD("invalid response");
        OnResult(ERR_JS_ACCOUNT_AUTHENTICATOR_SERVICE_EXCEPTION, errResult);
        return ERR_JS_SUCCESS;
    }
    if ((!request_.callback) || (!request_.callback->AsObject())) {
        ACCOUNT_LOGD("app account callback is nullptr");
        if (isConnected_) {
            AbilityManagerAdapter::GetInstance()->DisconnectAbility(conn_);
        }
        CloseSelf();
        return ERR_JS_SUCCESS;
    }
    newRequest.SetParam(Constants::KEY_ACTION, action_);
    newRequest.SetParam(Constants::KEY_NAME, request_.name);
    newRequest.SetParam(Constants::KEY_SESSION_ID, sessionId_);
    newRequest.SetParam(Constants::KEY_CALLER_BUNDLE_NAME, request_.callerBundleName);
    newRequest.SetParam(Constants::KEY_CALLER_PID, request_.callerPid);
    newRequest.SetParam(Constants::KEY_CALLER_UID, request_.callerUid);
    if (action_ == AUTHENTICATE || action_ == ADD_ACCOUNT_IMPLICITLY) {
        newRequest.SetParam(Constants::KEY_AUTH_TYPE, request_.authType);
    }
    request_.callback->OnRequestRedirected(newRequest);
    return ERR_JS_SUCCESS;
}

int32_t AppAccountAuthenticatorSession::OnRequestContinued() const
{
    if ((!request_.callback) || (!request_.callback->AsObject())) {
        ACCOUNT_LOGD("app account callback is nullptr");
        if (isConnected_) {
            AbilityManagerAdapter::GetInstance()->DisconnectAbility(conn_);
        }
        CloseSelf();
        return ERR_JS_SUCCESS;
    }
    request_.callback->OnRequestContinued();
    return ERR_JS_SUCCESS;
}

int32_t AppAccountAuthenticatorSession::OnAuthenticateDone(const AAFwk::Want &result) const
{
    std::string name = result.GetStringParam(Constants::KEY_NAME);
    if (name != request_.name) {
        return ERR_JS_ACCOUNT_AUTHENTICATOR_SERVICE_EXCEPTION;
    }
    return ERR_OK;
}

int32_t AppAccountAuthenticatorSession::OnAddAccountImplicitlyDone(const AAFwk::Want &result) const
{
    std::string name = result.GetStringParam(Constants::KEY_NAME);
    if (name.empty()) {
        return ERR_JS_ACCOUNT_AUTHENTICATOR_SERVICE_EXCEPTION;
    }
    AppAccountInfo info(name, request_.owner);
    info.SetAppIndex(0);
    AppAccountControlManager::GetInstance().AddAccount(name, "", ownerUid_, request_.owner, info);
    return ERR_OK;
}

void AppAccountAuthenticatorSession::GetRequest(AuthenticatorSessionRequest &request) const
{
    request = request_;
}

ErrCode AppAccountAuthenticatorSession::GetAuthenticatorCallback(
    const AuthenticatorSessionRequest &request, sptr<IRemoteObject> &callback) const
{
    callback = nullptr;
    if ((request.callerUid != ownerUid_) || (request.callerBundleName != request_.owner)) {
        ACCOUNT_LOGE("fail to get authenticator callback for permission denied");
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
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
