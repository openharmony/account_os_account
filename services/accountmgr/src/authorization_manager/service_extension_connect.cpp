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

#include "service_extension_connect.h"

#include <chrono>
#include <mutex>

#include <iservice_registry.h>
#include <system_ability_definition.h>
#include <want.h>

#include "ability_connection.h"
#include "account_error_no.h"
#include "account_hisysevent_adapter.h"
#include "account_log_wrapper.h"
#include "app_mgr_client.h"
#include "extension_manager_client.h"
#include "ipc_skeleton.h"
#include "json_utils.h"
#include "singleton.h"

namespace OHOS {
namespace AccountSA {
namespace {
constexpr int32_t DEFAULT_VALUE = -1;
constexpr int32_t PARAM_NUM = 3;
constexpr int32_t CONNECT_CODE = 1;
const std::string SYSTEM_SCENEBOARD_BUNDLE_NAME = "com.ohos.sceneboard";
const std::string SYSTEM_SCENEBOARD_ABILITY_NAME = "com.ohos.sceneboard.systemdialog";
constexpr std::int32_t UID_TRANSFORM_DIVISOR = 20000;
}

void SessionAbilityConnection::SessionAbilityConnectionStub::OnAbilityConnectDone(
    const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObject, int32_t resultCode)
{
    ACCOUNT_LOGI("OnAbilityConnectDone entry");
    if (!ValidateConnectionResult(resultCode)) {
        return;
    }

    if (SendConnectionRequest(remoteObject) != ERR_OK) {
        return;
    }

    ACCOUNT_LOGI("OnAbilityConnectDone exit");
}

bool SessionAbilityConnection::SessionAbilityConnectionStub::ValidateConnectionResult(int32_t resultCode)
{
    if (resultCode != ERR_OK) {
        ACCOUNT_LOGE("ability connect failed, error code:%{public}d", resultCode);
        REPORT_OS_ACCOUNT_FAIL(localId_, Constants::ACQUIRE_AUTH, resultCode,
            "ability connect failed");
        SessionAbilityConnection::GetInstance().CallbackOnResult(ERR_AUTHORIZATION_CREATE_SYS_EXTENSION_ERROR);
        return false;
    }
    return true;
}

ErrCode SessionAbilityConnection::SessionAbilityConnectionStub::SendConnectionRequest(
    const sptr<IRemoteObject> &remoteObject)
{
    if (remoteObject == nullptr) {
        ACCOUNT_LOGE("Get remoteObject failed");
        REPORT_OS_ACCOUNT_FAIL(localId_, Constants::ACQUIRE_AUTH, ERR_AUTHORIZATION_CREATE_SYS_EXTENSION_ERROR,
            "Get proxy is nullptr");
        SessionAbilityConnection::GetInstance().CallbackOnResult(ERR_AUTHORIZATION_CREATE_SYS_EXTENSION_ERROR);
        return ERR_AUTHORIZATION_CREATE_SYS_EXTENSION_ERROR;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInt32(PARAM_NUM);
    data.WriteString16(u"bundleName");
    data.WriteString16(Str8ToStr16(info_.bundleName));
    data.WriteString16(u"abilityName");
    data.WriteString16(Str8ToStr16(info_.abilityName));
    data.WriteString16(u"parameters");

    std::string parameters = "";
    if (!GenerateParameters(parameters)) {
        ACCOUNT_LOGE("GenerateParameters failed");
        REPORT_OS_ACCOUNT_FAIL(localId_, Constants::ACQUIRE_AUTH, ERR_AUTHORIZATION_GET_PROXY_ERROR,
            "GenerateParameters fails.");
        SessionAbilityConnection::GetInstance().CallbackOnResult(ERR_AUTHORIZATION_CREATE_SYS_EXTENSION_ERROR);
        return ERR_AUTHORIZATION_GET_PROXY_ERROR;
    }
    data.WriteString16(Str8ToStr16(parameters));

    int32_t errCode = remoteObject->SendRequest(CONNECT_CODE, data, reply, option);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Fail to sendRequest, errCode:%{public}d", errCode);
        REPORT_OS_ACCOUNT_FAIL(localId_, Constants::ACQUIRE_AUTH, errCode, "Fail to sendRequest");
        SessionAbilityConnection::GetInstance().CallbackOnResult(ERR_AUTHORIZATION_CREATE_SYS_EXTENSION_ERROR);
        return errCode;
    }
    return ERR_OK;
}

bool SessionAbilityConnection::SessionAbilityConnectionStub::GenerateParameters(std::string &parameters)
{
    auto json = CreateJson();
    if (!AddStringToJson(json, "ability.want.params.uiExtensionType", "sysDialog/common")) {
        ACCOUNT_LOGE("Fail to add uiExtensionType to json");
        return false;
    }
    if (!AddIntToJson(json, "sysDialogZOrder", 1)) {
        ACCOUNT_LOGE("Fail to add sysDialogZOrder to json");
        return false;
    }
    if (!AddStringToJson(json, "privilege", info_.privilege)) {
        ACCOUNT_LOGE("Fail to add privilege to json");
        return false;
    }
    if (!AddStringToJson(json, "description", info_.description)) {
        ACCOUNT_LOGE("Fail to add description to json");
        return false;
    }
    if (!AddStringToJson(json, "callingBundleName", info_.callingBundleName)) {
        ACCOUNT_LOGE("Fail to add uid to json");
        return false;
    }
    std::string challengeStr;
    TransVectorU8ToString(info_.challenge, challengeStr);
    if (!AddStringToJson(json, "challenge", challengeStr)) {
        ACCOUNT_LOGE("Fail to add challenge to json");
        return false;
    }
    parameters = PackJsonToString(json);
    return true;
}

void SessionAbilityConnection::SessionAbilityConnectionStub::OnAbilityDisconnectDone(
    const AppExecFwk::ElementName &element, int32_t resultCode)
{
    ACCOUNT_LOGI("OnAbilityDisconnectDone entry, code:%{public}d", resultCode);
}

SessionAbilityConnection::SessionAbilityConnectionStub::SessionAbilityConnectionStub(const ConnectAbilityInfo &info)
{
    info_ = info;
    localId_ = info.callingUid / UID_TRANSFORM_DIVISOR;
}

SessionAbilityConnection &SessionAbilityConnection::GetInstance()
{
    static SessionAbilityConnection instance;
    return instance;
}

ErrCode SessionAbilityConnection::SessionConnectExtension(const ConnectAbilityInfo &info,
    sptr<IAuthorizationCallback> &callback, AuthorizationResult &authorizationResult)
{
    ACCOUNT_LOGI("bundleName:%{public}s, abilityName:%{public}s", info.bundleName.c_str(), info.abilityName.c_str());
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    localId_ = info.callingUid / UID_TRANSFORM_DIVISOR;

    if (abilityConnectionStub_ != nullptr) {
        ACCOUNT_LOGI("Session ability extension is already connected");
        REPORT_OS_ACCOUNT_FAIL(localId_, Constants::ACQUIRE_AUTH,
            ERR_AUTHORIZATION_ALREADY_HAS_ERROR, "Session ability extension is already connected");
        authorizationResult.resultCode = AuthorizationResultCode::AUTHORIZATION_SYSTEM_BUSY;
        callback->OnResult(ERR_OK, authorizationResult);
        return ERR_OK;
    }

    ErrCode errCode = CreateCallbackDeathRecipient(callback);
    if (errCode != ERR_OK) {
        return errCode;
    }

    return CreateStubAndConnect(info, callback, authorizationResult);
}

ErrCode SessionAbilityConnection::CallbackOnResult(int32_t errCode, AuthorizationResultCode resultCode)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (callback_ == nullptr) {
        ACCOUNT_LOGE("Callback_ is nullptr.");
        REPORT_OS_ACCOUNT_FAIL(localId_, Constants::ACQUIRE_AUTH, ERR_AUTHORIZATION_GET_STUB_ERROR,
            "Callback_ is nullptr");
        return ERR_AUTHORIZATION_GET_STUB_ERROR;
    }
    authResult_.resultCode = resultCode;
    ErrCode err = callback_->OnResult(errCode, authResult_);
    SessionDisconnectExtension();
    return err;
}

ErrCode SessionAbilityConnection::SaveAuthorizationResult(ErrCode errCode, AuthorizationResultCode &resultCode,
    const std::vector<uint8_t> &iamToken, int32_t remainValidityTime)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (abilityConnectionStub_ == nullptr) {
        ACCOUNT_LOGE("AbilityConnectionStub_ is nullptr");
        REPORT_OS_ACCOUNT_FAIL(localId_, Constants::ACQUIRE_AUTH, ERR_AUTHORIZATION_GET_STUB_ERROR,
            "AbilityConnectionStub is nullptr");
        return ERR_AUTHORIZATION_GET_STUB_ERROR;
    }
    errCode_ = errCode;
    authResult_.resultCode = resultCode;
    authResult_.token = iamToken;
    authResult_.validityPeriod = remainValidityTime;
    hasAuthCallback_.exchange(true);
    return ERR_OK;
}

bool SessionAbilityConnection::HasServiceConnect()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    return abilityConnectionStub_ != nullptr;
}

void SessionAbilityConnection::GetConnectInfo(int32_t callingUid, ConnectAbilityInfo &info)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (callingUid == authAppUid_) {
        info = info_;
    }
}

ErrCode SessionAbilityConnection::RegisterAuthAppRemoteObject(int32_t callingUid,
    const sptr<IRemoteObject> &authAppRemoteObj)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (abilityConnectionStub_ == nullptr) {
        ACCOUNT_LOGE("AbilityConnectionStub_ is nullptr");
        REPORT_OS_ACCOUNT_FAIL(localId_, Constants::ACQUIRE_AUTH, ERR_AUTHORIZATION_GET_STUB_ERROR,
            "AbilityConnectionStub is nullptr");
        return ERR_AUTHORIZATION_GET_STUB_ERROR;
    }
    if (authAppRemoteObj == nullptr) {
        ACCOUNT_LOGE("AuthAppRemoteObj is nullptr");
        REPORT_OS_ACCOUNT_FAIL(localId_, Constants::ACQUIRE_AUTH, ERR_ACCOUNT_COMMON_INVALID_PARAMETER,
            "AuthAppRemoteObj is nullptr");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    auto deathRecipient = new (std::nothrow) AuthAppDeathRecipient();
    if (deathRecipient == nullptr) {
        ACCOUNT_LOGE("DeathRecipient is nullptr");
        REPORT_OS_ACCOUNT_FAIL(localId_, Constants::ACQUIRE_AUTH, ERR_ACCOUNT_COMMON_ADD_DEATH_RECIPIENT,
            "DeathRecipient is nullptr");
        return ERR_ACCOUNT_COMMON_ADD_DEATH_RECIPIENT;
    }
    if (!authAppRemoteObj->AddDeathRecipient(deathRecipient)) {
        ACCOUNT_LOGE("Fail to AddDeathRecipient");
        REPORT_OS_ACCOUNT_FAIL(localId_, Constants::ACQUIRE_AUTH, ERR_ACCOUNT_COMMON_ADD_DEATH_RECIPIENT,
            "Fail to AddDeathRecipient");
        return ERR_ACCOUNT_COMMON_ADD_DEATH_RECIPIENT;
    }
    authAppRemoteObj_ = authAppRemoteObj;
    authAppUid_ = callingUid;
    return ERR_OK;
}

ErrCode SessionAbilityConnection::UnRegisterAuthAppRemoteObject(int32_t callingUid)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (authAppUid_ != callingUid) {
        ACCOUNT_LOGE("CallingUid not equal.");
        REPORT_OS_ACCOUNT_FAIL(localId_, Constants::ACQUIRE_AUTH, ERR_AUTHORIZATION_NOT_SUPPORT,
            "CallingUid not equal");
        return ERR_AUTHORIZATION_NOT_SUPPORT;
    }
    CallbackOnResult(errCode_, hasAuthCallback_ ? authResult_.resultCode :
        AuthorizationResultCode::AUTHORIZATION_CANCELED);
    return ERR_OK;
}

void SessionAbilityConnection::SessionDisconnectExtension()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (abilityConnectionStub_ == nullptr) {
        ACCOUNT_LOGE("AbilityConnectionStub is nullptr");
        REPORT_OS_ACCOUNT_FAIL(localId_, Constants::ACQUIRE_AUTH, ERR_AUTHORIZATION_GET_STUB_ERROR,
            "AbilityConnectionStub is nullptr");
        return;
    }
    authAppRemoteObj_.clear();
    authAppRemoteObj_ = nullptr;
    auto ret = AAFwk::ExtensionManagerClient::GetInstance().DisconnectAbility(abilityConnectionStub_);
    abilityConnectionStub_.clear();
    abilityConnectionStub_ = nullptr;
    authAppUid_ = -1;
    callback_ = nullptr;
    hasAuthCallback_.exchange(false);
    errCode_ = ERR_OK;
    ACCOUNT_LOGI("Session ability disconnected, ret: %{public}d", ret);
}

void SessionAbilityConnection::AuthAppDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    if (remote == nullptr) {
        ACCOUNT_LOGE("Remote is nullptr");
        REPORT_OS_ACCOUNT_FAIL(IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR,
            Constants::ACQUIRE_AUTH, ERR_AUTHORIZATION_GET_STUB_ERROR, "Remote is nullptr");
        return;
    }
    SessionAbilityConnection::GetInstance().CallbackOnResult(ERR_AUTHORIZATION_CREATE_SYS_EXTENSION_ERROR);
}

void SessionAbilityConnection::AppDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    if (remote == nullptr) {
        ACCOUNT_LOGE("Remote is nullptr");
        REPORT_OS_ACCOUNT_FAIL(IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR,
            Constants::ACQUIRE_AUTH, ERR_AUTHORIZATION_GET_STUB_ERROR, "Remote is nullptr");
        return;
    }
    SessionAbilityConnection::GetInstance().SessionDisconnectExtension();
    int32_t errCode = DelayedSingleton<AppExecFwk::AppMgrClient>::GetInstance()->KillApplication(bundleName_);
    ACCOUNT_LOGI("KillAppApplicationSelf end, errCode:%{public}d", errCode);
}

ErrCode SessionAbilityConnection::CreateCallbackDeathRecipient(const sptr<IAuthorizationCallback> &callback)
{
    auto deathRecipient = new (std::nothrow) AppDeathRecipient(info_.bundleName);
    if (deathRecipient == nullptr) {
        REPORT_OS_ACCOUNT_FAIL(localId_, Constants::ACQUIRE_AUTH,
            ERR_ACCOUNT_COMMON_ADD_DEATH_RECIPIENT, "DeathRecipient is nullptr");
        ACCOUNT_LOGE("DeathRecipient is nullptr");
        return ERR_ACCOUNT_COMMON_ADD_DEATH_RECIPIENT;
    }

    if (!callback->AsObject()->AddDeathRecipient(deathRecipient)) {
        ACCOUNT_LOGE("Fail to AddDeathRecipient");
        REPORT_OS_ACCOUNT_FAIL(localId_, Constants::ACQUIRE_AUTH,
            ERR_ACCOUNT_COMMON_ADD_DEATH_RECIPIENT, "Fail to AddDeathRecipient");
        return ERR_ACCOUNT_COMMON_ADD_DEATH_RECIPIENT;
    }
    return ERR_OK;
}

ErrCode SessionAbilityConnection::CreateStubAndConnect(const ConnectAbilityInfo &info,
    const sptr<IAuthorizationCallback> &callback, const AuthorizationResult &authorizationResult)
{
    abilityConnectionStub_ =
        sptr<SessionAbilityConnectionStub>(new (std::nothrow) SessionAbilityConnectionStub(info));
    if (abilityConnectionStub_ == nullptr) {
        ACCOUNT_LOGE("Get session aibility connection is nullptr");
        REPORT_OS_ACCOUNT_FAIL(localId_, Constants::ACQUIRE_AUTH, ERR_AUTHORIZATION_GET_STUB_ERROR,
            "Get session aibility connection is nullptr");
        return ERR_AUTHORIZATION_GET_STUB_ERROR;
    }

    info_ = info;
    callback_ = callback;
    authResult_ = authorizationResult;

    AAFwk::Want want;
    want.SetElementName(SYSTEM_SCENEBOARD_BUNDLE_NAME, SYSTEM_SCENEBOARD_ABILITY_NAME);

    std::string identity = IPCSkeleton::ResetCallingIdentity();
    auto ret = AAFwk::ExtensionManagerClient::GetInstance().ConnectServiceExtensionAbility(
        want, abilityConnectionStub_, nullptr, DEFAULT_VALUE);
    IPCSkeleton::SetCallingIdentity(identity);

    if (ret != ERR_OK) {
        ACCOUNT_LOGE("ConnectServiceExtensionAbility failed, result: %{public}d", ret);
        REPORT_OS_ACCOUNT_FAIL(localId_, Constants::ACQUIRE_AUTH, ret,
            "ConnectServiceExtensionAbility failed");
        abilityConnectionStub_ = nullptr;
        return ERR_AUTHORIZATION_CREATE_SYS_EXTENSION_ERROR;
    }

    ACCOUNT_LOGI("ConnectServiceExtensionAbility succeed");
    return ERR_OK;
}
}
}
