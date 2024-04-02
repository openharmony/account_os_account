/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "account_iam_callback.h"

#include <securec.h>
#include "account_info_report.h"
#include "account_log_wrapper.h"
#include "account_hisysevent_adapter.h"
#include "iinner_os_account_manager.h"
#include "inner_account_iam_manager.h"
#include "inner_domain_account_manager.h"
#include "user_auth_client.h"
#include "user_idm_client.h"

namespace OHOS {
namespace AccountSA {
using UserIDMClient = UserIam::UserAuth::UserIdmClient;
using UserAuthClient = UserIam::UserAuth::UserAuthClient;

void AuthCallbackDeathRecipient::SetContextId(uint16_t contextId)
{
    contextId_ = contextId;
}

void AuthCallbackDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    ACCOUNT_LOGI("remote callback died, cancel authentication");
    if (contextId_ > 0) {
        UserAuthClient::GetInstance().CancelAuthentication(contextId_);
    }
}

AuthCallback::AuthCallback(uint32_t userId, AuthType authType, const sptr<IIDMCallback> &callback)
    : userId_(userId), authType_(authType), innerCallback_(callback)
{}

ErrCode AuthCallback::HandleAuthResult(const Attributes &extraInfo)
{
    std::vector<uint8_t> token;
    if (authType_ != static_cast<AuthType>(IAMAuthType::DOMAIN)) {
        // domain account authentication
        extraInfo.GetUint8ArrayValue(Attributes::ATTR_SIGNATURE, token);
        InnerDomainAccountManager::GetInstance().AuthWithToken(userId_, token);
    }
    // send msg to storage for unlock
    bool lockScreenStatus = false;
    ErrCode ret = InnerAccountIAMManager::GetInstance().GetLockScreenStatus(userId_, lockScreenStatus);
    if (ret != 0) {
        ReportOsAccountOperationFail(userId_, "getLockScreenStatus", ret, "failed to get lock status msg from storage");
    }
    if (!lockScreenStatus) {
        ACCOUNT_LOGI("start unlock user screen");
        ret = InnerAccountIAMManager::GetInstance().UnlockUserScreen(userId_);
        if (ret != 0) {
            ReportOsAccountOperationFail(userId_, "unlockUserScreen", ret, "failed to send unlock msg for storage");
            return ret;
        }
    }
    if (authType_ != AuthType::PIN) {
        return ERR_OK;
    }
    (void)IInnerOsAccountManager::GetInstance().IsOsAccountVerified(userId_, isAccountVerified_);
    if (isAccountVerified_) {
        return ERR_OK;
    }
    // file decryption
    std::vector<uint8_t> secret;
    extraInfo.GetUint8ArrayValue(Attributes::ATTR_ROOT_SECRET, secret);
    ret = InnerAccountIAMManager::GetInstance().ActivateUserKey(userId_, token, secret);
    if (ret != 0) {
        ACCOUNT_LOGE("failed to activate user key");
        ReportOsAccountOperationFail(userId_, "activateUserKey", ret, "failed to notice storage to activate user key");
        return ret;
    }
    return ret;
}

void AuthCallback::SetDeathRecipient(const sptr<AuthCallbackDeathRecipient> &deathRecipient)
{
    deathRecipient_ = deathRecipient;
}

void AuthCallback::OnResult(int32_t result, const Attributes &extraInfo)
{
    InnerAccountIAMManager::GetInstance().SetState(userId_, AFTER_OPEN_SESSION);
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGE("innerCallback_ is nullptr");
        return;
    }
    innerCallback_->AsObject()->RemoveDeathRecipient(deathRecipient_);
    if (result != 0) {
        ACCOUNT_LOGE("authentication failed");
        innerCallback_->OnResult(result, extraInfo);
        ReportOsAccountOperationFail(userId_, "authUser", result, "auth user failed");
        return AccountInfoReport::ReportSecurityInfo("", userId_, ReportEvent::EVENT_LOGIN, result);
    }
    if (HandleAuthResult(extraInfo) != ERR_OK) {
        int32_t remainTimes = 0;
        int32_t freezingTime = 0;
        extraInfo.GetInt32Value(Attributes::AttributeKey::ATTR_REMAIN_TIMES, remainTimes);
        extraInfo.GetInt32Value(Attributes::AttributeKey::ATTR_FREEZING_TIME, freezingTime);
        Attributes errInfo;
        errInfo.SetInt32Value(Attributes::AttributeKey::ATTR_REMAIN_TIMES, remainTimes);
        errInfo.SetInt32Value(Attributes::AttributeKey::ATTR_FREEZING_TIME, freezingTime);
        innerCallback_->OnResult(ResultCode::FAIL, errInfo);
        return AccountInfoReport::ReportSecurityInfo("", userId_, ReportEvent::EVENT_LOGIN, ResultCode::FAIL);
    }
    innerCallback_->OnResult(result, extraInfo);
    (void)IInnerOsAccountManager::GetInstance().SetOsAccountIsVerified(userId_, true);
    AccountInfoReport::ReportSecurityInfo("", userId_, ReportEvent::EVENT_LOGIN, result);
}

void AuthCallback::OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo)
{
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGE("innerCallback_ is nullptr");
        return;
    }
    innerCallback_->OnAcquireInfo(module, acquireInfo, extraInfo);
}

IDMAuthCallback::IDMAuthCallback(
    uint32_t userId, uint64_t credentialId, uint64_t secureUid, const sptr<IIDMCallback> &idmCallback)
    : userId_(userId), credentialId_(credentialId), secureUid_(secureUid), idmCallback_(idmCallback)
{}

void IDMAuthCallback::OnResult(int32_t result, const Attributes &extraInfo)
{
    if (result != 0) {
        ACCOUNT_LOGE("fail to update user key for authentication failure, error code: %{public}d", result);
        ReportOsAccountOperationFail(
            userId_, "authentication", result, "fail to update user key for authentication failure");
    } else {
        std::vector<uint8_t> token;
        std::vector<uint8_t> secret;
        extraInfo.GetUint8ArrayValue(Attributes::ATTR_SIGNATURE, token);
        extraInfo.GetUint8ArrayValue(Attributes::ATTR_ROOT_SECRET, secret);
        (void) InnerAccountIAMManager::GetInstance().UpdateUserKey(userId_, secureUid_, credentialId_, token, secret);
    }
    InnerAccountIAMManager::GetInstance().SetState(userId_, AFTER_OPEN_SESSION);
    if (idmCallback_ == nullptr) {
        ACCOUNT_LOGE("idm callback is nullptr");
        return;
    }
    Attributes resultAttr;
    resultAttr.SetUint64Value(Attributes::AttributeKey::ATTR_CREDENTIAL_ID, credentialId_);
    resultAttr.SetUint64Value(Attributes::AttributeKey::ATTR_SEC_USER_ID, secureUid_);
    idmCallback_->OnResult(ERR_OK, resultAttr);
}

void IDMAuthCallback::OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo)
{
    ACCOUNT_LOGW("unsupported operation");
}

void IDMCallbackDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    ACCOUNT_LOGI("Remote callback died, cancel cred");
    if (userId_ > 0) {
        UserIDMClient::GetInstance().Cancel(userId_);
    }
}

IDMCallbackDeathRecipient::IDMCallbackDeathRecipient(uint32_t userId) : userId_(userId)
{}

AddCredCallback::AddCredCallback(uint32_t userId, const CredentialParameters &credInfo,
    const sptr<IIDMCallback> &callback)
    : userId_(userId), credInfo_(credInfo), innerCallback_(callback)
{}

void AddCredCallback::SetDeathRecipient(const sptr<IDMCallbackDeathRecipient> &deathRecipient)
{
    deathRecipient_ = deathRecipient;
}

void AddCredCallback::OnResult(int32_t result, const Attributes &extraInfo)
{
    if (innerCallback_ == nullptr || innerCallback_->AsObject() == nullptr) {
        ACCOUNT_LOGE("innerCallback_ is nullptr");
        return;
    }
    innerCallback_->AsObject()->RemoveDeathRecipient(deathRecipient_);
    if ((result == 0) && (credInfo_.authType == AuthType::PIN)) {
        InnerAccountIAMManager::GetInstance().SetState(userId_, AFTER_ADD_CRED);
        uint64_t credentialId = 0;
        extraInfo.GetUint64Value(Attributes::AttributeKey::ATTR_CREDENTIAL_ID, credentialId);
        (void)IInnerOsAccountManager::GetInstance().SetOsAccountCredentialId(userId_, credentialId);
        std::vector<uint8_t> challenge;
        InnerAccountIAMManager::GetInstance().GetChallenge(userId_, challenge);
        uint64_t secureUid = 0;
        extraInfo.GetUint64Value(Attributes::AttributeKey::ATTR_SEC_USER_ID, secureUid);
        auto callback = std::make_shared<IDMAuthCallback>(userId_, credentialId, secureUid, innerCallback_);
        UserAuthClient::GetInstance().BeginAuthentication(
            userId_, challenge, AuthType::PIN, AuthTrustLevel::ATL4, callback);
        return;
    }
    if (result != 0) {
        ReportOsAccountOperationFail(userId_, "addCredential", result, "fail to add credential");
    }
    InnerAccountIAMManager::GetInstance().SetState(userId_, AFTER_OPEN_SESSION);
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGE("inner callback is nullptr");
        return;
    }
    innerCallback_->OnResult(result, extraInfo);
}

void AddCredCallback::OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo)
{
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGE("innerCallback_ is nullptr");
        return;
    }
    innerCallback_->OnAcquireInfo(module, acquireInfo, extraInfo);
}

UpdateCredCallback::UpdateCredCallback(
    uint32_t userId, const CredentialParameters &credInfo, const sptr<IIDMCallback> &callback)
    : userId_(userId), credInfo_(credInfo), innerCallback_(callback)
{}

void UpdateCredCallback::SetDeathRecipient(const sptr<IDMCallbackDeathRecipient> &deathRecipient)
{
    deathRecipient_ = deathRecipient;
}

void UpdateCredCallback::OnResult(int32_t result, const Attributes &extraInfo)
{
    if (innerCallback_ == nullptr || innerCallback_->AsObject() == nullptr) {
        ACCOUNT_LOGE("inner callback is nullptr");
        return;
    }
    innerCallback_->AsObject()->RemoveDeathRecipient(deathRecipient_);
    if ((result != 0) || (credInfo_.authType != AuthType::PIN)) {
        InnerAccountIAMManager::GetInstance().SetState(userId_, AFTER_OPEN_SESSION);
        innerCallback_->OnResult(result, extraInfo);
        return;
    }
    InnerAccountIAMManager::GetInstance().SetState(userId_, AFTER_UPDATE_CRED);

    uint64_t credentialId = 0;
    extraInfo.GetUint64Value(Attributes::AttributeKey::ATTR_CREDENTIAL_ID, credentialId);
    uint64_t secureUid = 0;
    extraInfo.GetUint64Value(Attributes::AttributeKey::ATTR_SEC_USER_ID, secureUid);
    auto callback = std::make_shared<IDMAuthCallback>(userId_, credentialId, secureUid, innerCallback_);

    std::vector<uint8_t> challenge;
    InnerAccountIAMManager::GetInstance().GetChallenge(userId_, challenge);
    UserAuthClient::GetInstance().BeginAuthentication(
        userId_, challenge, AuthType::PIN, AuthTrustLevel::ATL4, callback);
}

void UpdateCredCallback::OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo)
{
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGE("innerCallback_ is nullptr");
        return;
    }
    innerCallback_->OnAcquireInfo(module, acquireInfo, extraInfo);
}

DelCredCallback::DelCredCallback(int32_t userId, bool isPIN, const sptr<IIDMCallback> &callback)
    : userId_(userId), isPIN_(isPIN), innerCallback_(callback)
{}

void DelCredCallback::OnResult(int32_t result, const Attributes &extraInfo)
{
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGE("innerCallback_ is nullptr");
        return;
    }
    if ((result == 0) && isPIN_) {
        (void)IInnerOsAccountManager::GetInstance().SetOsAccountCredentialId(userId_, 0);  // 0-invalid credentialId
    }
    if (result != 0) {
        ReportOsAccountOperationFail(userId_, "deleteCredential", result, "fail to delete credential");
    }
    InnerAccountIAMManager::GetInstance().SetState(userId_, AFTER_OPEN_SESSION);
    innerCallback_->OnResult(result, extraInfo);
}

void DelCredCallback::OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo)
{
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGE("inner callback is nullptr");
        return;
    }
    innerCallback_->OnAcquireInfo(module, acquireInfo, extraInfo);
}

GetCredInfoCallbackWrapper::GetCredInfoCallbackWrapper(
    int32_t userId, int32_t authType, const sptr<IGetCredInfoCallback> &callback)
    : userId_(userId), authType_(authType), innerCallback_(callback)
{}

void GetCredInfoCallbackWrapper::OnCredentialInfo(const std::vector<CredentialInfo> &infoList)
{
    if (innerCallback_ == nullptr) {
        return;
    }
    if (authType_ == 0) {
        bool isAvailable = InnerAccountIAMManager::GetInstance().CheckDomainAuthAvailable(userId_);
        if (isAvailable) {
            std::vector<CredentialInfo> newInfoList = infoList;
            CredentialInfo info;
            info.authType = static_cast<AuthType>(IAMAuthType::DOMAIN);
            info.pinType = static_cast<PinSubType>(IAMAuthSubType::DOMAIN_MIXED);
            newInfoList.emplace_back(info);
            return innerCallback_->OnCredentialInfo(newInfoList);
        }
    }
    return innerCallback_->OnCredentialInfo(infoList);
}

GetPropCallbackWrapper::GetPropCallbackWrapper(int32_t userId, const sptr<IGetSetPropCallback> &callback)
    : userId_(userId), innerCallback_(callback)
{}

void GetPropCallbackWrapper::OnResult(int32_t result, const Attributes &extraInfo)
{
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGE("inner callback is nullptr");
        return;
    }
    if (result != 0) {
        ReportOsAccountOperationFail(userId_, "getProperty", result, "fail to get property");
    }
    innerCallback_->OnResult(result, extraInfo);
}

SetPropCallbackWrapper::SetPropCallbackWrapper(int32_t userId, const sptr<IGetSetPropCallback> &callback)
    : userId_(userId), innerCallback_(callback)
{}

void SetPropCallbackWrapper::OnResult(int32_t result, const Attributes &extraInfo)
{
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGE("inner callback is nullptr");
        return;
    }
    if (result != 0) {
        ReportOsAccountOperationFail(userId_, "setProperty", result, "fail to set property");
    }
    innerCallback_->OnResult(result, extraInfo);
}

GetDomainAuthStatusInfoCallback::GetDomainAuthStatusInfoCallback(
    const GetPropertyRequest &request, const sptr<IGetSetPropCallback> &callback)
    : request_(request), innerCallback_(callback)
{}

void GetDomainAuthStatusInfoCallback::OnResult(int32_t result, Parcel &parcel)
{
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGE("inner callback is nullptr");
        return;
    }
    Attributes attributes;
    std::shared_ptr<AuthStatusInfo> infoPtr(AuthStatusInfo::Unmarshalling(parcel));
    if (infoPtr == nullptr) {
        innerCallback_->OnResult(result, attributes);
        return;
    }
    attributes.SetInt32Value(Attributes::ATTR_PIN_SUB_TYPE, static_cast<int32_t>(IAMAuthSubType::DOMAIN_MIXED));
    attributes.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, infoPtr->remainingTimes);
    attributes.SetInt32Value(Attributes::ATTR_FREEZING_TIME, infoPtr->freezingTime);
    innerCallback_->OnResult(result, attributes);
}
}  // namespace AccountSA
}  // namespace OHOS
