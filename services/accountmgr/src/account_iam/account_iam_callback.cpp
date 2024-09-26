/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include <string>
#include "access_token.h"
#include "account_iam_info.h"
#include "account_info_report.h"
#include "account_log_wrapper.h"
#include "account_hisysevent_adapter.h"
#include "iinner_os_account_manager.h"
#include "inner_account_iam_manager.h"
#include "inner_domain_account_manager.h"
#include "ipc_skeleton.h"
#include "os_account_delete_user_idm_callback.h"
#include "token_setproc.h"
#include "user_auth_client.h"
#include "user_idm_client.h"
#include "os_account_constants.h"

namespace OHOS {
namespace AccountSA {
using UserIDMClient = UserIam::UserAuth::UserIdmClient;
using UserAuthClient = UserIam::UserAuth::UserAuthClient;

const std::vector<uint8_t> TEMP_PIN = {50, 48, 50, 52, 48, 56};

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

AuthCallback::AuthCallback(
    uint32_t userId, uint64_t credentialId, AuthType authType, const sptr<IIDMCallback> &callback)
    : userId_(userId), credentialId_(credentialId), authType_(authType), innerCallback_(callback)
{}

AuthCallback::AuthCallback(uint32_t userId, uint64_t credentialId, AuthType authType,
    bool isRemoteAuth, const sptr<IIDMCallback> &callback)
    : userId_(userId), credentialId_(credentialId), authType_(authType),
    isRemoteAuth_(isRemoteAuth), innerCallback_(callback)
{}

ErrCode AuthCallback::HandleAuthResult(const Attributes &extraInfo, int32_t accountId, bool &isUpdateVerifiedStatus)
{
    std::vector<uint8_t> token;
    extraInfo.GetUint8ArrayValue(Attributes::ATTR_SIGNATURE, token);
    std::vector<uint8_t> secret;
    extraInfo.GetUint8ArrayValue(Attributes::ATTR_ROOT_SECRET, secret);
    ErrCode ret = ERR_OK;
    if (authType_ == AuthType::PIN) {
        (void)InnerAccountIAMManager::GetInstance().HandleFileKeyException(userId_, secret, token);
        bool isVerified = false;
        (void)IInnerOsAccountManager::GetInstance().IsOsAccountVerified(accountId, isVerified);
        if (!isVerified) {
            // el2 file decryption
            ret = InnerAccountIAMManager::GetInstance().ActivateUserKey(accountId, token, secret);
            if (ret != 0) {
                ACCOUNT_LOGE("failed to activate user key");
                ReportOsAccountOperationFail(accountId, "activateUserKey", ret,
                    "failed to notice storage to activate user key");
                return ret;
            }
            isUpdateVerifiedStatus = true;
        }
    }
    if (!isUpdateVerifiedStatus) {
        bool lockScreenStatus = false;
        ret = InnerAccountIAMManager::GetInstance().GetLockScreenStatus(accountId, lockScreenStatus);
        if (ret != 0) {
            ReportOsAccountOperationFail(
                accountId, "getLockScreenStatus", ret, "failed to get lock status msg from storage");
        }
        if (!lockScreenStatus && authType_ != AuthType::RECOVERY_KEY) {
            ACCOUNT_LOGI("start unlock user screen");
            // el3\4 file decryption
            ret = InnerAccountIAMManager::GetInstance().UnlockUserScreen(accountId, token, secret);
            if (ret != 0) {
                ReportOsAccountOperationFail(
                    accountId, "unlockUserScreen", ret, "failed to send unlock msg for storage");
                return ret;
            }
        }
    }
    // domain account authentication
    if (authType_ == static_cast<AuthType>(IAMAuthType::DOMAIN)) {
        return ERR_OK;
    }
    InnerDomainAccountManager::GetInstance().AuthWithToken(accountId, token);
    return ret;
}

void AuthCallback::SetDeathRecipient(const sptr<AuthCallbackDeathRecipient> &deathRecipient)
{
    deathRecipient_ = deathRecipient;
}

static void GenerateAttributesInfo(const Attributes &extraInfo, Attributes &extraAuthInfo)
{
    std::vector<uint8_t> token;
    if (extraInfo.GetUint8ArrayValue(Attributes::AttributeKey::ATTR_SIGNATURE, token)) {
        extraAuthInfo.SetUint8ArrayValue(Attributes::AttributeKey::ATTR_SIGNATURE, token);
    }
    int32_t remainTimes = 0;
    if (extraInfo.GetInt32Value(Attributes::AttributeKey::ATTR_REMAIN_TIMES, remainTimes)) {
        extraAuthInfo.SetInt32Value(Attributes::AttributeKey::ATTR_REMAIN_TIMES, remainTimes);
    }
    int32_t freezingTime = 0;
    if (extraInfo.GetInt32Value(Attributes::AttributeKey::ATTR_FREEZING_TIME, freezingTime)) {
        extraAuthInfo.SetInt32Value(Attributes::AttributeKey::ATTR_FREEZING_TIME, freezingTime);
    }
    int32_t nextPhaseFreezingTime = 0;
    if (extraInfo.GetInt32Value(Attributes::AttributeKey::ATTR_NEXT_FAIL_LOCKOUT_DURATION, nextPhaseFreezingTime)) {
        extraAuthInfo.SetInt32Value(Attributes::AttributeKey::ATTR_NEXT_FAIL_LOCKOUT_DURATION, nextPhaseFreezingTime);
    }
    int32_t accountId = 0;
    if (extraInfo.GetInt32Value(Attributes::AttributeKey::ATTR_USER_ID, accountId)) {
        extraAuthInfo.SetInt32Value(Attributes::AttributeKey::ATTR_USER_ID, accountId);
    }
    // pinValidityPeriod
    int64_t pinValidityPeriod = 0;
    if (extraInfo.GetInt64Value(Attributes::AttributeKey::ATTR_PIN_EXPIRED_INFO, pinValidityPeriod)) {
        extraAuthInfo.SetInt64Value(Attributes::AttributeKey::ATTR_PIN_EXPIRED_INFO, pinValidityPeriod);
    }
}

void AuthCallback::OnResult(int32_t result, const Attributes &extraInfo)
{
    int32_t authedAccountId = 0;
    if (!extraInfo.GetInt32Value(Attributes::AttributeKey::ATTR_USER_ID, authedAccountId)) {
        ACCOUNT_LOGE("Get account id from auth result failed");
        authedAccountId = static_cast<int32_t>(userId_);
    }
    ACCOUNT_LOGI("Auth ret: authType=%{public}d, result=%{public}d, id=%{public}d", authType_, result, authedAccountId);
    InnerAccountIAMManager::GetInstance().SetState(authedAccountId, AFTER_OPEN_SESSION);
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGE("innerCallback_ is nullptr");
        return;
    }
    innerCallback_->AsObject()->RemoveDeathRecipient(deathRecipient_);
    if (result != 0) {
        innerCallback_->OnResult(result, extraInfo);
        ReportOsAccountOperationFail(authedAccountId, "authUser", result, "auth user failed");
        return AccountInfoReport::ReportSecurityInfo("", authedAccountId, ReportEvent::EVENT_LOGIN, result);
    }
    if (isRemoteAuth_) {
        ACCOUNT_LOGI("Remote auth");
        innerCallback_->OnResult(result, extraInfo);
        return;
    }
    bool isUpdateVerifiedStatus = false;
    if (HandleAuthResult(extraInfo, authedAccountId, isUpdateVerifiedStatus) != ERR_OK) {
        int32_t remainTimes = 0;
        int32_t freezingTime = 0;
        extraInfo.GetInt32Value(Attributes::AttributeKey::ATTR_REMAIN_TIMES, remainTimes);
        extraInfo.GetInt32Value(Attributes::AttributeKey::ATTR_FREEZING_TIME, freezingTime);
        Attributes errInfo;
        errInfo.SetInt32Value(Attributes::AttributeKey::ATTR_REMAIN_TIMES, remainTimes);
        errInfo.SetInt32Value(Attributes::AttributeKey::ATTR_FREEZING_TIME, freezingTime);
        innerCallback_->OnResult(ResultCode::FAIL, errInfo);
        return AccountInfoReport::ReportSecurityInfo("", authedAccountId, ReportEvent::EVENT_LOGIN, ResultCode::FAIL);
    }
    uint64_t credentialId = 0;
    if (!extraInfo.GetUint64Value(Attributes::AttributeKey::ATTR_CREDENTIAL_ID, credentialId) && (credentialId_ != 0)) {
        Attributes extraAuthInfo;
        GenerateAttributesInfo(extraInfo, extraAuthInfo);
        extraAuthInfo.SetUint64Value(Attributes::AttributeKey::ATTR_CREDENTIAL_ID, credentialId_);
        innerCallback_->OnResult(result, extraAuthInfo);
    } else {
        innerCallback_->OnResult(result, extraInfo);
    }
    if (isUpdateVerifiedStatus) {
        (void)IInnerOsAccountManager::GetInstance().SetOsAccountIsVerified(authedAccountId, true);
    }
    (void)IInnerOsAccountManager::GetInstance().SetOsAccountIsLoggedIn(authedAccountId, true);
    AccountInfoReport::ReportSecurityInfo("", authedAccountId, ReportEvent::EVENT_LOGIN, result);
}

void AuthCallback::OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo)
{
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGE("innerCallback_ is nullptr");
        return;
    }
    innerCallback_->OnAcquireInfo(module, acquireInfo, extraInfo);
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
    ACCOUNT_LOGI("AddCredCallback, result=%{public}d.", result);
    if (innerCallback_ == nullptr || innerCallback_->AsObject() == nullptr) {
        ACCOUNT_LOGE("innerCallback_ is nullptr");
        return;
    }
    innerCallback_->AsObject()->RemoveDeathRecipient(deathRecipient_);
    auto &innerIamMgr_ = InnerAccountIAMManager::GetInstance();
    if ((result == 0) && (credInfo_.authType == AuthType::PIN)) {
        InnerAccountIAMManager::GetInstance().SetState(userId_, AFTER_ADD_CRED);
        uint64_t credentialId = 0;
        extraInfo.GetUint64Value(Attributes::AttributeKey::ATTR_CREDENTIAL_ID, credentialId);
        (void)IInnerOsAccountManager::GetInstance().SetOsAccountCredentialId(userId_, credentialId);

        uint64_t secureUid = 0;
        extraInfo.GetUint64Value(Attributes::AttributeKey::ATTR_SEC_USER_ID, secureUid);
        std::vector<uint8_t> newSecret;
        extraInfo.GetUint8ArrayValue(Attributes::ATTR_ROOT_SECRET, newSecret);
        std::vector<uint8_t> token;
        extraInfo.GetUint8ArrayValue(Attributes::ATTR_AUTH_TOKEN, token);
        std::vector<uint8_t> oldSecret;
        ErrCode code = innerIamMgr_.UpdateStorageKey(userId_, secureUid, token, oldSecret, newSecret);
        if (code == ERR_OK) {
            std::string path = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + std::to_string(userId_) +
                Constants::PATH_SEPARATOR + Constants::USER_ADD_SECRET_FLAG_FILE_NAME;
            auto accountFileOperator = std::make_shared<AccountFileOperator>();
            code = accountFileOperator->DeleteDirOrFile(path);
            if (code != ERR_OK) {
                ACCOUNT_LOGE("Delete file fail, path=%{public}s", path.c_str());
            }
        }
    }
    if (result != 0) {
        ReportOsAccountOperationFail(userId_, "addCredential", result, "Add credential failed");
    }
    innerIamMgr_.SetState(userId_, AFTER_OPEN_SESSION);
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

static void DeleteCredential(uint32_t userId, uint64_t credentialId, const std::vector<uint8_t> &token)
{
    auto idmCallback = std::make_shared<DelCredCallback>(userId, true, token, nullptr);
    UserIDMClient::GetInstance().DeleteCredential(userId, credentialId, token, idmCallback);
}

void UpdateCredCallback::OnResult(int32_t result, const Attributes &extraInfo)
{
    ACCOUNT_LOGI("UpdateCredCallback, userId=%{public}d, result=%{public}d.", userId_, result);
    if (innerCallback_ == nullptr || innerCallback_->AsObject() == nullptr) {
        ACCOUNT_LOGE("inner callback is nullptr");
        return;
    }
    innerCallback_->AsObject()->RemoveDeathRecipient(deathRecipient_);
    auto &innerIamMgr_ = InnerAccountIAMManager::GetInstance();
    if ((result != 0) || (credInfo_.authType != AuthType::PIN)) {
        ACCOUNT_LOGE("UpdateCredCallback fail code=%{public}d, authType=%{public}d", result, credInfo_.authType);
        innerIamMgr_.SetState(userId_, AFTER_OPEN_SESSION);
        innerCallback_->OnResult(result, extraInfo);
        return;
    }
    UpdateCredInfo updateCredInfo;
    extraInfo.GetUint64Value(Attributes::AttributeKey::ATTR_CREDENTIAL_ID, updateCredInfo.credentialId);
    extraInfo.GetUint64Value(Attributes::AttributeKey::ATTR_SEC_USER_ID, updateCredInfo.secureUid);
    extraInfo.GetUint8ArrayValue(Attributes::ATTR_AUTH_TOKEN, updateCredInfo.token);
    extraInfo.GetUint8ArrayValue(Attributes::ATTR_ROOT_SECRET, updateCredInfo.newSecret);
    extraInfo.GetUint8ArrayValue(Attributes::ATTR_OLD_ROOT_SECRET, updateCredInfo.oldSecret);
    if (updateCredInfo.oldSecret.empty()) {
        ErrCode code = innerIamMgr_.UpdateUserAuthWithRecoveryKey(credInfo_.token,
            updateCredInfo.newSecret, updateCredInfo.secureUid, userId_);
        if (code != ERR_OK) {
            DeleteCredential(userId_, updateCredInfo.credentialId, credInfo_.token);
            innerIamMgr_.SetState(userId_, AFTER_OPEN_SESSION);
            return innerCallback_->OnResult(code, extraInfo);
        }
    } else {
        ErrCode code = innerIamMgr_.UpdateStorageUserAuth(userId_, updateCredInfo.secureUid,
            updateCredInfo.token, updateCredInfo.oldSecret, {});
        if (code != ERR_OK) {
            DeleteCredential(userId_, updateCredInfo.credentialId, credInfo_.token);
            innerIamMgr_.SetState(userId_, AFTER_OPEN_SESSION);
            return innerCallback_->OnResult(code, extraInfo);
        }
    }
    innerIamMgr_.SetState(userId_, AFTER_UPDATE_CRED);
    uint64_t oldCredentialId = 0;
    extraInfo.GetUint64Value(Attributes::AttributeKey::ATTR_OLD_CREDENTIAL_ID, oldCredentialId);
    auto idmCallback = std::make_shared<CommitCredUpdateCallback>(userId_, updateCredInfo, innerCallback_);
    Security::AccessToken::AccessTokenID selfToken = IPCSkeleton::GetSelfTokenID();
    result = SetFirstCallerTokenID(selfToken);
    ACCOUNT_LOGI("Set first caller info result: %{public}d", result);
    UserIDMClient::GetInstance().DeleteCredential(userId_, oldCredentialId, credInfo_.token, idmCallback);
}

void UpdateCredCallback::OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo)
{
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGE("innerCallback_ is nullptr");
        return;
    }
    innerCallback_->OnAcquireInfo(module, acquireInfo, extraInfo);
}

#ifdef HAS_PIN_AUTH_PART
void DelUserInputer::OnGetData(int32_t authSubType, std::vector<uint8_t> challenge,
    std::shared_ptr<IInputerData> inputerData)
{
    ACCOUNT_LOGI("Get temporary data, authSubType: %{public}d", authSubType);
    if (inputerData == nullptr) {
        ACCOUNT_LOGE("InputerData is nullptr");
        return;
    }
    inputerData->OnSetData(authSubType, TEMP_PIN);
}

DelUserCallback::DelUserCallback(uint32_t userId, const sptr<IIDMCallback> &callback)
    : userId_(userId), innerCallback_(callback)
{}

DelUserCallback::~DelUserCallback()
{
    InnerAccountIAMManager::GetInstance().OnDelUserDone(userId_);
}

static int32_t ConvertDelUserErrCode(int32_t result)
{
    switch (result) {
        case ResultCode::NOT_ENROLLED:
        case ResultCode::INVALID_PARAMETERS:
            return ERR_IAM_TOKEN_AUTH_FAILED;
        case ResultCode::CANCELED:
        case ResultCode::TIMEOUT:
            return ERR_IAM_GENERAL_ERROR;
        default:
            return result;
    }
}

void DelUserCallback::OnResult(int32_t result, const Attributes &extraInfo)
{
    ACCOUNT_LOGI("DelUserCallback, userId: %{public}d, result: %{public}d", userId_, result);
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGE("Inner callbcak is nullptr");
        return;
    }
    result = ConvertDelUserErrCode(result);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("DelUserCallback fail code = %{public}d", result);
        return innerCallback_->OnResult(result, extraInfo);
    }
    uint64_t secureUid = 0;
    extraInfo.GetUint64Value(Attributes::AttributeKey::ATTR_SEC_USER_ID, secureUid);
    std::vector<uint8_t> oldSecret;
    extraInfo.GetUint8ArrayValue(Attributes::ATTR_OLD_ROOT_SECRET, oldSecret);
    std::vector<uint8_t> token;
    extraInfo.GetUint8ArrayValue(Attributes::ATTR_AUTH_TOKEN, token);
    auto &innerIamMgr_ = InnerAccountIAMManager::GetInstance();
    ErrCode errCode = innerIamMgr_.UpdateStorageUserAuth(userId_, secureUid, token, oldSecret, {});
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Fail to delete root secret, userId=%{public}d, errcode=%{public}d", userId_, errCode);
        return innerCallback_->OnResult(errCode, extraInfo);
    }

    auto eraseUserCallback = std::make_shared<OsAccountDeleteUserIdmCallback>();
    errCode = UserIam::UserAuth::UserIdmClient::GetInstance().EraseUser(userId_, eraseUserCallback);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Fail to erase user, userId=%{public}d, errcode=%{public}d", userId_, errCode);
        return innerCallback_->OnResult(errCode, extraInfo);
    }
    std::unique_lock<std::mutex> lock(eraseUserCallback->mutex_);
    eraseUserCallback->onResultCondition_.wait(lock, [eraseUserCallback] {
        return eraseUserCallback->isCalled_;
    });
    if (eraseUserCallback->resultCode_ != ERR_OK) {
        ACCOUNT_LOGE("Fail to erase user, userId=%{public}d, errcode=%{public}d",
            userId_, eraseUserCallback->resultCode_);
        return innerCallback_->OnResult(eraseUserCallback->resultCode_, extraInfo);
    }
    (void)IInnerOsAccountManager::GetInstance().SetOsAccountCredentialId(userId_, 0);
    errCode = innerIamMgr_.UpdateStorageKeyContext(userId_);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Fail to update key context, userId=%{public}d, errcode=%{public}d", userId_, errCode);
    }
    innerCallback_->OnResult(errCode, extraInfo);
}
#endif // HAS_PIN_AUTH_PART

CommitCredUpdateCallback::CommitCredUpdateCallback(int32_t userId,
    const UpdateCredInfo &extraUpdateInfo, const sptr<IIDMCallback> &callback)
    : userId_(userId), extraUpdateInfo_(extraUpdateInfo), innerCallback_(callback)
{}

void CommitCredUpdateCallback::OnResult(int32_t result, const Attributes &extraInfo)
{
    ACCOUNT_LOGI("CommitCredUpdateCallback, result=%{public}d.", result);
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGE("innerCallback_ is nullptr");
        return;
    }

    auto &innerIamMgr_ = InnerAccountIAMManager::GetInstance();
    if (result != 0) {
        ACCOUNT_LOGE("CommitCredUpdateCallback fail code=%{public}d", result);
        ReportOsAccountOperationFail(userId_, "CommitCredUpdated", result, "Fail to commit cred updated");
        innerCallback_->OnResult(result, extraInfo);
        innerIamMgr_.SetState(userId_, AFTER_OPEN_SESSION);
        return;
    }
    if (!extraUpdateInfo_.oldSecret.empty()) {
        ErrCode code = innerIamMgr_.UpdateStorageUserAuth(
            userId_, extraUpdateInfo_.secureUid, extraUpdateInfo_.token, {}, extraUpdateInfo_.newSecret);
        if (code != ERR_OK) {
            ACCOUNT_LOGE("Fail to update user auth, userId=%{public}d, code=%{public}d", userId_, code);
            innerIamMgr_.SetState(userId_, AFTER_OPEN_SESSION);
            innerCallback_->OnResult(code, extraInfo);
            return;
        }
    }
    Attributes extraInfoResult;
    extraInfoResult.SetUint64Value(Attributes::AttributeKey::ATTR_CREDENTIAL_ID, extraUpdateInfo_.credentialId);
    innerCallback_->OnResult(result, extraInfoResult);
    innerIamMgr_.UpdateStorageKeyContext(userId_);
    innerIamMgr_.SetState(userId_, AFTER_OPEN_SESSION);
}

void CommitCredUpdateCallback::OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo)
{
    ACCOUNT_LOGE("CommitCredUpdateCallback OnAcquireInfo");
}

DelCredCallback::DelCredCallback(int32_t userId, bool isPIN, std::vector<uint8_t> token,
    const sptr<IIDMCallback> &callback)
    : userId_(userId), isPIN_(isPIN), token_(token), innerCallback_(callback)
{}

void DelCredCallback::OnResult(int32_t result, const Attributes &extraInfo)
{
    ACCOUNT_LOGI("DelCredCallback, result=%{public}d, userId=%{public}d", result, userId_);
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGE("innerCallback_ is nullptr");
        return;
    }
    auto &innerIamMgr_ = InnerAccountIAMManager::GetInstance();
    if ((result == 0) && isPIN_) {
        (void)IInnerOsAccountManager::GetInstance().SetOsAccountCredentialId(userId_, 0);  // 0-invalid credentialId
        std::vector<uint8_t> newSecret;
        std::vector<uint8_t> oldSecret;
        extraInfo.GetUint8ArrayValue(Attributes::ATTR_OLD_ROOT_SECRET, oldSecret);
        uint64_t secureUid = 0;
        extraInfo.GetUint64Value(Attributes::AttributeKey::ATTR_SEC_USER_ID, secureUid);
        (void) innerIamMgr_.UpdateStorageKey(userId_, secureUid, token_, oldSecret, newSecret);
    }
    if (result != 0) {
        ACCOUNT_LOGE("DelCredCallback fail code=%{public}d, userId=%{public}d", result, userId_);
        ReportOsAccountOperationFail(userId_, "deleteCredential", result, "fail to delete credential");
    }

    innerIamMgr_.SetState(userId_, AFTER_OPEN_SESSION);
    innerCallback_->OnResult(result, extraInfo);
}

void DelCredCallback::OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo)
{
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGE("innerCallback_ is nullptr");
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

GetSecUserInfoCallbackWrapper::GetSecUserInfoCallbackWrapper(
    AuthType authType, const sptr<IGetEnrolledIdCallback> &callback)
    : authType_(authType), innerCallback_(callback)
{}

void GetSecUserInfoCallbackWrapper::OnSecUserInfo(const SecUserInfo &info)
{
    if (innerCallback_ == nullptr) {
        return;
    }

    auto it = std::find_if(info.enrolledInfo.begin(), info.enrolledInfo.end(), [this](const auto& item) {
        return item.authType == authType_;
    });
    if (it != info.enrolledInfo.end()) {
        return innerCallback_->OnEnrolledId(ERR_OK, it->enrolledId);
    } else {
        return innerCallback_->OnEnrolledId(ERR_IAM_NOT_ENROLLED, 0);
    }
}

GetSecureUidCallback::GetSecureUidCallback(int32_t userId): userId_(userId)
{}

void GetSecureUidCallback::OnSecUserInfo(const SecUserInfo &info)
{
    ACCOUNT_LOGI("SecUserInfo call back userId=%{public}d", userId_);
    std::unique_lock<std::mutex> lck(secureMtx_);
    this->secureUid_ = info.secureUid;
    isCalled_ = true;
    secureCv_.notify_all();
}

PrepareRemoteAuthCallbackWrapper::PrepareRemoteAuthCallbackWrapper(const sptr<IPreRemoteAuthCallback> &callback)
    : innerCallback_(callback)
{}

void PrepareRemoteAuthCallbackWrapper::OnResult(int32_t result)
{
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGE("Inner callback is nullptr.");
        return;
    }
    if (result != 0) {
        ACCOUNT_LOGE("PrepareRemoteAuth, result=%{public}d fail to prepare remote auth.", result);
    }
    innerCallback_->OnResult(result);
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
