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

#include "account_log_wrapper.h"
#include "iinner_os_account_manager.h"
#include "inner_account_iam_manager.h"
#include "user_auth_client.h"
#include "user_idm_client.h"

namespace OHOS {
namespace AccountSA {
using UserIDMClient = UserIam::UserAuth::UserIdmClient;
using UserAuthClient = UserIam::UserAuth::UserAuthClient;

AuthCallback::AuthCallback(uint32_t userId, AuthType authType, const sptr<IIDMCallback> &callback)
    : userId_(userId), authType_(authType), innerCallback_(callback)
{}

void AuthCallback::OnResult(int32_t result, const Attributes &extraInfo)
{
    InnerAccountIAMManager::GetInstance().SetState(userId_, AFTER_OPEN_SESSION);
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGE("innerCallback_ is nullptr");
        return;
    }
    if (result != 0 || authType_ != AuthType::PIN) {
        innerCallback_->OnResult(result, extraInfo);
        return;
    }
    std::vector<uint8_t> token;
    std::vector<uint8_t> secret;
    extraInfo.GetUint8ArrayValue(Attributes::ATTR_SIGNATURE, token);
    extraInfo.GetUint8ArrayValue(Attributes::ATTR_ROOT_SECRET, secret);
    int32_t activeResult =
        InnerAccountIAMManager::GetInstance().ActivateUserKey(userId_, token, secret);
    if (activeResult != 0) {
        ACCOUNT_LOGE("failed to activate user key");
        int32_t remainTimes = 0;
        int32_t freezingTime = 0;
        extraInfo.GetInt32Value(Attributes::AttributeKey::ATTR_REMAIN_TIMES, remainTimes);
        extraInfo.GetInt32Value(Attributes::AttributeKey::ATTR_FREEZING_TIME, freezingTime);
        Attributes errInfo;
        errInfo.SetInt32Value(Attributes::AttributeKey::ATTR_REMAIN_TIMES, remainTimes);
        errInfo.SetInt32Value(Attributes::AttributeKey::ATTR_FREEZING_TIME, freezingTime);
        innerCallback_->OnResult(ResultCode::FAIL, errInfo);
    } else {
        innerCallback_->OnResult(result, extraInfo);
        (void)IInnerOsAccountManager::GetInstance()->SetOsAccountIsVerified(userId_, true);
    }
}

void AuthCallback::OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo)
{
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGE("innerCallback_ is nullptr");
        return;
    }
    innerCallback_->OnAcquireInfo(module, acquireInfo, extraInfo);
}

IDMAuthCallback::IDMAuthCallback(uint32_t userId, const CredentialParameters &credInfo,
    int32_t oldResult, const Attributes &reqResult, const sptr<IIDMCallback> &idmCallback)
    : userId_(userId), credInfo_(credInfo), oldResult_(oldResult), idmCallback_(idmCallback)
{
    reqResult.GetUint64Value(Attributes::AttributeKey::ATTR_CREDENTIAL_ID, credentialId_);
    reqResult_.SetUint64Value(Attributes::AttributeKey::ATTR_CREDENTIAL_ID, credentialId_);
}

void IDMAuthCallback::OnResult(int32_t result, const Attributes &extraInfo)
{
    if (idmCallback_ == nullptr) {
        ACCOUNT_LOGE("inner callback is nullptr");
        return;
    }
    if (result != 0) {
        idmCallback_->OnResult(ResultCode::FAIL, reqResult_);
        InnerAccountIAMManager::GetInstance().SetState(userId_, AFTER_OPEN_SESSION);
        return;
    }
    std::vector<uint8_t> token;
    std::vector<uint8_t> secret;
    extraInfo.GetUint8ArrayValue(Attributes::ATTR_SIGNATURE, token);
    extraInfo.GetUint8ArrayValue(Attributes::ATTR_ROOT_SECRET, secret);
    int32_t updateKeyResult = InnerAccountIAMManager::GetInstance().UpdateUserKey(
        userId_, credentialId_, token, secret);
    if (updateKeyResult == 0) {
        InnerAccountIAMManager::GetInstance().SetState(userId_, AFTER_OPEN_SESSION);
        idmCallback_->OnResult(oldResult_, reqResult_);
        return;
    }
    IAMState state = InnerAccountIAMManager::GetInstance().GetState(userId_);
    if (state == AFTER_ADD_CRED) {
        ACCOUNT_LOGE("failed to unlock user key, delete the added credential");
        InnerAccountIAMManager::GetInstance().SetState(userId_, ROLL_BACK_ADD_CRED);
        auto delCallback = std::make_shared<DelCredCallback>(userId_, credentialId_, token, idmCallback_);
        UserIDMClient::GetInstance().DeleteCredential(userId_, credentialId_, token, delCallback);
    } else if (state == AFTER_UPDATE_CRED) {
        ACCOUNT_LOGE("failed to unlock user key, restore the old credential");
        InnerAccountIAMManager::GetInstance().SetState(userId_, ROLL_BACK_UPDATE_CRED);
        credInfo_.token = token;
        auto updateCallback = std::make_shared<UpdateCredCallback>(userId_, credInfo_, idmCallback_);
        UserIDMClient::GetInstance().UpdateCredential(0, credInfo_, updateCallback);
    } else {
        InnerAccountIAMManager::GetInstance().SetState(userId_, AFTER_OPEN_SESSION);
        idmCallback_->OnResult(oldResult_, reqResult_);
    }
}

void IDMAuthCallback::OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo)
{
    ACCOUNT_LOGW("unsupported operation");
}

AddCredCallback::AddCredCallback(uint32_t userId, const CredentialParameters &credInfo,
    const sptr<IIDMCallback> &callback)
    : userId_(userId), credInfo_(credInfo), innerCallback_(callback)
{}

void AddCredCallback::OnResult(int32_t result, const Attributes &extraInfo)
{
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGE("inner callback is nullptr");
        return;
    }
    if (result != 0 || credInfo_.authType != AuthType::PIN) {
        ACCOUNT_LOGE("failed to add credential, result = %{public}d", result);
        innerCallback_->OnResult(result, extraInfo);
        InnerAccountIAMManager::GetInstance().SetState(userId_, AFTER_OPEN_SESSION);
        return;
    }
    InnerAccountIAMManager::GetInstance().SetState(userId_, AFTER_ADD_CRED);
    std::vector<uint8_t> challenge;
    InnerAccountIAMManager::GetInstance().GetChallenge(userId_, challenge);
    auto callback = std::make_shared<IDMAuthCallback>(userId_, credInfo_, result, extraInfo, innerCallback_);
    UserAuthClient::GetInstance().BeginAuthentication(
        userId_, challenge, AuthType::PIN, AuthTrustLevel::ATL4, callback);
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

void UpdateCredCallback::OnResult(int32_t result, const Attributes &extraInfo)
{
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGE("inner callback is nullptr");
        return;
    }
    IAMState state = InnerAccountIAMManager::GetInstance().GetState(userId_);
    if (state == ROLL_BACK_UPDATE_CRED) {
        if (result != 0) {
            ACCOUNT_LOGE("roll back credential failed");
        }
        InnerAccountIAMManager::GetInstance().SetState(userId_, AFTER_OPEN_SESSION);
        Attributes errResult;
        innerCallback_->OnResult(ResultCode::FAIL, errResult);
        return;
    }
    if (result != 0 || credInfo_.authType != AuthType::PIN) {
        ACCOUNT_LOGE("failed to update credential");
        innerCallback_->OnResult(result, extraInfo);
        InnerAccountIAMManager::GetInstance().SetState(userId_, AFTER_OPEN_SESSION);
        return;
    }
    InnerAccountIAMManager::GetInstance().SetState(userId_, AFTER_UPDATE_CRED);
    std::vector<uint8_t> challenge;
    InnerAccountIAMManager::GetInstance().GetChallenge(userId_, challenge);
    auto callback = std::make_shared<IDMAuthCallback>(userId_, credInfo_, result, extraInfo, innerCallback_);
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

DelCredCallback::DelCredCallback(int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken,
    const sptr<IIDMCallback> &callback)
    : userId_(userId), credentialId_(credentialId), authToken_(authToken), innerCallback_(callback)
{}

void DelCredCallback::OnResult(int32_t result, const Attributes &extraInfo)
{
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGE("innerCallback_ is nullptr");
        return;
    }
    IAMState state = InnerAccountIAMManager::GetInstance().GetState(userId_);
    if (state == ROLL_BACK_ADD_CRED) {
        if (result != 0) {
            ACCOUNT_LOGE("roll back credential failed");
        }
        InnerAccountIAMManager::GetInstance().SetState(userId_, AFTER_OPEN_SESSION);
        Attributes errResult;
        innerCallback_->OnResult(ResultCode::FAIL, errResult);
        return;
    }
    if (result != 0) {
        InnerAccountIAMManager::GetInstance().RestoreUserKey(userId_, credentialId_, authToken_);
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

GetPropCallbackWrapper::GetPropCallbackWrapper(const sptr<IGetSetPropCallback> &callback) : innerCallback_(callback)
{}

void GetPropCallbackWrapper::OnResult(int32_t result, const Attributes &extraInfo)
{
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGE("inner callback is nullptr");
        return;
    }
    innerCallback_->OnResult(result, extraInfo);
}

SetPropCallbackWrapper::SetPropCallbackWrapper(const sptr<IGetSetPropCallback> &callback) : innerCallback_(callback)
{}

void SetPropCallbackWrapper::OnResult(int32_t result, const Attributes &extraInfo)
{
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGE("inner callback is nullptr");
        return;
    }
    innerCallback_->OnResult(result, extraInfo);
}
}  // namespace AccountSA
}  // namespace OHOS
