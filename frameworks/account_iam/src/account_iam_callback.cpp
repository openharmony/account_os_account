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

#include "account_iam_callback.h"

#include "account_iam_client.h"
#include "account_log_wrapper.h"
#include "os_account_manager.h"
#include "pinauth_register.h"
#include "user_auth_client.h"
#include "user_idm_client.h"

namespace OHOS {
namespace AccountSA {
using UserIDMClient = UserIam::UserAuth::UserIdmClient;
using UserAuthClient = UserIam::UserAuth::UserAuthClient;

AuthCallback::AuthCallback(uint32_t userId, const std::shared_ptr<AuthenticationCallback> &callback)
    : userId_(userId), innerCallback_(callback)
{}

AuthCallback::~AuthCallback()
{}

void AuthCallback::OnResult(int32_t result, const Attributes &extraInfo)
{
    ACCOUNT_LOGD("enter");
    AccountIAMClient::GetInstance().SetState(userId_, AFTER_OPEN_SESSION);
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGD("innerCallback_ is nullptr");
        return;
    }
    if (result != 0) {
        innerCallback_->OnResult(result, extraInfo);
        return;
    }
    std::vector<uint8_t> token;
    std::vector<uint8_t> secret;
    extraInfo.GetUint8ArrayValue(Attributes::ATTR_SIGNATURE, token);
    extraInfo.GetUint8ArrayValue(Attributes::ATTR_ROOT_SECRET, secret);
    int32_t activeResult =
        AccountIAMClient::GetInstance().ActivateUserKey(userId_, token, secret);
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
    }
}

void AuthCallback::OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo)
{
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGD("innerCallback_ is nullptr");
        return;
    }
    innerCallback_->OnAcquireInfo(module, acquireInfo, extraInfo);
}

IDMAuthCallback::IDMAuthCallback(uint32_t userId, const CredentialParameters &credInfo,
    int32_t oldResult, const Attributes &reqResult, const std::shared_ptr<UserIdmClientCallback> &idmCallback)
    : userId_(userId), credInfo_(credInfo), oldResult_(oldResult), idmCallback_(idmCallback)
{
    reqResult.GetUint64Value(Attributes::AttributeKey::ATTR_CREDENTIAL_ID, credentialId_);
    reqResult_.SetUint64Value(Attributes::AttributeKey::ATTR_CREDENTIAL_ID, credentialId_);
}

IDMAuthCallback::~IDMAuthCallback()
{}

void IDMAuthCallback::OnResult(int32_t result, const Attributes &extraInfo)
{
    ACCOUNT_LOGD("enter");
    if (idmCallback_ == nullptr) {
        ACCOUNT_LOGD("inner callback is nullptr");
        return;
    }
    if (result != 0) {
        idmCallback_->OnResult(ResultCode::FAIL, reqResult_);
        AccountIAMClient::GetInstance().SetState(userId_, AFTER_OPEN_SESSION);
        return;
    }
    std::vector<uint8_t> token;
    std::vector<uint8_t> secret;
    extraInfo.GetUint8ArrayValue(Attributes::ATTR_SIGNATURE, token);
    extraInfo.GetUint8ArrayValue(Attributes::ATTR_ROOT_SECRET, secret);
    int32_t updateKeyResult = AccountIAMClient::GetInstance().UpdateUserKey(
        userId_, credentialId_, token, secret);
    if (updateKeyResult == 0) {
        ACCOUNT_LOGD("unlock user key successfully");
        idmCallback_->OnResult(oldResult_, reqResult_);
        return;
    }
    IAMState state = AccountIAMClient::GetInstance().GetState(userId_);
    if (state == AFTER_ADD_CRED) {
        ACCOUNT_LOGE("failed to unlock user key, delete the added credential");
        AccountIAMClient::GetInstance().SetState(userId_, ROLL_BACK_ADD_CRED);
        auto delCallback = std::make_shared<DelCredCallback>(userId_, credentialId_, token, idmCallback_);
        UserIDMClient::GetInstance().DeleteCredential(userId_, credentialId_, token, delCallback);
    } else if (state == AFTER_UPDATE_CRED) {
        ACCOUNT_LOGE("failed to unlock user key, restore the old credential");
        AccountIAMClient::GetInstance().SetState(userId_, ROLL_BACK_UPDATE_CRED);
        credInfo_.token = token;
        auto updateCallback = std::make_shared<UpdateCredCallback>(userId_, credInfo_, idmCallback_);
        UserIDMClient::GetInstance().UpdateCredential(0, credInfo_, updateCallback);
    } else {
        idmCallback_->OnResult(oldResult_, reqResult_);
    }
}

void IDMAuthCallback::OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo)
{
    ACCOUNT_LOGD("unsupported operation");
}

AddCredCallback::AddCredCallback(uint32_t userId, const CredentialParameters &credInfo,
    const std::shared_ptr<UserIdmClientCallback> &callback)
    : userId_(userId), credInfo_(credInfo), innerCallback_(callback)
{}

AddCredCallback::~AddCredCallback()
{}

void AddCredCallback::OnResult(int32_t result, const Attributes &extraInfo)
{
    ACCOUNT_LOGD("enter");
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGD("inner callback is nullptr");
        return;
    }
    if (result != 0) {
        ACCOUNT_LOGD("failed to add credential");
        innerCallback_->OnResult(result, extraInfo);
        AccountIAMClient::GetInstance().SetState(userId_, AFTER_OPEN_SESSION);
        return;
    }
    AccountIAMClient::GetInstance().SetState(userId_, AFTER_ADD_CRED);
    std::vector<uint8_t> challenge;
    AccountIAMClient::GetInstance().GetChallenge(userId_, challenge);
    auto callback = std::make_shared<IDMAuthCallback>(userId_, credInfo_, result, extraInfo, innerCallback_);
    UserAuthClient::GetInstance().BeginAuthentication(
        userId_, challenge, AuthType::PIN, AuthTrustLevel::ATL4, callback);
}

void AddCredCallback::OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo)
{
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGD("innerCallback_ is nullptr");
        return;
    }
    innerCallback_->OnAcquireInfo(module, acquireInfo, extraInfo);
}

UpdateCredCallback::UpdateCredCallback(
    uint32_t userId, const CredentialParameters &credInfo, const std::shared_ptr<UserIdmClientCallback> &callback)
    : userId_(userId), credInfo_(credInfo), innerCallback_(callback)
{}

UpdateCredCallback::~UpdateCredCallback()
{}

void UpdateCredCallback::OnResult(int32_t result, const Attributes &extraInfo)
{
    ACCOUNT_LOGD("enter");
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGD("inner callback is nullptr");
        return;
    }
    IAMState state = AccountIAMClient::GetInstance().GetState(userId_);
    if (state == ROLL_BACK_UPDATE_CRED) {
        if (result != 0) {
            ACCOUNT_LOGE("roll back credential failed");
        } else {
            ACCOUNT_LOGD("roll back credential successully");
        }
        AccountIAMClient::GetInstance().SetState(userId_, AFTER_OPEN_SESSION);
        Attributes errResult;
        innerCallback_->OnResult(ResultCode::FAIL, errResult);
        return;
    }
    if (result != 0) {
        ACCOUNT_LOGD("failed to update credential");
        innerCallback_->OnResult(result, extraInfo);
        AccountIAMClient::GetInstance().SetState(userId_, AFTER_OPEN_SESSION);
        return;
    }
    AccountIAMClient::GetInstance().SetState(userId_, AFTER_UPDATE_CRED);
    std::vector<uint8_t> challenge;
    AccountIAMClient::GetInstance().GetChallenge(userId_, challenge);
    auto callback = std::make_shared<IDMAuthCallback>(userId_, credInfo_, result, extraInfo, innerCallback_);
    UserAuthClient::GetInstance().BeginAuthentication(
        userId_, challenge, AuthType::PIN, AuthTrustLevel::ATL4, callback);
}

void UpdateCredCallback::OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo)
{
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGD("innerCallback_ is nullptr");
        return;
    }
    innerCallback_->OnAcquireInfo(module, acquireInfo, extraInfo);
}

DelCredCallback::DelCredCallback(int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken,
    const std::shared_ptr<UserIdmClientCallback> &callback)
    : userId_(userId), credentialId_(credentialId), authToken_(authToken), innerCallback_(callback)
{}

DelCredCallback::~DelCredCallback()
{}

void DelCredCallback::OnResult(int32_t result, const Attributes &extraInfo)
{
    ACCOUNT_LOGD("enter");
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGD("innerCallback_ is nullptr");
        return;
    }
    IAMState state = AccountIAMClient::GetInstance().GetState(userId_);
    if (state == ROLL_BACK_ADD_CRED) {
        if (result != 0) {
            ACCOUNT_LOGE("roll back credential failed");
        } else {
            ACCOUNT_LOGD("roll back credential successully");
        }
        AccountIAMClient::GetInstance().SetState(userId_, AFTER_OPEN_SESSION);
        Attributes errResult;
        innerCallback_->OnResult(ResultCode::FAIL, errResult);
        return;
    }
    if (result == 0) {
        AccountIAMClient::GetInstance().SetState(userId_, AFTER_OPEN_SESSION);
    } else {
        AccountIAMClient::GetInstance().RestoreUserKey(userId_, credentialId_, authToken_);
    }
    innerCallback_->OnResult(result, extraInfo);
}

void DelCredCallback::OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo)
{
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGD("inner callback is nullptr");
        return;
    }
    innerCallback_->OnAcquireInfo(module, acquireInfo, extraInfo);
}

IAMInputerData::IAMInputerData(int32_t userId, const std::shared_ptr<IInputerData> &inputerData)
    : userId_(userId), innerInputerData_(inputerData)
{}

IAMInputerData::~IAMInputerData()
{}

void IAMInputerData::OnSetData(int32_t authSubType, std::vector<uint8_t> data)
{
    AccountIAMClient::GetInstance().SetCredential(userId_, authSubType, data);
    AccountIAMClient::GetInstance().SetCredential(userId_, 0, data);
    innerInputerData_->OnSetData(authSubType, data);
}

void IAMInputerData::ResetInnerInputerData(const std::shared_ptr<IInputerData> &inputerData)
{
    innerInputerData_ = inputerData;
}

IAMInputer::IAMInputer(int32_t userId, const std::shared_ptr<IInputer> &inputer)
    : userId_(userId), innerInputer_(inputer)
{
    auto iamInputerData = new (std::nothrow) IAMInputerData(userId, nullptr);
    if (iamInputerData == nullptr) {
        ACCOUNT_LOGD("failed to create IAMInputerData");
        return;
    }
    inputerData_.reset(iamInputerData);
}

IAMInputer::~IAMInputer()
{}

void IAMInputer::OnGetData(int32_t authSubType, std::shared_ptr<IInputerData> inputerData)
{
    ACCOUNT_LOGD("enter");
    if (inputerData_ == nullptr) {
        ACCOUNT_LOGD("inputerData_ is nullptr");
        return;
    }
    inputerData_->ResetInnerInputerData(inputerData);
    IAMState state = AccountIAMClient::GetInstance().GetState(userId_);
    if (state < AFTER_ADD_CRED) {
        innerInputer_->OnGetData(authSubType, inputerData_);
        return;
    }
    CredentialPair credPair;
    AccountIAMClient::GetInstance().GetCredential(userId_, authSubType, credPair);
    if (state == ROLL_BACK_UPDATE_CRED) {
        inputerData->OnSetData(authSubType, credPair.oldCredential);
    } else {
        inputerData->OnSetData(authSubType, credPair.credential);
    }
}

void IAMInputer::ResetInnerInputer(const std::shared_ptr<IInputer> &inputer)
{
    innerInputer_ = inputer;
}
}  // namespace AccountSA
}  // namespace OHOS
