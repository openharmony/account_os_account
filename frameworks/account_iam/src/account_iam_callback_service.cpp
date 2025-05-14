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

#include "account_iam_callback_service.h"

#include "account_error_no.h"
#include "account_iam_client.h"
#include "account_log_wrapper.h"
#include "domain_account_client.h"

namespace OHOS {
namespace AccountSA {
IDMCallbackService::IDMCallbackService(int32_t userId, const std::shared_ptr<IDMCallback> &callback)
    : userId_(userId), callback_(callback)
{}

IDMCallbackService::~IDMCallbackService()
{
    if (!isCalled_ && (callback_ != nullptr)) {
        ACCOUNT_LOGW("No valid result returned because system exception");
        Attributes emptyAttributes;
        callback_->OnResult(ERR_ACCOUNT_ZIDL_ACCOUNT_SERVICE_ERROR, emptyAttributes);
    }
}

void IDMCallbackService::OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo)
{
    if (callback_ == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return;
    }
    callback_->OnAcquireInfo(module, acquireInfo, extraInfo);
}

void IDMCallbackService::OnResult(int32_t result, const Attributes &extraInfo)
{
    isCalled_ = true;
    if (callback_ == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return;
    }
    if (result != 0) {
        ACCOUNT_LOGE("idm operation failure, localId: %{public}d", userId_);
    }
    callback_->OnResult(result, extraInfo);
}

GetCredInfoCallbackService::GetCredInfoCallbackService(const std::shared_ptr<GetCredInfoCallback> &callback)
    : callback_(callback)
{}

GetCredInfoCallbackService::~GetCredInfoCallbackService()
{
    if (!isCalled_ && (callback_ != nullptr)) {
        ACCOUNT_LOGW("No valid result returned because system exception");
        std::vector<CredentialInfo> emptyInfoList;
        callback_->OnCredentialInfo(ERR_ACCOUNT_ZIDL_ACCOUNT_SERVICE_ERROR, emptyInfoList);
    }
}

void GetCredInfoCallbackService::OnCredentialInfo(const std::vector<CredentialInfo> &infoList)
{
    isCalled_ = true;
    if (callback_ == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return;
    }
    callback_->OnCredentialInfo(result_, infoList);
}

void GetCredInfoCallbackService::SetResult(int32_t errCode)
{
    result_ = errCode;
}

GetSetPropCallbackService::GetSetPropCallbackService(const std::shared_ptr<GetSetPropCallback> &callback)
    : callback_(callback)
{}

GetSetPropCallbackService::~GetSetPropCallbackService()
{
    if (!isCalled_ && (callback_ != nullptr)) {
        ACCOUNT_LOGW("No valid result returned because system exception");
        Attributes emptyAttributes;
        callback_->OnResult(ERR_ACCOUNT_ZIDL_ACCOUNT_SERVICE_ERROR, emptyAttributes);
    }
}

void GetSetPropCallbackService::OnResult(int32_t result, const Attributes &extraInfo)
{
    isCalled_ = true;
    if (callback_ == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return;
    }
    callback_->OnResult(result, extraInfo);
}

GetEnrolledIdCallbackService::GetEnrolledIdCallbackService(const std::shared_ptr<GetEnrolledIdCallback> &callback)
    : callback_(callback)
{}

GetEnrolledIdCallbackService::~GetEnrolledIdCallbackService()
{
    if (!isCalled_ && (callback_ != nullptr)) {
        ACCOUNT_LOGW("No valid result returned because system exception");
        uint64_t enrolledId = 0;
        callback_->OnEnrolledId(ERR_ACCOUNT_ZIDL_ACCOUNT_SERVICE_ERROR, enrolledId);
    }
}

void GetEnrolledIdCallbackService::OnEnrolledId(int32_t result, uint64_t enrolledId)
{
    isCalled_ = true;
    if (callback_ == nullptr) {
        ACCOUNT_LOGE("Callback is nullptr");
        return;
    }
    callback_->OnEnrolledId(result, enrolledId);
}

PreRemoteAuthCallbackService::PreRemoteAuthCallbackService(
    const std::shared_ptr<PreRemoteAuthCallback> &callback) : callback_(callback)
{}

PreRemoteAuthCallbackService::~PreRemoteAuthCallbackService()
{
    if (!isCalled_ && (callback_ != nullptr)) {
        ACCOUNT_LOGW("No valid result returned because system exception");
        callback_->OnResult(ERR_ACCOUNT_ZIDL_ACCOUNT_SERVICE_ERROR);
    }
}

void PreRemoteAuthCallbackService::OnResult(int32_t result)
{
    isCalled_ = true;
    if (callback_ == nullptr) {
        ACCOUNT_LOGE("Callback is nullptr.");
        return;
    }
    callback_->OnResult(result);
}

DomainAuthCallbackAdapter::DomainAuthCallbackAdapter(
    const std::shared_ptr<IDMCallback> &callback) : callback_(callback)
{}

void DomainAuthCallbackAdapter::OnResult(const int32_t errCode, Parcel &parcel)
{
    if (callback_ == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return;
    }
    std::shared_ptr<DomainAuthResult> authResult(DomainAuthResult::Unmarshalling(parcel));
    if (authResult == nullptr) {
        ACCOUNT_LOGE("authResult is nullptr");
        return;
    }
    Attributes attr;
    attr.SetUint8ArrayValue(Attributes::AttributeKey::ATTR_SIGNATURE, (*authResult).token);
    attr.SetInt32Value(Attributes::AttributeKey::ATTR_REMAIN_TIMES, (*authResult).authStatusInfo.remainingTimes);
    attr.SetInt32Value(Attributes::AttributeKey::ATTR_FREEZING_TIME, (*authResult).authStatusInfo.freezingTime);
    callback_->OnResult(errCode, attr);
}

#ifdef HAS_PIN_AUTH_PART
DomainCredentialRecipient::DomainCredentialRecipient(int32_t userId, const std::shared_ptr<IDMCallback> &callback)
    : userId_(userId), idmCallback_(callback)
{}

DomainCredentialRecipient::~DomainCredentialRecipient()
{}

void DomainCredentialRecipient::OnSetData(int32_t authSubType, std::vector<uint8_t> data)
{
    auto callback = std::make_shared<DomainAuthCallbackAdapter>(idmCallback_);
    ErrCode errCode = DomainAccountClient::GetInstance().AuthUser(userId_, data, callback);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to auth user, errCode=%{public}d", errCode);
        Parcel emptyParcel;
        AccountSA::DomainAuthResult emptyResult;
        if (!emptyResult.Marshalling(emptyParcel)) {
            ACCOUNT_LOGE("authResult Marshalling failed");
            return;
        }
        callback->OnResult(errCode, emptyParcel);
    }
}

IAMInputer::IAMInputer(int32_t userId, const std::shared_ptr<IInputer> &inputer)
    : userId_(userId), innerInputer_(inputer)
{}

void IAMInputer::OnGetData(int32_t authSubType, std::vector<uint8_t> challenge,
    std::shared_ptr<IInputerData> inputerData)
{
    ACCOUNT_LOGI("AuthSubType: %{public}d", authSubType);
    if (authSubType == 0) {
        authSubType = AccountIAMClient::GetInstance().GetAuthSubType(userId_);
    }
    if (innerInputer_ == nullptr) {
        ACCOUNT_LOGE("innerInputer_ is nullptr");
        return;
    }
    innerInputer_->OnGetData(authSubType, challenge, inputerData);
}
#endif
}  // namespace AccountSA
}  // namespace OHOS
