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

#include "account_iam_callback_service.h"

#include "account_error_no.h"
#include "account_iam_client.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
IDMCallbackService::IDMCallbackService(std::shared_ptr<IDMCallback> callback) : callback_(callback)
{}

void IDMCallbackService::OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo)
{
    if (callback_ == nullptr) {
        ACCOUNT_LOGD("callback is nullptr");
        return;
    }
    callback_->OnAcquireInfo(module, acquireInfo, extraInfo);
}

void IDMCallbackService::OnResult(int32_t result, const Attributes &extraInfo)
{
    if (callback_ == nullptr) {
        ACCOUNT_LOGD("callback is nullptr");
        return;
    }
    callback_->OnResult(result, extraInfo);
}

GetCredInfoCallbackService::GetCredInfoCallbackService(std::shared_ptr<GetCredInfoCallback> callback)
    : callback_(callback)
{}

void GetCredInfoCallbackService::OnCredentialInfo(const std::vector<CredentialInfo> &infoList)
{
    if (callback_ == nullptr) {
        ACCOUNT_LOGD("callback is nullptr");
        return;
    }
    callback_->OnCredentialInfo(infoList);
}

GetSetPropCallbackService::GetSetPropCallbackService(std::shared_ptr<GetSetPropCallback> callback)
    : callback_(callback)
{}

void GetSetPropCallbackService::OnResult(int32_t result, const Attributes &extraInfo)
{
    if (callback_ == nullptr) {
        ACCOUNT_LOGD("callback is nullptr");
        return;
    }
    callback_->OnResult(result, extraInfo);
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
    IAMState state = AccountIAMClient::GetInstance().GetAccountState(userId_);
    if (authSubType == 0) {
        authSubType = AccountIAMClient::GetInstance().GetAuthSubType(userId_);
    }
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
