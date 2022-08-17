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

GetDataCallbackService::GetDataCallbackService(const std::shared_ptr<GetDataCallback> &callback) : callback_(callback)
{}

void GetDataCallbackService::OnGetData(int32_t authSubType, const sptr<ISetDataCallback> &inputerSetData)
{
    if (callback_ == nullptr) {
        ACCOUNT_LOGD("callback is nullptr");
        return;
    }
    callback_->OnGetData(authSubType, inputerSetData);
}
}  // namespace AccountSA
}  // namespace OHOS
