/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "domain_account_callback_service.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
DomainAccountCallbackService::DomainAccountCallbackService(
    const std::shared_ptr<DomainAccountCallback> &callback)
    : innerCallback_(callback)
{}

DomainAccountCallbackService::DomainAccountCallbackService(const DomainAccountCallbackFunc &callback)
    : callback_(callback)
{}

DomainAccountCallbackService::~DomainAccountCallbackService()
{}

ErrCode DomainAccountCallbackService::OnResult(int32_t errCode, const DomainAccountParcel &domainAccountParcel)
{
    ACCOUNT_LOGI("enter");
    Parcel parcel;
    domainAccountParcel.GetParcelData(parcel);
    if (innerCallback_ != nullptr) {
        innerCallback_->OnResult(errCode, parcel);
    }
    if (callback_ != nullptr) {
        callback_(errCode, parcel);
    }
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS