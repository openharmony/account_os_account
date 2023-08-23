/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "domain_has_domain_info_callback.h"
#include "account_log_wrapper.h"
#include "domain_account_common.h"
#include "parcel.h"

namespace OHOS {
namespace AccountSA {
DomainHasDomainInfoCallback::DomainHasDomainInfoCallback(
    const sptr<IDomainAccountCallback> &callback, const std::string &domain, const std::string &accountName)
    : innerCallback_(callback), domain_(domain), accountName_(accountName)
{}

void DomainHasDomainInfoCallback::OnResult(const int32_t errCode, Parcel &parcel)
{
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGE("innerPlugin_ is nullptr");
        return;
    }
    Parcel parcelResult;
    if (errCode != ERR_OK) {
        parcelResult.WriteBool(false);
        return innerCallback_->OnResult(errCode, parcelResult);
    }
    std::shared_ptr<AAFwk::WantParams> parameters(AAFwk::WantParams::Unmarshalling(parcel));
    if (parameters == nullptr) {
        ACCOUNT_LOGE("parameters unmarshalling error");
        parcelResult.WriteBool(false);
        return innerCallback_->OnResult(ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR, parcelResult);
    }
    DomainAccountInfo info;
    info.accountName_ = parameters->GetStringParam("accountName");
    info.domain_ = parameters->GetStringParam("domain");
    info.accountId_ = parameters->GetStringParam("accountId");
    if ((info.domain_ != domain_) || (info.accountName_ != accountName_)) {
        parcelResult.WriteBool(false);
        return innerCallback_->OnResult(errCode, parcelResult);
    }
    parcelResult.WriteBool(true);
    return innerCallback_->OnResult(errCode, parcelResult);
}
}  // namespace AccountSA
}  // namespace OHOS