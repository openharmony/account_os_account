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

#include "domain_account_callback_client.h"

#include "account_error_no.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
DomainAccountCallbackClient::DomainAccountCallbackClient(const sptr<IDomainAccountCallback> &proxy)
    : proxy_(proxy)
{}

DomainAccountCallbackClient::~DomainAccountCallbackClient()
{}

void DomainAccountCallbackClient::OnResult(const int32_t errCode, Parcel &parcel)
{
    if (proxy_ != nullptr) {
        proxy_->OnResult(errCode, parcel);
    }
}
}  // namespace AccountSA
}  // namespace OHOS
