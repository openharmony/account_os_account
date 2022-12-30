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

#include "domain_auth_callback_client.h"

#include "account_error_no.h"

namespace OHOS {
namespace AccountSA {
DomainAuthCallbackClient::DomainAuthCallbackClient(const sptr<IDomainAuthCallback> &proxy) : proxy_(proxy)
{}

DomainAuthCallbackClient::~DomainAuthCallbackClient()
{}

void DomainAuthCallbackClient::OnResult(int32_t resultCode, const DomainAuthResult &result)
{
    if (proxy_ != nullptr) {
        proxy_->OnResult(resultCode, result);
    }
}
}  // namespace AccountSA
}  // namespace OHOS
