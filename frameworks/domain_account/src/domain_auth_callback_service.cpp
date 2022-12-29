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

#include "domain_auth_callback_service.h"

#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
DomainAuthCallbackService::DomainAuthCallbackService(const std::shared_ptr<DomainAuthCallback> &callback)
    : innerCallback_(callback)
{}

DomainAuthCallbackService::~DomainAuthCallbackService()
{}

void DomainAuthCallbackService::OnResult(int32_t resultCode, const DomainAuthResult &result)
{
    if (innerCallback_ == nullptr) {
        ACCOUNT_LOGE("innerPlugin_ is nullptr");
        return;
    }
    return innerCallback_->OnResult(resultCode, result);
}
}  // namespace AccountSA
}  // namespace OHOS