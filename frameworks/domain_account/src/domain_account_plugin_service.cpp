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

#include "domain_account_plugin_service.h"

#include "account_log_wrapper.h"
#include "domain_auth_callback_client.h"

namespace OHOS {
namespace AccountSA {
DomainAccountPluginService::DomainAccountPluginService(const std::shared_ptr<DomainAccountPlugin> &plugin)
    : innerPlugin_(plugin)
{}

DomainAccountPluginService::~DomainAccountPluginService()
{}

ErrCode DomainAccountPluginService::Auth(const DomainAccountInfo &info, const std::vector<uint8_t> &password,
    const sptr<IDomainAuthCallback> &callback)
{
    if (innerPlugin_ == nullptr) {
        ACCOUNT_LOGE("innerPlugin_ is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    auto callbackClient = std::make_shared<DomainAuthCallbackClient>(callback);
    if (callbackClient == nullptr) {
        ACCOUNT_LOGE("failed to create DomainAuthCallbackClient");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    innerPlugin_->Auth(info, password, callbackClient);
    return ERR_OK;
}

ErrCode DomainAccountPluginService::GetAuthProperty(const DomainAccountInfo &info, DomainAuthProperty &property)
{
    if (innerPlugin_ == nullptr) {
        ACCOUNT_LOGE("innerPlugin_ is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    return innerPlugin_->GetAuthProperty(info, property);
}
}  // namespace AccountSA
}  // namespace OHOS