/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "domain_account_auth_death_recipient.h"

#include <cinttypes>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "domain_hisysevent_utils.h"
#include "inner_domain_account_manager.h"

namespace OHOS {
namespace AccountSA {
void DomainAccountAuthDeathRecipient::SetContextId(uint64_t contextId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    contextId_ = contextId;
}

void DomainAccountAuthDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if ((remote == nullptr) || (remote.promote() == nullptr)) {
        ACCOUNT_LOGE("remote object is nullptr");
        return;
    }
    if (contextId_ != 0) {
        ACCOUNT_LOGE("Auth client exits abnormally, contextId = %{public}" PRIu64, contextId_);
        std::string errMsg = "Auth client exits abnormally, contextId = " + std::to_string(contextId_);
        REPORT_DOMAIN_ACCOUNT_FAIL(ERR_ACCOUNT_COMMON_REMOTE_DIED, errMsg, Constants::DOMAIN_OPT_AUTH, localId_);
        InnerDomainAccountManager::GetInstance().CancelAuth(contextId_);
        contextId_ = 0;
        return;
    }
}
}  // namespace AccountSA
}  // namespace OHOS

