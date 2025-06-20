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

#include "os_account_constraint_subscribe_death_recipient.h"

#include "account_log_wrapper.h"
#include "os_account_constraint_subscribe_manager.h"

namespace OHOS {
namespace AccountSA {
void OsAccountConstraintSubscribeDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    sptr<IRemoteObject> object = remote.promote();
    if (object == nullptr) {
        ACCOUNT_LOGE("Object is nullptr");
        return;
    }

    OsAccountConstraintSubscribeManager::GetInstance().UnsubscribeOsAccountConstraints(object);

    ACCOUNT_LOGI("End");
}
}  // namespace AccountSA
}  // namespace OHOS
