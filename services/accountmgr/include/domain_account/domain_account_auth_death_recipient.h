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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_DOMAIN_ACCOUNT_DOMAIN_ACCOUNT_AUTH_DEATH_RECIPIENT_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_DOMAIN_ACCOUNT_DOMAIN_ACCOUNT_AUTH_DEATH_RECIPIENT_H

#include "iremote_object.h"

namespace OHOS {
namespace AccountSA {
class DomainAccountAuthDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    DomainAccountAuthDeathRecipient(int32_t localId) : localId_(localId) {};
    ~DomainAccountAuthDeathRecipient() override = default;
    void SetContextId(uint64_t contextId);
    void OnRemoteDied(const wptr<IRemoteObject> &remote) override;

private:
    uint64_t contextId_ = 0;
    std::mutex mutex_;
    int32_t localId_ = -1;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_DOMAIN_ACCOUNT_DOMAIN_ACCOUNT_AUTH_DEATH_RECIPIENT_H
