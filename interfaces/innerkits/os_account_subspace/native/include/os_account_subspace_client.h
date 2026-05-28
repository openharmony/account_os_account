/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_OS_ACCOUNT_SUBSPACE_INCLUDE_OS_ACCOUNT_SUBSPACE_CLIENT_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_OS_ACCOUNT_SUBSPACE_INCLUDE_OS_ACCOUNT_SUBSPACE_CLIENT_H

#include <set>
#include "account_info.h"
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
#include "ios_account_subspace.h"
#include "nocopyable.h"
#endif // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
#include "account_error_no.h"

namespace OHOS {
namespace AccountSA {
class OsAccountSubspaceClient {
public:
    static OsAccountSubspaceClient &GetInstance();

    ErrCode CreateOsAccountSubspace(int32_t osAccountId,
        OsAccountSubspaceResult &subspaceResult);
    ErrCode DeleteOsAccountSubspace(int32_t osAccountId, int32_t subspaceId);
    ErrCode SwitchOsAccountSubspace(int32_t osAccountId, int32_t subspaceId);

private:
    OsAccountSubspaceClient();
    ~OsAccountSubspaceClient() = default;
    DISALLOW_COPY_AND_MOVE(OsAccountSubspaceClient);

#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
    class OsAccountSubspaceDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        OsAccountSubspaceDeathRecipient() = default;
        ~OsAccountSubspaceDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;
        DISALLOW_COPY_AND_MOVE(OsAccountSubspaceDeathRecipient);
    };

    sptr<IOsAccountSubspace> GetOsAccountSubspaceProxy();
    void ResetProxy(const wptr<IRemoteObject> &remote);

    std::mutex mutex_;
    sptr<IOsAccountSubspace> proxy_ = nullptr;
    sptr<OsAccountSubspaceDeathRecipient> deathRecipient_ = nullptr;
#endif // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_OS_ACCOUNT_SUBSPACE_INCLUDE_OS_ACCOUNT_SUBSPACE_CLIENT_H