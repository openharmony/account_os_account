/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef BASE_ACCOUNT_OHOS_ACCOUNT_KITS_IMPL_H
#define BASE_ACCOUNT_OHOS_ACCOUNT_KITS_IMPL_H

#include <mutex>
#include "ipc_skeleton.h"
#include "ohos_account_kits.h"
#include "singleton.h"

namespace OHOS {
namespace AccountSA {
class OhosAccountKitsImpl final : public OhosAccountKits, public DelayedRefSingleton<OhosAccountKitsImpl> {
    DECLARE_DELAYED_REF_SINGLETON(OhosAccountKitsImpl);

public:
    DISALLOW_COPY_AND_MOVE(OhosAccountKitsImpl);
    bool UpdateOhosAccountInfo(const std::string& accountName, const std::string& uid,
        const std::string& eventStr) final;
    std::int32_t SetOhosAccountInfo(const OhosAccountInfo &ohosAccountInfo,
        const std::string &eventStr) final;
    std::pair<bool, OhosAccountInfo> QueryOhosAccountInfo() final;
    ErrCode GetOhosAccountInfo(OhosAccountInfo &accountInfo) final;
    ErrCode GetOhosAccountInfoByUserId(int32_t userId, OhosAccountInfo &accountInfo) final;
    std::pair<bool, OhosAccountInfo> QueryOhosAccountInfoByUserId(std::int32_t userId) final;
    ErrCode QueryDeviceAccountId(std::int32_t& accountId) final;
    std::int32_t GetDeviceAccountIdByUID(std::int32_t& uid) final;
    sptr<IRemoteObject> GetDomainAccountService();

private:
    // For death event procession
    class DeathRecipient final : public IRemoteObject::DeathRecipient {
    public:
        DeathRecipient() = default;
        ~DeathRecipient() final = default;
        DISALLOW_COPY_AND_MOVE(DeathRecipient);

        void OnRemoteDied(const wptr<IRemoteObject>& remote) final;
    };

    void ResetService(const wptr<IRemoteObject>& remote);
    sptr<IAccount> GetService();

    sptr<IRemoteObject::DeathRecipient> deathRecipient_{};
    std::mutex accountProxyLock_;
    sptr<IAccount> accountProxy_{};
};
} // namespace AccountSA
} // namespace OHOS

#endif // BASE_ACCOUNT_OHOS_ACCOUNT_KITS_IMPL_H
