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
#include "distributed_account_event_service.h"
#include "iaccount.h"
#include "ipc_skeleton.h"
#include "ohos_account_kits.h"

namespace OHOS {
namespace AccountSA {
using DomainAccountSubscribeSACallbackFunc = std::function<void(int32_t, const std::string)>;
class OhosAccountKitsImpl final : public OhosAccountKits {
public:
    DISALLOW_COPY_AND_MOVE(OhosAccountKitsImpl);
    static OhosAccountKitsImpl &GetInstance();
    ErrCode UpdateOhosAccountInfo(const std::string& accountName, const std::string& uid,
        const std::string& eventStr) final;
    ErrCode SetOhosAccountInfo(const OhosAccountInfo &ohosAccountInfo,
        const std::string &eventStr) final;
    ErrCode SetOsAccountDistributedInfo(
        const int32_t localId, const OhosAccountInfo& ohosAccountInfo, const std::string& eventStr) final;
    std::pair<bool, OhosAccountInfo> QueryOhosAccountInfo() final;
    ErrCode QueryOhosAccountInfo(OhosAccountInfo &accountInfo);
    ErrCode QueryDistributedVirtualDeviceId(std::string &dvid);
    ErrCode QueryDistributedVirtualDeviceId(const std::string &bundleName, int32_t localId, std::string &dvid);
    ErrCode GetOhosAccountInfo(OhosAccountInfo &accountInfo) final;
    ErrCode GetOsAccountDistributedInfo(int32_t localId, OhosAccountInfo &accountInfo) final;
    std::pair<bool, OhosAccountInfo> QueryOsAccountDistributedInfo(std::int32_t localId) final;
    ErrCode QueryOsAccountDistributedInfo(std::int32_t localId, OhosAccountInfo &accountInfo);
    ErrCode QueryDeviceAccountId(std::int32_t& accountId) final;
    std::int32_t GetDeviceAccountIdByUID(std::int32_t& uid) final;
    ErrCode SubscribeDistributedAccountEvent(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type,
        const std::shared_ptr<DistributedAccountSubscribeCallback> &callback) final;
    ErrCode UnsubscribeDistributedAccountEvent(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type,
        const std::shared_ptr<DistributedAccountSubscribeCallback> &callback) final;
    void RestoreSubscribe();
    ErrCode SubscribeSystemAbility(const DomainAccountSubscribeSACallbackFunc& callbackFunc);
    sptr<IRemoteObject> GetOsAccountService();
    sptr<IRemoteObject> GetDomainAccountService();
    sptr<IRemoteObject> GetAppAccountService();
    sptr<IRemoteObject> GetAccountIAMService();

private:
    OhosAccountKitsImpl() = default;
    ~OhosAccountKitsImpl() = default;
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
    ErrCode CreateDistributedAccountEventService(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type,
        const std::shared_ptr<DistributedAccountSubscribeCallback> &callback,
        sptr<IRemoteObject> &DistributedAccountEventService);

    bool isSubscribeSA_ = false;
    std::mutex eventListenersMutex_;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_{};
    std::mutex accountProxyLock_;
    sptr<IAccount> accountProxy_{};
};
} // namespace AccountSA
} // namespace OHOS

#endif // BASE_ACCOUNT_OHOS_ACCOUNT_KITS_IMPL_H
