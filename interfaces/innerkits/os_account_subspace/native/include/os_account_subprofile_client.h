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

#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_OS_ACCOUNT_SUBSPACE_INCLUDE_OS_ACCOUNT_SUBPROFILE_CLIENT_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_OS_ACCOUNT_SUBSPACE_INCLUDE_OS_ACCOUNT_SUBPROFILE_CLIENT_H

#include <set>
#include "account_info.h"
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
#include "ios_account_sub_profile.h"
#include "nocopyable.h"
#endif // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
#include "account_error_no.h"
#include "distributed_account_subscribe_callback.h"

namespace OHOS {
namespace AccountSA {
class OsAccountSubProfileClient {
public:
    static OsAccountSubProfileClient &GetInstance();

    ErrCode CreateOsAccountSubProfile(int32_t osAccountId,
        OsAccountSubspaceResult &subspaceResult);
    ErrCode DeleteOsAccountSubProfile(int32_t osAccountId, int32_t subspaceId);
    ErrCode SwitchOsAccountSubProfile(int32_t osAccountId, int32_t subspaceId);

    ErrCode GetOsAccountForegroundSubProfileId(int32_t &subProfileId);
    ErrCode GetOsAccountForegroundSubProfileId(int32_t osAccountId, int32_t &subProfileId);
    ErrCode GetOsAccountSubProfileIds(std::vector<int32_t> &subProfileIds);
    ErrCode GetOsAccountSubProfileIds(int32_t osAccountId, std::vector<int32_t> &subProfileIds);
    ErrCode GetOsAccountLocalIdForSubProfile(int32_t subProfileId, int32_t &osAccountId);
    ErrCode GetOsAccountSubProfile(int32_t subProfileId,
        OsAccountSubspaceResult &subspaceResult, OhosAccountInfo &distributedInfo);
    ErrCode GetOsAccountSubProfile(int32_t osAccountId, int32_t subProfileId,
        OsAccountSubspaceResult &subspaceResult, OhosAccountInfo &distributedInfo);

    ErrCode SubscribeOsAccountSubProfileEvents(
        const std::set<DistributedAccountSubProfileEventType>& types,
        const std::shared_ptr<DistributedAccountSubscribeCallback>& callback);
    ErrCode UnsubscribeOsAccountSubProfileEvents(
        const std::shared_ptr<DistributedAccountSubscribeCallback>& callback);
    ErrCode GetOsAccountSubProfileId(
        int32_t osAccountLocalId, int32_t appIndex, int32_t &subProfileId);
    ErrCode GetOsAccountSubProfileId(uint32_t tokenId, int32_t &subProfileId);
    ErrCode GetOsAccountSubProfileIndex(
        int32_t osAccountLocalId, int32_t subProfileId, int32_t &index);

private:
    OsAccountSubProfileClient();
    ~OsAccountSubProfileClient() = default;
    DISALLOW_COPY_AND_MOVE(OsAccountSubProfileClient);

#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
    class OsAccountSubProfileDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        OsAccountSubProfileDeathRecipient() = default;
        ~OsAccountSubProfileDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;
        DISALLOW_COPY_AND_MOVE(OsAccountSubProfileDeathRecipient);
    };

    sptr<IOsAccountSubProfile> GetOsAccountSubProfileProxy();
    void ResetProxy(const wptr<IRemoteObject> &remote);

    std::mutex mutex_;
    sptr<IOsAccountSubProfile> proxy_ = nullptr;
    sptr<OsAccountSubProfileDeathRecipient> deathRecipient_ = nullptr;
#endif // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_OS_ACCOUNT_SUBSPACE_INCLUDE_OS_ACCOUNT_SUBPROFILE_CLIENT_H