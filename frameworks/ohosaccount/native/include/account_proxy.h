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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_PROXY_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_PROXY_H

#include <iremote_proxy.h>
#include "account_info.h"
#include "iaccount.h"

namespace OHOS {
namespace AccountSA {
class AccountProxy : public IRemoteProxy<IAccount> {
public:
    explicit AccountProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<IAccount>(impl)
    {}
    ~AccountProxy();

    ErrCode UpdateOhosAccountInfo(
        const std::string &accountName, const std::string &uid, const std::string &eventStr) override;
    ErrCode SetOsAccountDistributedInfo(
        const int32_t localId, const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr) override;
    ErrCode SetOhosAccountInfo(const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr) override;
    ErrCode QueryOhosAccountInfo(OhosAccountInfo &accountInfo) override;
    ErrCode QueryDistributedVirtualDeviceId(std::string &dvid) override;
    ErrCode QueryDistributedVirtualDeviceId(const std::string &bundleName, int32_t localId, std::string &dvid) override;
    ErrCode GetOhosAccountInfo(OhosAccountInfo &ohosAccountInfo) override;
    ErrCode GetOsAccountDistributedInfo(std::int32_t localId, OhosAccountInfo &ohosAccountInfo) override;
    ErrCode QueryOsAccountDistributedInfo(std::int32_t localId, OhosAccountInfo &info) override;
    std::int32_t QueryDeviceAccountId(std::int32_t &accountId) override;
    ErrCode SubscribeDistributedAccountEvent(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type,
        const sptr<IRemoteObject> &eventListener) override;
    ErrCode UnsubscribeDistributedAccountEvent(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type,
        const sptr<IRemoteObject> &eventListener) override;
    sptr<IRemoteObject> GetAppAccountService() override;
    sptr<IRemoteObject> GetOsAccountService() override;
    sptr<IRemoteObject> GetAccountIAMService() override;
    sptr<IRemoteObject> GetDomainAccountService() override;

private:
    ErrCode SendRequest(AccountMgrInterfaceCode code, MessageParcel &data, MessageParcel &reply);
    std::int32_t DeviceAccountRequest(std::uint32_t code, std::int32_t accountId);
    static inline BrokerDelegator<AccountProxy> delegator_;
    uintptr_t destroyedMagic_ = 0;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_PROXY_H
