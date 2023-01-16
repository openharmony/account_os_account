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
    ~AccountProxy()
    {}

    bool UpdateOhosAccountInfo(
        const std::string &accountName, const std::string &uid, const std::string &eventStr) override;
    std::int32_t SetOhosAccountInfo(const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr) override;
    std::pair<bool, OhosAccountInfo> QueryOhosAccountInfo(void) override;
    ErrCode GetOhosAccountInfo(OhosAccountInfo &accountInfo) override;
    ErrCode GetOhosAccountInfoByUserId(std::int32_t userId, OhosAccountInfo &ohosAccountInfo) override;
    std::pair<bool, OhosAccountInfo> QueryOhosAccountInfoByUserId(std::int32_t userId) override;
    std::int32_t QueryDeviceAccountId(std::int32_t &accountId) override;
    sptr<IRemoteObject> GetAppAccountService() override;
    sptr<IRemoteObject> GetOsAccountService() override;
    sptr<IRemoteObject> GetAccountIAMService() override;
    sptr<IRemoteObject> GetDomainAccountService() override;

private:
    std::int32_t DeviceAccountRequest(std::uint32_t code, std::int32_t accountId);
    static inline BrokerDelegator<AccountProxy> delegator_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_PROXY_H
