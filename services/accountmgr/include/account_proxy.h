/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef ACCOUNT_PROXY_H
#define ACCOUNT_PROXY_H

#include "iaccount.h"
#include "account_info.h"
#include <iremote_proxy.h>

namespace OHOS {
namespace AccountSA {
class AccountProxy : public IRemoteProxy<IAccount> {
public:
    explicit AccountProxy(const sptr<IRemoteObject>& impl)
        : IRemoteProxy<IAccount>(impl) {
    }
    ~AccountProxy() { }
    bool UpdateOhosAccountInfo(const std::string& accountName, const std::string& uid,
        const std::string& eventStr) override;
    std::pair<bool, OhosAccountInfo> QueryOhosAccountInfo(void) override;
    std::int32_t QueryDeviceAccountId(std::int32_t& accountId) override;
    std::int32_t QueryDeviceAccountIdFromUid(std::int32_t uid) override;

private:
    std::int32_t DeviceAccountRequest(std::uint32_t code, std::int32_t accountId);
    static inline BrokerDelegator<AccountProxy> delegator_;
};
} // namespace AccountSA
} // namespace OHOS

#endif // ACCOUNT_PROXY_H
