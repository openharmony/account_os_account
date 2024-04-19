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

#ifndef BASE_ACCOUNT_IACCOUNT_H
#define BASE_ACCOUNT_IACCOUNT_H

#include <cstdint>
#include <string>
#include <iremote_broker.h>
#include "accountmgr_service_ipc_interface_code.h"
#include "account_info.h"
#include "device_account_info.h"
#include "distributed_account_subscribe_callback.h"

namespace OHOS {
namespace AccountSA {
const char ACCOUNT_SERVICE_NAME[] = "AccountService";

class IAccount : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.accountfwk.IAccount");

    virtual bool UpdateOhosAccountInfo(
        const std::string &accountName, const std::string &uid, const std::string &eventStr) = 0;
    virtual std::int32_t SetOhosAccountInfo(const OhosAccountInfo &ohosAccountInfo,
        const std::string &eventStr) = 0;
    virtual std::int32_t SetOhosAccountInfoByUserId(
        const int32_t userId, const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr) = 0;
    virtual std::pair<bool, OhosAccountInfo> QueryOhosAccountInfo(void) = 0;
    virtual std::pair<bool, OhosAccountInfo> QueryOhosAccountInfoByUserId(std::int32_t userId) = 0;
    virtual ErrCode GetOhosAccountInfo(OhosAccountInfo &accountInfo) = 0;
    virtual ErrCode GetOhosAccountInfoByUserId(int32_t userId, OhosAccountInfo &info) = 0;
    virtual std::int32_t QueryDeviceAccountId(std::int32_t &accountId) = 0;
    virtual ErrCode SubscribeDistributedAccountEvent(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type,
        const sptr<IRemoteObject> &eventListener) = 0;
    virtual ErrCode UnsubscribeDistributedAccountEvent(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type,
        const sptr<IRemoteObject> &eventListener) = 0;
    virtual sptr<IRemoteObject> GetAppAccountService() = 0;
    virtual sptr<IRemoteObject> GetOsAccountService() = 0;
    virtual sptr<IRemoteObject> GetAccountIAMService() = 0;
    virtual sptr<IRemoteObject> GetDomainAccountService() = 0;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // BASE_ACCOUNT_IACCOUNT_H
