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

#include <string>
#include <stdint.h>
#include <iremote_broker.h>
#include "account_info.h"
#include "device_account_info.h"

namespace OHOS {
namespace AccountSA {
const std::string ACCOUNT_SERVICE_NAME = "AccountService";

class IAccount : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.accountfwk.IAccount");
    enum {
        UPDATE_OHOS_ACCOUNT_INFO = 1,
        QUERY_OHOS_ACCOUNT_INFO = 2,
        QUERY_OHOS_ACCOUNT_QUIT_TIPS = 3,
        QUERY_OHOS_ACCOUNT_INFO_BY_USER_ID = 4,
        SET_OHOS_ACCOUNT_INFO = 5,
        GET_OHOS_ACCOUNT_INFO = 6,
        GET_OHOS_ACCOUNT_INFO_BY_USER_ID = 7,
        QUERY_DEVICE_ACCOUNT_ID = 104,
        GET_APP_ACCOUNT_SERVICE = 105,
        GET_OS_ACCOUNT_SERVICE = 106,
        GET_ACCOUNT_IAM_SERVICE = 107,
        GET_DOMAIN_ACCOUNT_SERVICE = 108,
    };

    virtual bool UpdateOhosAccountInfo(
        const std::string &accountName, const std::string &uid, const std::string &eventStr) = 0;
    virtual std::int32_t SetOhosAccountInfo(const OhosAccountInfo &ohosAccountInfo,
        const std::string &eventStr) = 0;
    virtual std::pair<bool, OhosAccountInfo> QueryOhosAccountInfo(void) = 0;
    virtual std::pair<bool, OhosAccountInfo> QueryOhosAccountInfoByUserId(std::int32_t userId) = 0;
    virtual ErrCode GetOhosAccountInfo(OhosAccountInfo &accountInfo) = 0;
    virtual ErrCode GetOhosAccountInfoByUserId(int32_t userId, OhosAccountInfo &info) = 0;
    virtual std::int32_t QueryDeviceAccountId(std::int32_t &accountId) = 0;
    virtual sptr<IRemoteObject> GetAppAccountService() = 0;
    virtual sptr<IRemoteObject> GetOsAccountService() = 0;
    virtual sptr<IRemoteObject> GetAccountIAMService() = 0;
    virtual sptr<IRemoteObject> GetDomainAccountService() = 0;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // BASE_ACCOUNT_IACCOUNT_H
