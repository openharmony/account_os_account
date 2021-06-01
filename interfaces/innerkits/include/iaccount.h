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
    enum {
        UPDATE_OHOS_ACCOUNT_INFO = 1,
        QUERY_OHOS_ACCOUNT_INFO = 2,
        QUERY_OHOS_ACCOUNT_QUIT_TIPS = 3,
        QUERY_DEVICE_ACCOUNT_ID = 104,
        QUERY_DEVICE_ACCOUNT_ID_FROM_UID = 105,
    };

    virtual bool UpdateOhosAccountInfo(const std::string& accountName, const std::string& uid,
        const std::string& eventStr) = 0;
    virtual std::pair<bool, OhosAccountInfo> QueryOhosAccountInfo(void) = 0;
    virtual std::int32_t QueryDeviceAccountId(std::int32_t& accountId) = 0;
    virtual std::int32_t QueryDeviceAccountIdFromUid(std::int32_t uid) = 0;
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.AccountSA.IAccount");
};
} // namespace AccountSA
} // namespace OHOS

#endif // BASE_ACCOUNT_IACCOUNT_H
