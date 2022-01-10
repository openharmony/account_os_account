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
#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_STANDARD_INTERFACE_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_STANDARD_INTERFACE_H
#include <vector>
#include "account_error_no.h"
#include "os_account_info.h"
#include "os_account_stop_user_callback.h"
namespace OHOS {
namespace AccountSA {
class OsAccountStandardInterface {
public:
    static ErrCode SendToAMSAccountStart(OsAccountInfo &osAccountInfo);
    static ErrCode SendToAMSAccountStop(
        OsAccountInfo &osAccountInfo, sptr<OsAccountStopUserCallback> &osAccountStopUserCallback);
    static ErrCode SendToBMSAccountCreate(OsAccountInfo &osAccountInfo);
    static ErrCode SendToBMSAccountDelete(OsAccountInfo &osAccountInfo);
    static ErrCode SendToCESAccountCreate(OsAccountInfo &osAccountInfo);
    static ErrCode SendToCESAccountDelete(OsAccountInfo &osAccountInfo);
    static ErrCode SendToCESAccountSwithced(OsAccountInfo &osAccountInfo);
};
}  // namespace AccountSA
}  // namespace OHOS
#endif /* OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OSACCOUNT_OS_ACCOUNT_STANDARD_INTERFACE_H */
