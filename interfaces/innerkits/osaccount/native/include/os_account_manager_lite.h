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

#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_OS_ACCOUNT_MANAGER_LITE_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_OS_ACCOUNT_MANAGER_LITE_H

#include <cstdint>

#include "account_error_no.h"

namespace OHOS {
namespace AccountSA {
class OsAccountManagerLite final {
public:
    static ErrCode GetForegroundOsAccountLocalId(int32_t &localId);
    static ErrCode GetOsAccountSubProfileId(
        int32_t osAccountLocalId, int32_t appIndex, int32_t &subProfileId);
    static ErrCode GetOsAccountSubProfileId(uint32_t tokenId, int32_t &subProfileId);
    static ErrCode GetOsAccountSubProfileIndex(
        int32_t osAccountId, int32_t subProfileId, int32_t &index);
    static ErrCode GetOsAccountForegroundSubProfileId(
        int32_t osAccountId, int32_t &subProfileId);
    static ErrCode GetOsAccountLocalIdForSubProfile(
        int32_t subProfileId, int32_t &osAccountId);
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_OS_ACCOUNT_MANAGER_LITE_H
