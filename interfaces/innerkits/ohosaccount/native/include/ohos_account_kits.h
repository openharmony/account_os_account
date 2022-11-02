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

#ifndef BASE_ACCOUNT_OHOS_ACCOUNT_KITS_H
#define BASE_ACCOUNT_OHOS_ACCOUNT_KITS_H

#include "account_info.h"
#include "nocopyable.h"
#include "iaccount.h"

namespace OHOS {
namespace AccountSA {
/**
 * Interfaces for ohos account subsystem.
 */
class OhosAccountKits {
public:
    virtual ~OhosAccountKits() = default;
    DISALLOW_COPY_AND_MOVE(OhosAccountKits);

    /**
     * Get instance of ohos account manager.
     *
     * @return Instance of ohos account manager.
     */
    static OhosAccountKits& GetInstance();

    /**
     * Query OHOS Account Info.
     *
     * @param VOID.
     * @return Return a pair of operation result and ohos account info.
     */
    virtual std::pair<bool, OhosAccountInfo> QueryOhosAccountInfo() = 0;

    /**
     * Query OHOS Account Info.
     *
     * @param OhosAccountInfo. ohos account info
     * @return Return error code.
     */
    virtual ErrCode GetOhosAccountInfo(OhosAccountInfo &accountInfo) = 0;

    /**
     * Get OHOS account info by user id.
     *
     * @param OhosAccountInfo. ohos account info
     * @return Return error code.
     */
    virtual ErrCode GetOhosAccountInfoByUserId(int32_t userId, OhosAccountInfo &accountInfo) = 0;

    /**
     * Query OHOS Account Info By user ID.
     *
     * @param userId. target local user id
     * @return Return a pair of operation result and ohos account info.
     */
    virtual std::pair<bool, OhosAccountInfo> QueryOhosAccountInfoByUserId(std::int32_t userId) = 0;

    /**
     * Update OHOS Account Info.
     *
     * @param accountName Indicates the name of the OS account used for a distributed system.
     * @param uid Uniquely identifies the OS account used for a distributed system.
     * @param eventStr Indicates the event of the OS account used for a distributed system.
     * @return Returns {@code true} if the distributed information of the account is updated;
     *     returns {@code false} otherwise.
     */
    virtual bool UpdateOhosAccountInfo(const std::string& accountName, const std::string& uid,
        const std::string& eventStr) = 0;

    /**
     * Update OHOS Account Info.
     *
     * @param ohosAccountInfo Indicates the information of the disctributed account.
     * Update OHOS Account Info.
     * @param eventStr Indicates the event of the OS account used for a distributed system.
     * @return Returns {@code true} if the distributed information of the account is updated;
     *     returns {@code false} otherwise.
     */
    virtual std::int32_t SetOhosAccountInfo(const OhosAccountInfo &ohosAccountInfo,
        const std::string &eventStr) = 0;

    /**
     * Query Device Account Id.
     *
     * @param device account id.
     * @return if succeed, return ERR_OK and device account Id.
     */
    virtual ErrCode QueryDeviceAccountId(std::int32_t& accountId) = 0;

    /**
     * Transform uid to device account id.
     *
     * @param process calling uid.
     * @return transformed device account Id
     */
    virtual std::int32_t GetDeviceAccountIdByUID(std::int32_t& uid) = 0;
protected:
    OhosAccountKits() = default;
};
} // namespace AccountSA
} // namespace OHOS

#endif // BASE_ACCOUNT_OHOS_ACCOUNT_KITS_H
