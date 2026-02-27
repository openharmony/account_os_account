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

#ifndef OS_ACCOUNT_SET_OSACCOUNT_ID_H
#define OS_ACCOUNT_SET_OSACCOUNT_ID_H

/**
 * @addtogroup OsAccount
 * @{
 *
 * @brief Provide the definition of the C interface for the native OsAccount.
 * @since 24
 */
/**
 * @file os_account_set_osaccount_id.h
 *
 * @brief Declares the APIs for accessing and managing the OS account information.
 * @library libset_os_account_id.so
 * @syscap SystemCapability.Account.OsAccount
 * @since 24
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Query the osAccount id from uid.
 *
 * @param uid Indicates the process UID.
 * @return {@link osaccountid} Indicates successful, return osaccountid;<br>
 *         {@link -1} Indicates the internal error.<br>
 * @syscap SystemCapability.Account.OsAccount
 * @since 24
 */
int32_t GetOsAccountIdForUid(const int32_t uid);

/**
 * @brief Set the osAccount id by ioctl.
 *
 * @param osAccountId Indicates the osAccount id associated with the specified UID.
 * @return {@link 0} Indicates successful;<br>
 *         {@link -1} Indicates the internal error.<br>
 * @syscap SystemCapability.Account.OsAccount
 * @since 24
 */
int32_t SetOsAccountId(const int32_t osAccountId);

/**
 * @brief Get the osAccount id from ioctl.
 *
 * @param osAccountId Indicates the osAccount id associated with the specified UID.
 * @return {@link osaccountid} Indicates successful, return osaccountid;<br>
 *         {@link -1} Indicates the internal error.<br>
 * @syscap SystemCapability.Account.OsAccount
 * @since 24
 */
int32_t GetOsAccountId();

#ifdef __cplusplus
};
#endif

#endif // OS_ACCOUNT_SET_OSACCOUNT_ID_H