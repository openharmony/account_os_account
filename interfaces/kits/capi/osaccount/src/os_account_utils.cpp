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
#include "os_account_utils.h"
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "account_log_wrapper.h"

using namespace OHOS;
using namespace OHOS::AccountSA;

#define HM_ACCESS_TOKEN_ID_IOCTL_BASE 'A'
enum {
    HM_SET_USERID = 12,
    HM_GET_USERID = 13,
};

#define ACCESS_TOKENID_SET_USERID _IOW(HM_ACCESS_TOKEN_ID_IOCTL_BASE, HM_SET_USERID, uint32_t)
#define ACCESS_TOKENID_GET_USERID _IOR(HM_ACCESS_TOKEN_ID_IOCTL_BASE, HM_GET_USERID, uint32_t)

constexpr std::int32_t UID_TRANSFORM_DIVISOR = 200000; // local account id = uid / UID_TRANSFORM_DIVISOR
constexpr const char* HDAC_DEV = "/dev/access_token_id";

int32_t GetOsAccountIdForUid(const int32_t uid)
{
    if (uid < 0) {
        return -1;
    }
    return uid / UID_TRANSFORM_DIVISOR;
}

int32_t SetOsAccountId(const int32_t osAccountId)
{
    if (osAccountId < 0) {
        return -1;
    }
    int32_t fdIoctl = open(HDAC_DEV, O_WRONLY);
    if (fdIoctl < 0) {
        return -1;
    }
    fdsan_exchange_owner_tag(fdIoctl, 0, LOG_DOMAIN);
    int32_t rc = ioctl(fdIoctl, ACCESS_TOKENID_SET_USERID, &osAccountId);
    if (rc < 0) {
        fdsan_close_with_tag(fdIoctl, LOG_DOMAIN);
        return -1;
    }
    fdsan_close_with_tag(fdIoctl, LOG_DOMAIN);
    return 0;
}

int32_t GetOsAccountId()
{
    int32_t osAccountId = -1;
    int32_t fdIoctl = open(HDAC_DEV, O_WRONLY);
    if (fdIoctl < 0) {
        return -1;
    }
    fdsan_exchange_owner_tag(fdIoctl, 0, LOG_DOMAIN);
    int32_t rc = ioctl(fdIoctl, ACCESS_TOKENID_GET_USERID, &osAccountId);
    if (rc < 0) {
        fdsan_close_with_tag(fdIoctl, LOG_DOMAIN);
        return -1;
    }
    fdsan_close_with_tag(fdIoctl, LOG_DOMAIN);
    return osAccountId;
}