/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_EVENT_PROVIDER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_EVENT_PROVIDER_H

#include <string>
#include <want.h>
#include "domain_account_common.h"

namespace OHOS {
namespace AccountSA {
// CES for distributed account events
const char COMMON_EVENT_OS_ACCOUNT_SUB_PROFILE_CREATED[] = "usual.event.OS_ACCOUNT_SUB_PROFILE_CREATED";
const char COMMON_EVENT_OS_ACCOUNT_SUB_PROFILE_DELETED[] = "usual.event.OS_ACCOUNT_SUB_PROFILE_DELETED";
const char COMMON_EVENT_OS_ACCOUNT_SUB_PROFILE_SWITCHING[] = "usual.event.OS_ACCOUNT_SUB_PROFILE_SWITCHING";
const char COMMON_EVENT_OS_ACCOUNT_SUB_PROFILE_SWITCHED[] = "usual.event.OS_ACCOUNT_SUB_PROFILE_SWITCHED";
const char COMMON_EVENT_DISTRIBUTED_ACCOUNT_BOUND[] = "usual.event.DISTRIBUTED_ACCOUNT_BOUND";
const char COMMON_EVENT_DISTRIBUTED_ACCOUNT_UNBOUND[] = "usual.event.DISTRIBUTED_ACCOUNT_UNBOUND";
const char COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGIN[] = "common.event.DISTRIBUTED_ACCOUNT_LOGIN";
const char COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOUT[] = "common.event.DISTRIBUTED_ACCOUNT_LOGOUT";
const char COMMON_EVENT_DISTRIBUTED_ACCOUNT_TOKEN_INVALID[] = "common.event.DISTRIBUTED_ACCOUNT_TOKEN_INVALID";
const char COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOFF[] = "common.event.DISTRIBUTED_ACCOUNT_LOGOFF";
const char COMMON_EVENT_USER_INFO_UPDATED[] = "usual.event.USER_INFO_UPDATED";
const char COMMON_EVENT_HWID_LOGIN[] = "common.event.HWID_LOGIN";
const char COMMON_EVENT_HWID_LOGOUT[] = "common.event.HWID_LOGOUT";
const char COMMON_EVENT_HWID_TOKEN_INVALID[] = "common.event.HWID_TOKEN_INVALID";
const char COMMON_EVENT_HWID_LOGOFF[] = "common.event.HWID_LOGOFF";

class AccountEventProvider {
public:
    static bool EventPublish(const std::string& event, int32_t userId, const DomainAccountEventData *report);
    static bool EventPublishAsUser(const std::string& event, int32_t userId);
    static bool EventPublishAsUser(const std::string& event, const AAFwk::Want &want, int32_t userId);
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_EVENT_PROVIDER_H