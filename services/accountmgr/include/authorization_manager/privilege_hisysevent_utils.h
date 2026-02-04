/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OS_ACCOUNT_PRIVILEGE_HISYSEVENT_UTILS_H
#define OS_ACCOUNT_PRIVILEGE_HISYSEVENT_UTILS_H

#include "account_hisysevent_adapter.h"

namespace OHOS {
namespace AccountSA {
const char PRIVILEGE_OPT_PERSIST_CACHE[] = "persistPrivilegeCache";
const char PRIVILEGE_OPT_RECOVER_PERSIST_CACHE[] = "recoverPersistCache";
const char PRIVILEGE_OPT_ACQUIRE_AUTH[] = "acquirePrivilegeAuth";
const char PRIVILEGE_OPT_RELEASE_AUTH[] = "releasePrivilegeAuth";
const char PRIVILEGE_OPT_VERIFY_TOKEN[] = "verifyPrivilegeToken";
} // namespace AccountSA
} // namespace OHOS
#endif // OS_ACCOUNT_PRIVILEGE_HISYSEVENT_UTILS_H