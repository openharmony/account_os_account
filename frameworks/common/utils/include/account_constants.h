/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_FRAMEWORKS_ACCOUNT_CONSTANTS_H
#define OS_ACCOUNT_FRAMEWORKS_ACCOUNT_CONSTANTS_H

#define TOKEN_ID_LOWMASK 0xffffffff
namespace OHOS {
namespace AccountSA {
// for watchdog func
#ifdef HICOLLIE_ENABLE
const uint32_t TIMEOUT = 30; // 30s
constexpr const char TIMER_NAME[] = "AccountMgrTimer";
#endif // HICOLLIE_ENABLE

} // namespace AccountSA
} // namespace OHOS
#endif // OS_ACCOUNT_FRAMEWORKS_ACCOUNT_CONSTANTS_H