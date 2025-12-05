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
constexpr int32_t WAIT_TIME = 60;
// for watchdog func
#ifdef HICOLLIE_ENABLE
const uint32_t TIMEOUT = 30; // 30s
const uint32_t BOOT_ACTIVATE_TIMEOUT = 150; // 150s
constexpr const char TIMER_NAME[] = "AccountMgrTimer";
#endif // HICOLLIE_ENABLE
namespace Constants {
constexpr int32_t DELAY_FOR_EXCEPTION = 100;
constexpr int32_t MAX_RETRY_TIMES = 10;
const char OPERATION_EVENT_PUBLISH[] = "eventPublish";
const char OPERATION_GET_INFO[] = "getInfo";
const char OPERATION_SET_INFO[] = "setInfo";
const char OPERATION_TOKEN_INVALID[] = "tokenInvalid";
const char OPERATION_LOGOUT[] = "logout";
const char OPERATION_LOGOFF[] = "logoff";
const char OPERATION_LOGIN[] = "login";
const char OPERATION_SUBSCRIBE[] = "subscribe";
const char OPERATION_UNSUBSCRIBE[] = "unsubscribe";
const char OPERATION_GET_SERVICE[] = "getService";
const int32_t E_IPC_ERROR = 29189;
const int32_t E_IPC_SA_DIED = 32;
}
} // namespace AccountSA
} // namespace OHOS
#endif // OS_ACCOUNT_FRAMEWORKS_ACCOUNT_CONSTANTS_H