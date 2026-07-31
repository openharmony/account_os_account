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

#ifndef OS_ACCOUNT_DFX_OHOS_ACCOUNT_DFX_CONSTANTS_H
#define OS_ACCOUNT_DFX_OHOS_ACCOUNT_DFX_CONSTANTS_H

#include "account_hisysevent_adapter.h"

namespace OHOS {
namespace AccountSA {
namespace Constants {
//OHOS_DFX
const char OPERATION_SET_INFO[] = "setInfo";
const char OPERATION_INIT[] = "init";
const char OPERATION_STATE_CHANGE[] = "stateChange";
const char OPERATION_TOKEN_INVALID[] = "tokenInvalid";
const char OPERATION_LOGOUT[] = "logout";
const char OPERATION_LOGOFF[] = "logoff";
const char OPERATION_LOGIN[] = "login";
const char OPERATION_SUBSCRIBE[] = "subscribe";
const char OPERATION_UNSUBSCRIBE[] = "unsubscribe";
const char OPERATION_SUBSCRIBE_SPACE_EVENT[] = "subscribeSpaceEvent";
const char OPERATION_UNSUBSCRIBE_SPACE_EVENT[] = "unsubscribeSpaceEvent";
const char OPERATION_GET_SERVICE[] = "getService";
const char OPERATION_CLEAR[] = "clear";
const char OPERATION_FILE_WATCHER[] = "fileWatcher";
//FILE_DFX
const char OPERATION_INIT_OPEN_FILE_TO_READ[] = "InitOpenFileToRead";
const char OPERATION_STAT_FILE[] = "StatFile";
const char OPERATION_CREATE_FILE[] = "CreateFile";
const char OPERATION_REMOVE_FILE[] = "RemoveFile";
const char OPERATION_OPEN_FILE_TO_READ[] = "OpenFileToRead";
const char OPERATION_OPEN_FILE_TO_WRITE[] = "OpenFileToWrite";
const char OPERATION_CHANGE_MODE_FILE[] = "ChangeModeFile";
const char OPERATION_FORCE_CREATE_DIRECTORY[] = "ForceCreateDirectory";
const char OPERATION_CHANGE_MODE_DIRECTORY[] = "ChangeModeDirectory";

} // namespace Constants
} // namespace AccountSA
} // namespace OHOS

#endif // OS_ACCOUNT_DFX_OHOS_ACCOUNT_DFX_CONSTANTS_H