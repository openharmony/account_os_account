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
#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_OS_ACCOUNT_CONSTANT_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_OS_ACCOUNT_CONSTANT_H

#include <string>
#include "os_account_info.h"

namespace OHOS {
namespace AccountSA {
namespace Constants {
const std::string PATH_SEPARATOR = "/";
const std::string USER_INFO_BASE = "/data/system/users";
const std::string OSACCOUNT_CONSTRAINTS_JSON_PATH = "/system/etc/account/osaccount_constraints.json";
const std::string USER_LIST_FILE_NAME = "account_list.json";
const std::string USER_PHOTO_FILE_PNG_NAME = "fase.png";
const std::string USER_PHOTO_FILE_JPG_NAME = "fase.jpg";
const std::string USER_PHOTO_BASE_JPG_HEAD = "data:image/jpeg;base64,";
const std::string USER_PHOTO_BASE_PNG_HEAD = "data:image/png;base64,";
const std::string USER_INFO_FILE_NAME = "account_info.json";
constexpr std::int32_t UID_TRANSFORM_DIVISOR = 100000;
// distributed database
const std::string APP_ID = "os_account_mgr_service";
const std::string STORE_ID = "os_account_info";
const bool SYNC_OS_ACCOUNT_DATABSE = false;

// uid judgment
const std::int32_t APP_UID_START = 2100;

// subscribe
const int SUBSCRIBER_MAX_SIZE = 100;
// account restrict
const unsigned int LOCAL_NAME_MAX_SIZE = 1024 - 1;
const unsigned int LOCAL_PHOTO_MAX_SIZE = 1024 * 4 - 1;

// temporary 100
const int ADMIN_LOCAL_ID = 0;
const int ADMIN_TYPE = -1;
const std::string ADMIN_LOCAL_NAME = "admin";
const std::string STANDARD_LOCAL_NAME = "user";
const int STANDARD_TYPE = 0;
const int START_USER_ID = 100;
const int MAX_USER_ID = 999;
const int64_t SERIAL_NUMBER_NUM_START_FOR_ADMIN = 20210231;
const int64_t SERIAL_NUMBER_NUM_START = 101;
const int64_t CARRY_NUM = 100000000;

// type temeplate
const std::string USER_CONSTRATINTS_TEMPLATE = "UserConstraintsTemplate";
const std::string TYPE_LIST = "TypeList";
const std::string ACCOUNT_LIST = "AccountList";
const std::string COUNT_ACCOUNT_NUM = "CountAccountNum";
const std::string NOW_ALLOW_CREATE_ACCOUNT_NUM = "NowAllowCreateAccountNum";
const std::string MAX_ALLOW_CREATE_ACCOUNT_NUM = "MaxAllowCreateAccountNum";
const std::string SERIAL_NUMBER_NUM = "SerialNumber";
const std::string IS_MULTI_OS_ACCOUNT_ENABLE = "IsMultiOsAccountEnable";

// start type
const OS_ACCOUNT_SWITCH_MOD NOW_OS_ACCOUNT_SWITCH_MOD = OS_ACCOUNT_SWITCH_MOD::HOT_SWITCH;
};  // namespace Constants
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_OS_ACCOUNT_CONSTANT_H